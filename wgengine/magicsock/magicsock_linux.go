// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/net/netns"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
)

const (
	udpHeaderSize          = 8
	ipv6FragmentHeaderSize = 8
)

// Enable/disable using raw sockets to receive disco traffic.
var debugDisableRawDisco = envknob.RegisterBool("TS_DEBUG_DISABLE_RAW_DISCO")

// These are our BPF filters that we use for testing packets.
var (
	magicsockFilterV4 = []bpf.Instruction{
		// For raw UDPv4 sockets, BPF receives the entire IP packet to
		// inspect.

		// Disco packets are so small they should never get
		// fragmented, and we don't want to handle reassembly.
		bpf.LoadAbsolute{Off: 6, Size: 2},
		// More Fragments bit set means this is part of a fragmented packet.
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x2000, SkipTrue: 7, SkipFalse: 0},
		// Non-zero fragment offset with MF=0 means this is the last
		// fragment of packet.
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 6, SkipFalse: 0},

		// Load IP header length into X register.
		bpf.LoadMemShift{Off: 0},

		// Get the first 4 bytes of the UDP packet, compare with our magic number
		bpf.LoadIndirect{Off: udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadIndirect{Off: udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(discoMagic2), SkipTrue: 0, SkipFalse: 1},

		// Accept the whole packet
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}

	// IPv6 is more complicated to filter, since we can have 0-to-N
	// extension headers following the IPv6 header. Since BPF can't
	// loop, we can't really parse these in a general way; instead, we
	// simply handle the case where we have no extension headers; any
	// packets with headers will be skipped. IPv6 extension headers
	// are sufficiently uncommon that we're willing to accept false
	// negatives here.
	//
	// The "proper" way to handle this would be to do minimal parsing in
	// BPF and more in-depth parsing of all IPv6 packets in userspace, but
	// on systems with a high volume of UDP that would be unacceptably slow
	// and thus we'd rather be conservative here and possibly not receive
	// disco packets rather than slow down the system.
	magicsockFilterV6 = []bpf.Instruction{
		// For raw UDPv6 sockets, BPF receives _only_ the UDP header onwards, not an entire IP packet.
		//
		//    https://stackoverflow.com/questions/24514333/using-bpf-with-sock-dgram-on-linux-machine
		//    https://blog.cloudflare.com/epbf_sockets_hop_distance/
		//
		// This is especially confusing because this *isn't* true for
		// IPv4; see the following code from the 'ping' utility that
		// corroborates this:
		//
		//    https://github.com/iputils/iputils/blob/1ab5fa/ping/ping.c#L1667-L1676
		//    https://github.com/iputils/iputils/blob/1ab5fa/ping/ping6_common.c#L933-L941

		// Compare with our magic number. Start by loading and
		// comparing the first 4 bytes of the UDP payload.
		bpf.LoadAbsolute{Off: udpHeaderSize, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic1, SkipTrue: 0, SkipFalse: 3},

		// Compare the next 2 bytes
		bpf.LoadAbsolute{Off: udpHeaderSize + 4, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: discoMagic2, SkipTrue: 0, SkipFalse: 1},

		// Accept the whole packet
		bpf.RetConstant{Val: 0xFFFFFFFF},

		// Skip the packet
		bpf.RetConstant{Val: 0x0},
	}

	testDiscoPacket = []byte{
		// Disco magic
		0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac,
		// Sender key
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		// Nonce
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	}
)

// listenRawDisco starts listening for disco packets on the given
// address family, which must be "ip4" or "ip6", using a raw socket
// and BPF filter.
// https://github.com/tailscale/tailscale/issues/3824
func (c *Conn) listenRawDisco(family string) (io.Closer, error) {
	if debugDisableRawDisco() {
		return nil, errors.New("raw disco listening disabled by debug flag")
	}

	// https://github.com/tailscale/tailscale/issues/5607
	if !netns.UseSocketMark() {
		return nil, errors.New("raw disco listening disabled, SO_MARK unavailable")
	}

	var (
		network  string
		addr     string
		testAddr string
		prog     []bpf.Instruction
	)
	switch family {
	case "ip4":
		network = "ip4:17"
		addr = "0.0.0.0"
		testAddr = "127.0.0.1:1"
		prog = magicsockFilterV4
	case "ip6":
		network = "ip6:17"
		addr = "::"
		testAddr = "[::1]:1"
		prog = magicsockFilterV6
	default:
		return nil, fmt.Errorf("unsupported address family %q", family)
	}

	asm, err := bpf.Assemble(prog)
	if err != nil {
		return nil, fmt.Errorf("assembling filter: %w", err)
	}

	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, fmt.Errorf("creating packet conn: %w", err)
	}

	if err := setBPF(pc, asm); err != nil {
		pc.Close()
		return nil, fmt.Errorf("installing BPF filter: %w", err)
	}

	// If all the above succeeds, we should be ready to receive. Just
	// out of paranoia, check that we do receive a well-formed disco
	// packet.
	tc, err := net.ListenPacket("udp", net.JoinHostPort(addr, "0"))
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("creating disco test socket: %w", err)
	}
	defer tc.Close()
	if _, err := tc.(*net.UDPConn).WriteToUDPAddrPort(testDiscoPacket, netip.MustParseAddrPort(testAddr)); err != nil {
		pc.Close()
		return nil, fmt.Errorf("writing disco test packet: %w", err)
	}
	pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var buf [1500]byte
	for {
		n, _, err := pc.ReadFrom(buf[:])
		if err != nil {
			pc.Close()
			return nil, fmt.Errorf("reading during raw disco self-test: %w", err)
		}
		if n < udpHeaderSize {
			continue
		}
		if !bytes.Equal(buf[udpHeaderSize:n], testDiscoPacket) {
			continue
		}
		break
	}
	pc.SetReadDeadline(time.Time{})

	go c.receiveDisco(pc, family == "ip6")
	return pc, nil
}

func (c *Conn) receiveDisco(pc net.PacketConn, isIPV6 bool) {
	var buf [1500]byte
	for {
		n, src, err := pc.ReadFrom(buf[:])
		if errors.Is(err, net.ErrClosed) {
			return
		} else if err != nil {
			c.logf("disco raw reader failed: %v", err)
			return
		}
		if n < udpHeaderSize {
			// Too small to be a valid UDP datagram, drop.
			continue
		}

		dstPort := binary.BigEndian.Uint16(buf[2:4])
		if dstPort == 0 {
			c.logf("[unexpected] disco raw: received packet for port 0")
		}

		var acceptPort uint16
		if isIPV6 {
			acceptPort = c.pconn6.Port()
		} else {
			acceptPort = c.pconn4.Port()
		}
		if acceptPort == 0 {
			// This should only typically happen if the receiving address family
			// was recently disabled.
			c.dlogf("[v1] disco raw: dropping packet for port %d as acceptPort=0", dstPort)
			continue
		}

		if dstPort != acceptPort {
			c.dlogf("[v1] disco raw: dropping packet for port %d", dstPort)
			continue
		}

		srcIP, ok := netip.AddrFromSlice(src.(*net.IPAddr).IP)
		if !ok {
			c.logf("[unexpected] PacketConn.ReadFrom returned not-an-IP %v in from", src)
			continue
		}
		srcPort := binary.BigEndian.Uint16(buf[:2])

		if srcIP.Is4() {
			metricRecvDiscoPacketIPv4.Add(1)
		} else {
			metricRecvDiscoPacketIPv6.Add(1)
		}

		c.handleDiscoMessage(buf[udpHeaderSize:n], netip.AddrPortFrom(srcIP, srcPort), key.NodePublic{})
	}
}

// setBPF installs filter as the BPF filter on conn.
// Ideally we would just use SetBPF as implemented in x/net/ipv4,
// but x/net/ipv6 doesn't implement it. And once you've written
// this code once, it turns out to be address family agnostic, so
// we might as well use it on both and get to use a net.PacketConn
// directly for both families instead of being stuck with
// different types.
func setBPF(conn net.PacketConn, filter []bpf.RawInstruction) error {
	sc, err := conn.(*net.IPConn).SyscallConn()
	if err != nil {
		return err
	}
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	var setErr error
	err = sc.Control(func(fd uintptr) {
		setErr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
	})
	if err != nil {
		return err
	}
	if setErr != nil {
		return err
	}
	return nil
}

type BatchReaderWriter interface {
	BatchReader
	BatchWriter
}

type BatchWriter interface {
	WriteBatch([]ipv6.Message, int) (int, error)
}

type BatchReader interface {
	ReadBatch([]ipv6.Message, int) (int, error)
}

type packetConnWithBatchOps struct {
	nettype.PacketConn
	xpc BatchReaderWriter
}

func (p packetConnWithBatchOps) WriteBatch(ms []ipv6.Message, flags int) (int, error) {
	return p.xpc.WriteBatch(ms, flags)
}

func (p packetConnWithBatchOps) ReadBatch(ms []ipv6.Message, flags int) (int, error) {
	return p.xpc.ReadBatch(ms, flags)
}

// listenPacket opens a packet listener.
// The network must be "udp4" or "udp6".
func (c *Conn) listenPacket(network string, port uint16) (nettype.PacketConn, error) {
	pc, err := c.listenPacketCommon(network, port)
	if err != nil {
		return nil, err
	}
	pcbo := packetConnWithBatchOps{
		PacketConn: pc,
	}
	switch network {
	case "udp4":
		pcbo.xpc = ipv4.NewPacketConn(pc)
	case "udp6":
		pcbo.xpc = ipv6.NewPacketConn(pc)
	}
	return pcbo, nil
}

func (c *Conn) SendV(buffs [][]byte, ep conn.Endpoint) error {
	n := int64(len(buffs))
	metricSendData.Add(n)
	if c.networkDown() {
		metricSendDataNetworkDown.Add(n)
		return errNetworkDown
	}
	return ep.(*endpoint).sendv(buffs)
}

func (de *endpoint) sendv(buffs [][]byte) error {
	now := mono.Now()

	de.mu.Lock()
	udpAddr, derpAddr := de.addrForSendLocked(now)
	if de.canP2P() && (!udpAddr.IsValid() || now.After(de.trustBestAddrUntil)) {
		de.sendPingsLocked(now, true)
	}
	de.noteActiveLocked()
	de.mu.Unlock()

	if !udpAddr.IsValid() && !derpAddr.IsValid() {
		return errors.New("no UDP or DERP addr")
	}
	var err error
	if udpAddr.IsValid() {
		_, err = de.c.sendUDPBatch(udpAddr, buffs)
	}
	if derpAddr.IsValid() {
		allOk := true
		for _, buff := range buffs {
			ok, _ := de.c.sendAddr(derpAddr, de.publicKey, buff)
			if !ok {
				allOk = false
			}
		}
		if allOk {
			return nil
		}
	}
	return err
}

type sendBatch struct {
	ua   *net.UDPAddr
	msgs []ipv6.Message // ipv4.Message and ipv6.Message are the same underlying type
}

var (
	sendBatchPool = &sync.Pool{
		New: func() any {
			ua := &net.UDPAddr{
				IP: make([]byte, 16),
			}
			msgs := make([]ipv6.Message, conn.MaxPacketVectorSize)
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].Addr = ua
			}
			return &sendBatch{
				ua:   ua,
				msgs: msgs,
			}
		},
	}
)

func (c *Conn) sendUDPBatch(addr netip.AddrPort, buffs [][]byte) (sent bool, err error) {
	batch := sendBatchPool.Get().(*sendBatch)
	defer sendBatchPool.Put(batch)

	isIPv6 := false
	switch {
	case addr.Addr().Is4():
	case addr.Addr().Is6():
		isIPv6 = true
	default:
		panic("bogus sendUDPBatch addr type")
	}

	as16 := addr.Addr().As16()
	copy(batch.ua.IP, as16[:])
	batch.ua.Port = int(addr.Port())
	for i, buff := range buffs {
		batch.msgs[i].Buffers[0] = buff
		batch.msgs[i].Addr = batch.ua
	}

	if isIPv6 {
		_, err = c.pconn6.WriteBatch(batch.msgs[:len(buffs)], 0)
	} else {
		_, err = c.pconn4.WriteBatch(batch.msgs[:len(buffs)], 0)
	}
	return err == nil, err
}

func (c *blockForeverConn) WriteBatch(p []ipv4.Message, flags int) (int, error) {
	// Silently drop writes.
	return len(p), nil
}

func (c *RebindingUDPConn) WriteBatch(msgs []ipv6.Message, flags int) (int, error) {
	for {
		pconn := c.pconnAtomic.Load()
		bw, ok := pconn.(BatchWriter)
		if !ok {
			return 0, errors.New("pconn is not a BatchWriter")
		}

		n, err := bw.WriteBatch(msgs, flags)
		if err != nil {
			if pconn != c.currentConn() {
				continue
			}
		}
		return n, err
	}
}

func (c *RebindingUDPConn) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	for {
		pconn := c.pconnAtomic.Load()
		br, ok := pconn.(BatchReader)
		if !ok {
			panic("pconn is not a BatchReader")
		}
		n, err := br.ReadBatch(msgs, flags)
		if err != nil && pconn != c.currentConn() {
			continue
		}
		return n, err
	}
}

type receiveBatch struct {
	msgs      []ipv6.Message
	sizes     []int
	endpoints []conn.Endpoint
}

func init() {
	n := conn.MaxPacketVectorSize
	for _, b := range []*receiveBatch{ipv4ReceiveBatch, ipv6ReceiveBatch, derpReceiveBatch} {
		msgs := make([]ipv6.Message, n)
		for i := range msgs {
			msgs[i].Buffers = make([][]byte, 1)
		}
		*b = receiveBatch{
			msgs:      msgs,
			sizes:     make([]int, n),
			endpoints: make([]conn.Endpoint, n),
		}
	}
}

var (
	ipv4ReceiveBatch = &receiveBatch{}
	ipv6ReceiveBatch = &receiveBatch{}
	derpReceiveBatch = &receiveBatch{}
)

func (c *Conn) receiveMultipleIPv4(buffs [][]byte) ([]int, []conn.Endpoint, error) {
	health.ReceiveIPv4.Enter()
	defer health.ReceiveIPv4.Exit()

	for {
		batch := ipv4ReceiveBatch
		for i := range buffs {
			batch.msgs[i].Buffers[0] = buffs[i]
		}
		numMsgs, err := c.pconn4.ReadBatch(batch.msgs, 0)
		if err != nil {
			return nil, nil, err
		}
		for i := 0; i < numMsgs; i++ {
			msg := &batch.msgs[i]
			msg.Buffers[0] = msg.Buffers[0][:msg.N]
			ipp := msg.Addr.(*net.UDPAddr).AddrPort()
			if ep, ok := c.receiveIP(msg.Buffers[0], ipp, &c.ippEndpoint4, c.closeDisco4 == nil); ok {
				metricRecvDataIPv4.Add(1)
				batch.sizes[i] = msg.N
				batch.endpoints[i] = ep
			} else {
				batch.sizes[i] = 0
			}
		}
		if len(batch.sizes) > 0 {
			return batch.sizes[:numMsgs], batch.endpoints[:numMsgs], nil
		}
	}
}

func (c *Conn) receiveMultipleIPv6(buffs [][]byte) ([]int, []conn.Endpoint, error) {
	health.ReceiveIPv6.Enter()
	defer health.ReceiveIPv6.Exit()

	for {
		batch := ipv6ReceiveBatch
		for i := range buffs {
			batch.msgs[i].Buffers[0] = buffs[i]
		}
		numMsgs, err := c.pconn6.ReadBatch(batch.msgs, 0)
		if err != nil {
			return nil, nil, err
		}
		for i := 0; i < numMsgs; i++ {
			msg := &batch.msgs[i]
			msg.Buffers[0] = msg.Buffers[0][:msg.N]
			ipp := msg.Addr.(*net.UDPAddr).AddrPort()
			if ep, ok := c.receiveIP(msg.Buffers[0], ipp, &c.ippEndpoint6, c.closeDisco6 == nil); ok {
				metricRecvDataIPv6.Add(1)
				batch.sizes[i] = msg.N
				batch.endpoints[i] = ep
			} else {
				batch.sizes[i] = 0
			}
		}
		if len(batch.sizes) > 0 {
			return batch.sizes[:numMsgs], batch.endpoints[:numMsgs], nil
		}
	}
}

func (c *connBind) receiveMultipleDERP(b [][]byte) (sizes []int, eps []conn.Endpoint, err error) {
	batch := derpReceiveBatch
	n, ep, err := c.receiveDERP(b[0])
	batch.sizes[0] = n
	batch.endpoints[0] = ep
	return batch.sizes[:1], batch.endpoints[:1], err
}

func (c *connBind) OpenV(_ uint16) ([]conn.ReceiveVFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return nil, 0, errors.New("magicsock: connBind already open")
	}
	c.closed = false
	fns := []conn.ReceiveVFunc{c.receiveMultipleIPv4, c.receiveMultipleIPv6, c.receiveMultipleDERP}
	return fns, c.LocalPort(), nil
}
