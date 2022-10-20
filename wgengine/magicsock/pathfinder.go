// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"errors"
	"fmt"
	"time"

	"tailscale.com/tstime/mono"
)

// startPathFinder initializes the sendFunc, and
// will eventually kick off a goroutine that monitors whether
// that sendFunc is still the best option for the endpoint
// to use and adjusts accordingly.
func (de *endpoint) startPathFinder() {
	de.pathFinderRunning = true
	de.sendFunc.Store(de.sendDerpOnly()) // default to only derp

	go func() {
		for mono.Since(de.lastSendAtomic.Load()) < sessionActiveTimeout {
			// while the session has not timed out yet,
			// check whether path needs to be upgraded on an interval
			de.updateSendPathIfNecessary(mono.Now())

			// TODO(2022-10-20): should not be using heartbeat at all, currently just
			// trying to replicate existing behaviour
			time.Sleep(heartbeatInterval)
		}
	}()
}

// updateSendPathIfNecessary optionally upates sendFunc
// based on analysis of current conditions
func (de *endpoint) updateSendPathIfNecessary(now mono.Time) {
	de.mu.Lock()
	defer de.mu.Unlock()

	if !de.canP2P() {
		// if it can't P2P, stick to using only derp
		// does Store cost something? Is CompareAndSwap better here?
		de.sendFunc.Store(de.sendDerpOnly())
		return
	}

	// if it's been less than 6.5seconds (trustUDPAddrDuration) since last pong
	// just use regular UDP send
	if now.Before(de.trustBestAddrUntil) {
		de.sendFunc.Store(de.sendUDPOnly())
	} else {
		de.sendFunc.Store(de.sendDerpAndUDP())
	}

	if de.wantFullPingLocked(now) {
		de.sendPingsLocked(now, true) // spray endpoints, and enqueue CMM
	}

	// currently does not re-implement the heartbeat calling startPingLocked
	// keep-alive every 3 seconds. this is where the bulk of the new upgrade
	// logic should be, I think?
}

func (de *endpoint) sendUDPOnly() endpointSendFunc {
	de.mu.Lock()
	// I think this addr will stay the same for the duration
	// of the function pointer until it is set again???
	addr := de.bestAddr.AddrPort
	de.mu.Unlock()

	return func(b []byte) error {
		if addr.IsValid() {
			_, err := de.c.sendAddr(addr, de.publicKey, b)
			return err
		}
		return errors.New(fmt.Sprintf("UDP addr %s is invalid", addr))
	}
}

func (de *endpoint) sendDerpOnly() endpointSendFunc {
	de.mu.Lock()
	addr := de.derpAddr
	de.mu.Unlock()

	return func(b []byte) error {
		if addr.IsValid() {
			_, err := de.c.sendAddr(addr, de.publicKey, b)
			return err
		}
		return errors.New(fmt.Sprintf("Derp addr %s is invalid", addr))
	}
}

func (de *endpoint) sendDerpAndUDP() endpointSendFunc {
	de.mu.Lock()
	derpAddr := de.derpAddr
	udpAddr := de.bestAddr.AddrPort
	de.mu.Unlock()

	return func(b []byte) error {
		if !derpAddr.IsValid() && !udpAddr.IsValid() {
			return errors.New(fmt.Sprintf("Both UDP addr %s and DERP addr %s are invalid", udpAddr, derpAddr))
		}
		var derpErr, udpErr error
		if derpAddr.IsValid() {
			_, derpErr = de.c.sendAddr(derpAddr, de.publicKey, b)
		}
		if udpAddr.IsValid() {
			_, udpErr = de.c.sendAddr(udpAddr, de.publicKey, b)
		}
		if derpErr == nil || udpErr == nil {
			// at least one packet send succeeded, good enough
			return nil
		}
		return udpErr // error from UDP send supersedes error from Derp send
	}
}
