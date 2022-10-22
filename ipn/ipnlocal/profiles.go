// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/exp/slices"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
)

// ProfileManager is a wrapper around a StateStore that manages
// multiple profiles and the current profile.
type ProfileManager struct {
	store ipn.StateStore
	logf  logger.Logf

	// Lock order: LocalBackend.mu, then pm.mu.
	mu            sync.Mutex // guards following
	knownProfiles []string
	currentState  ipn.StateKey
	prefs         ipn.PrefsView
}

// SaveAsStartState saves the provided prefs as the state to start with
// when running in server mode. This is only used by the Windows GUI in
// server mode.
func (pm *ProfileManager) SaveAsStartState(userID string, prefs *ipn.Prefs) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if err := pm.switchStateLocked(ipn.StateKey("user-" + userID)); err != nil {
		return err
	}
	return pm.SetPrefs(prefs)
}

// Unload unloads the current profile, if any.
// It also clears the server-mode-start-key, so that the next time
// tailscaled starts it will start with no profile.
// Any future calls to SetPrefs will not be persisted, until a profile
// is loaded.
// This is used by the Windows in client mode, as the state is stored
// elsewhere.
func (pm *ProfileManager) Unload() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.prefs = emptyPrefs
	pm.currentState = ""
	pm.useCurrentProfileAtStartup()
}

// SetPrefs sets the current profile's prefs to the provided value.
// It also saves the prefs to the StateStore. It stores a copy of the
// provided prefs, which maybe accessed via CurrentPrefs.
// It does not persist the prefs to disk if the currentState is empty.
func (pm *ProfileManager) SetPrefs(prefsIn *ipn.Prefs) error {
	prefs := prefsIn.Clone()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.prefs = prefs.View()
	return pm.writePrefsToStore(pm.currentState, pm.prefs)
}

func (pm *ProfileManager) writePrefsToStore(key ipn.StateKey, prefs ipn.PrefsView) error {
	if key == "" {
		return nil
	}
	if err := pm.store.WriteState(key, prefs.ToBytes()); err != nil {
		pm.logf("WriteState(%q): %v", key, err)
		return err
	}
	return nil
}

// Profiles returns the list of known profiles.
func (pm *ProfileManager) Profiles() []string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	var profiles []string
	for _, kp := range pm.knownProfiles {
		profiles = append(profiles, kp)
	}
	return profiles
}

// SwitchProfile switches to the profile with the given name.
func (pm *ProfileManager) SwitchProfile(profile string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	stateKey := ipn.StateKey("profile-" + profile)
	return pm.switchStateLocked(stateKey)
}

func (pm *ProfileManager) switchStateLocked(stateKey ipn.StateKey) error {
	if stateKey == pm.currentState && pm.prefs.Valid() {
		return nil
	}
	prefs, err := pm.loadSavedPrefs(stateKey)
	if err != nil {
		return err
	}
	pm.currentState = stateKey
	pm.prefs = prefs.View()
	if pm.prefs.Valid() && pm.prefs.ForceDaemon() {
		return pm.store.WriteState(ipn.ServerModeStartKey, []byte(pm.currentState))
	}
	if err := pm.store.WriteState(ipn.ServerModeStartKey, nil); err != nil {
		pm.logf("WriteState(%q): %v", ipn.ServerModeStartKey, err)
	}
	return pm.useCurrentProfileAtStartup()
}

func (pm *ProfileManager) useCurrentProfileAtStartup() error {
	return pm.store.WriteState(ipn.CurrentProfileStateKey, []byte(pm.currentState))
}

func (pm *ProfileManager) loadSavedPrefs(key ipn.StateKey) (*ipn.Prefs, error) {
	bs, err := pm.store.ReadState(key)
	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		prefs := ipn.NewPrefs()
		prefs.WantRunning = false
		pm.logf("using backend prefs; created empty state for %q: %s", key, prefs.Pretty())
		return prefs, nil
	case err != nil:
		return nil, fmt.Errorf("backend prefs: store.ReadState(%q): %v", key, err)
	}
	savedPrefs, err := ipn.PrefsFromBytes(bs)
	if err != nil {
		return nil, fmt.Errorf("PrefsFromBytes: %v", err)
	}
	pm.logf("using backend prefs for %q: %v", key, savedPrefs.Pretty())

	// Ignore any old stored preferences for https://login.tailscale.com
	// as the control server that would override the new default of
	// controlplane.tailscale.com.
	// This makes sure that mobile clients go through the new
	// frontends where we're (2021-10-02) doing battery
	// optimization work ahead of turning down the old backends.
	if savedPrefs != nil && savedPrefs.ControlURL != "" &&
		savedPrefs.ControlURL != ipn.DefaultControlURL &&
		ipn.IsLoginServerSynonym(savedPrefs.ControlURL) {
		savedPrefs.ControlURL = ""
	}
	return savedPrefs, nil
}

// CurrentProfile returns the name of the current profile, or "" if the profile
// is not named. It also returns the associated current state key.
func (pm *ProfileManager) CurrentProfile() (string, ipn.StateKey) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if strings.HasPrefix(string(pm.currentState), "profile-") {
		return strings.TrimPrefix(string(pm.currentState), "profile-"), pm.currentState
	}
	return "", pm.currentState
}

// DeleteProfile removes the profile with the given name. It is a no-op if the
// profile does not exist.
func (pm *ProfileManager) DeleteProfile(profile string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	ix := slices.Index(pm.knownProfiles, profile)
	if ix < 0 {
		return nil // already gone
	}
	pk := ipn.StateKey("profile-" + profile)
	if pk == pm.currentState {
		return fmt.Errorf("cannot remove current profile")
	}
	pm.knownProfiles = append(pm.knownProfiles[:ix], pm.knownProfiles[ix+1:]...)
	return pm.writeKnownProfiles()
}

func (pm *ProfileManager) writeKnownProfiles() error {
	b, err := json.Marshal(pm.knownProfiles)
	if err != nil {
		return err
	}
	return pm.store.WriteState(ipn.KnownProfilesStateKey, b)
}

// NewProfile creates a new profile with the given name.
// It does not switch to the new profile.
func (pm *ProfileManager) NewProfile(profile string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if slices.Contains(pm.knownProfiles, profile) {
		return fmt.Errorf("profile %q already exists", profile)
	}
	pm.knownProfiles = append(pm.knownProfiles, profile)
	if err := pm.writeKnownProfiles(); err != nil {
		return err
	}
	// In case one already exists in store, wipe it.
	return pm.writePrefsToStore(ipn.StateKey("profile-"+profile), emptyPrefs)
}

// emptyPrefs is the default prefs for a new profile.
var emptyPrefs = func() ipn.PrefsView {
	prefs := ipn.NewPrefs()
	prefs.WantRunning = false
	return prefs.View()
}()

// Store returns the StateStore used by the ProfileManager.
func (pm *ProfileManager) Store() ipn.StateStore {
	return pm.store
}

// CurrentPrefs returns a read-only view of the current prefs.
func (pm *ProfileManager) CurrentPrefs() ipn.PrefsView {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.prefs
}

// NewProfileManager creates a new ProfileManager using the provided StateStore.
// It also loads the list of known profiles from the StateStore.
// If a state key is provided, it will be used to load the current profile.
func NewProfileManager(store ipn.StateStore, logf logger.Logf, stateKey ipn.StateKey) (*ProfileManager, error) {
	if stateKey == "" {
		startKey := ipn.CurrentProfileStateKey
		stateKeyPrefix := "profile-"
		if runtime.GOOS == "windows" {
			// This is only used on non-Windows systems, as Windows caches
			// the state in the frontend.
			startKey = ipn.ServerModeStartKey
			stateKeyPrefix = "user-"
		}
		autoStartKey, err := store.ReadState(startKey)
		if err != nil && err != ipn.ErrStateNotExist {
			return nil, fmt.Errorf("calling ReadState on state store: %w", err)
		}
		if len(autoStartKey) != 0 {
			key := string(autoStartKey)
			if strings.HasPrefix(key, stateKeyPrefix) {
				stateKey = ipn.StateKey(key)
			}
		}
	}

	var knownProfiles []string
	prfB, err := store.ReadState(ipn.KnownProfilesStateKey)
	if err != nil && err != ipn.ErrStateNotExist {
		return nil, fmt.Errorf("calling ReadState on state store: %w", err)
	} else if err == nil {
		if err := json.Unmarshal(prfB, &knownProfiles); err != nil {
			return nil, fmt.Errorf("unmarshaling known profiles: %w", err)
		}
	}

	if stateKey == "" && len(knownProfiles) == 0 {
		knownProfiles = []string{"default"}
		stateKey = "profile-default"

		// No known profiles, see if there is a "_daemon" profile.
		// If so, migrate it to the new format.
		b, err := store.ReadState(ipn.GlobalDaemonStateKey)
		if err != nil && err != ipn.ErrStateNotExist {
			return nil, fmt.Errorf("calling ReadState on state store: %w", err)
		}
		if err == nil && len(b) > 0 {
			if err := store.WriteState(stateKey, b); err != nil {
				return nil, fmt.Errorf("writing profile state: %w", err)
			}
			if err := store.WriteState(ipn.KnownProfilesStateKey, []byte(`["default"]`)); err != nil {
				return nil, fmt.Errorf("writing known profiles: %w", err)
			}
			// Do not delete the old state key, as we may be downgraded to an
			// older version that still relies on it.
		}
	}
	pm := &ProfileManager{
		store:         store,
		currentState:  stateKey,
		knownProfiles: knownProfiles,
		logf:          logf,
	}
	prefs, err := pm.loadSavedPrefs(stateKey)
	if err != nil {
		return nil, err
	}
	pm.prefs = prefs.View()

	return pm, nil
}
