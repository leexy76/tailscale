// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"os"
	"strconv"
	"testing"

	"golang.org/x/exp/maps"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/types/logger"
)

// TestProfileManagement tests creating, loading, and switching profiles.
func TestProfileManagement(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	expectedCurProfile := "default"
	expectedProfiles := map[string]ipn.PrefsView{
		"default": emptyPrefs,
	}
	checkProfiles := func(t *testing.T) {
		t.Helper()
		prof, _ := pm.CurrentProfile()
		if prof != expectedCurProfile {
			t.Fatalf("CurrentProfile = %q; want default", prof)
		}
		profiles := pm.Profiles()
		if len(profiles) != len(expectedProfiles) {
			t.Fatalf("Profiles = %v; want %v", profiles, expectedProfiles)
		}

		if p := pm.CurrentPrefs(); p.Hostname() != expectedProfiles[expectedCurProfile].Hostname() {
			t.Fatalf("CurrentPrefs = %v; want %v", p.Hostname(), expectedProfiles[expectedCurProfile].Hostname())
		}
		for _, p := range profiles {
			if _, ok := expectedProfiles[p]; !ok {
				t.Fatalf("Profiles = %v; want %v", profiles, expectedProfiles)
			}
			got, err := pm.loadSavedPrefs(ipn.StateKey("profile-" + p))
			if err != nil {
				t.Fatal(err)
			}
			// Use Hostname as a proxy for all prefs.
			if got.Hostname() != expectedProfiles[p].Hostname() {
				t.Fatalf("Prefs for profile %q = %v; want %v", p, got.Hostname(), expectedProfiles[p].Hostname())
			}
		}
	}
	t.Logf("Check initial state from empty store")
	checkProfiles(t)

	{
		t.Logf("Set prefs for default profile")
		p := pm.CurrentPrefs().AsStruct()
		p.Hostname = "default"
		if err := pm.SetPrefs(p); err != nil {
			t.Fatal(err)
		}
		expectedProfiles["default"] = p.View()
	}
	checkProfiles(t)

	t.Logf("Create new named profile")
	if err := pm.NewProfile("test"); err != nil {
		t.Fatal(err)
	}
	expectedProfiles["test"] = emptyPrefs
	checkProfiles(t)

	t.Logf("Switch to newly created profile")
	if err := pm.SwitchProfile("test"); err != nil {
		t.Fatal(err)
	}
	expectedCurProfile = "test"
	checkProfiles(t)

	{
		t.Logf("Set prefs for test profile")
		p := pm.CurrentPrefs().AsStruct()
		p.Hostname = "test"
		if err := pm.SetPrefs(p); err != nil {
			t.Fatal(err)
		}
		expectedProfiles["test"] = p.View()
	}
	checkProfiles(t)

	t.Logf("Recreate profile manager from store")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)

	{
		t.Logf("Try to delete test profile while it is active")
		if err := pm.DeleteProfile("test"); err == nil {
			t.Fatal("expected error deleting active profile")
		}
	}

	t.Logf("Delete default profile")
	if err := pm.DeleteProfile("default"); err != nil {
		t.Fatal(err)
	}
	delete(expectedProfiles, "default")
	checkProfiles(t)

	t.Logf("Recreate profile manager from store after deleting default profile")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "linux")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)
}

// TestProfileManagementWindows tests going into and out of Unattended mode on
// Windows.
func TestProfileManagementWindows(t *testing.T) {
	store := new(mem.Store)

	pm, err := newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile := ""
	wantStateKey := ipn.StateKey("")
	wantProfiles := map[string]ipn.PrefsView{
		"": emptyPrefs,
	}
	checkProfiles := func(t *testing.T) {
		t.Helper()
		prof, sk := pm.CurrentProfile()
		if prof != wantCurProfile {
			t.Fatalf("CurrentProfile = %q; want %q", prof, wantCurProfile)
		}
		if prof == "" && sk != wantStateKey {
			t.Fatalf("CurrentProfile state key = %q; want %q", sk, wantStateKey)
		}
		if p := pm.CurrentPrefs(); p.Hostname() != wantProfiles[wantCurProfile].Hostname() {
			t.Fatalf("Hostname = %q; want %q", p.Hostname(), wantProfiles[wantCurProfile].Hostname())
		}

		wantLen := len(wantProfiles)
		profiles := pm.Profiles()
		if _, ok := wantProfiles[""]; ok {
			wantLen--
		}
		if len(profiles) != wantLen {
			t.Fatalf("Profiles = %q; want %q %d %d", profiles, maps.Keys(wantProfiles), len(profiles), wantLen)
		}

		for _, p := range profiles {
			if _, ok := wantProfiles[p]; !ok {
				t.Fatalf("Profiles = %q; want %q", profiles, maps.Keys(wantProfiles))
			}
			got, err := pm.loadSavedPrefs(ipn.StateKey("profile-" + p))
			if err != nil {
				t.Fatal(err)
			}
			// Use Hostname as a proxy for all prefs.
			if got.Hostname() != wantProfiles[p].Hostname() {
				t.Fatalf("Prefs for profile %q = %v; want %v", p, got.Hostname(), wantProfiles[p].Hostname())
			}
		}
	}
	t.Logf("Check initial state from empty store")
	checkProfiles(t)

	{
		t.Logf("Set prefs should only be in memory")
		p := pm.CurrentPrefs().AsStruct()
		p.Hostname = "default"
		if err := pm.SetPrefs(p); err != nil {
			t.Fatal(err)
		}
		wantProfiles[""] = p.View()
	}
	checkProfiles(t)

	{
		if err := pm.NewProfile("test"); err != nil {
			t.Fatal(err)
		}
		wantProfiles["test"] = emptyPrefs
		checkProfiles(t)

		if err := pm.SwitchProfile("test"); err != nil {
			t.Fatal(err)
		}
		wantCurProfile = "test"
		checkProfiles(t)

		t.Logf("Set prefs for test profile")
		p := pm.CurrentPrefs().AsStruct()
		p.Hostname = "test"
		if err := pm.SetPrefs(p); err != nil {
			t.Fatal(err)
		}
		wantProfiles["test"] = p.View()
		checkProfiles(t)
	}

	t.Logf("Recreate profile manager from store, should reset prefs")
	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	wantCurProfile = ""
	wantProfiles[""] = emptyPrefs
	checkProfiles(t)

	{
		t.Logf("Set prefs as server mode")
		p := pm.CurrentPrefs().AsStruct()
		p.Hostname = "default"
		uid := strconv.FormatInt(int64(os.Getuid()), 10)
		if err := pm.SaveAsStartState(uid, p); err != nil {
			t.Fatal(err)
		}
		wantProfiles[""] = p.View()
		wantStateKey = ipn.StateKey("user-" + uid)
	}
	checkProfiles(t)

	// Recreate the profile manager to ensure that it can load the profiles
	// from the store at startup.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)

	t.Logf("unload the profile")
	if err := pm.Unload(); err != nil {
		t.Fatal(err)
	}
	wantStateKey = ""
	wantProfiles[""] = emptyPrefs
	checkProfiles(t)

	// Recreate the profile manager to ensure that it starts with no profile.
	pm, err = newProfileManagerWithGOOS(store, logger.Discard, "", "windows")
	if err != nil {
		t.Fatal(err)
	}
	checkProfiles(t)
}
