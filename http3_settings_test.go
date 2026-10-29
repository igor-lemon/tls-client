package tls_client

import (
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/igor-lemon/quic-go-utls/http3"
	"github.com/igor-lemon/utls/behavior"
)

func TestHTTP3SettingsFactoryUsesPolicyAndIsolatesConnections(t *testing.T) {
	pol := behavior.Legacy().Clone()
	pol["h3.grease_setting_n_min"] = json.RawMessage("0")
	pol["h3.grease_setting_n_max"] = json.RawMessage("0")
	settings := map[uint64]uint64{1: 65536}
	order := []uint64{1}
	built, err := buildHTTP3Transport(&http3Config{behavior: pol, http3Settings: settings, http3SettingsOrder: order})
	if err != nil {
		t.Fatal(err)
	}
	tr := built.(*http3.Transport)
	if tr.SettingsForConnection == nil {
		t.Fatal("SETTINGS factory absent")
	}
	// Fixed-range repeats are valid, not a freshness failure. Source edits must
	// not change a configured transport or another connection's snapshot.
	pol["h3.grease_setting_n_min"] = json.RawMessage("9")
	settings[1] = 0
	order[0] = 6
	var wait sync.WaitGroup
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			values, ordered := tr.SettingsForConnection()
			if len(values) != 2 || values[1] != 65536 || len(ordered) != 2 || ordered[0] != 1 || ordered[1] != 33 {
				t.Errorf("policy/snapshot lost: %v %v", values, ordered)
			}
			if _, ok := values[33]; !ok {
				t.Error("fixed lower boundary GREASE missing")
			}
			values[1] = 42
			ordered[0] = 42
		}()
	}
	wait.Wait()
}

func TestHTTP3SettingsFactoryDisabledAndMaximumPolicy(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		pol := behavior.Legacy().Clone()
		pol["h3.grease_settings"], _ = json.Marshal(enabled)
		pol["h3.grease_setting_n_min"] = json.RawMessage("4294967295")
		pol["h3.grease_setting_n_max"] = json.RawMessage("4294967295")
		built, err := buildHTTP3Transport(&http3Config{behavior: pol})
		if err != nil {
			t.Fatal(err)
		}
		values, _ := built.(*http3.Transport).SettingsForConnection()
		if !enabled && len(values) != 0 {
			t.Fatal("disabled GREASE sent")
		}
		if enabled {
			if _, ok := values[31*uint64(4294967295)+33]; !ok {
				t.Fatal("upper boundary lost")
			}
		}
	}
}

func TestHTTP3SettingsGREASEPlacementIsSelectedByData(t *testing.T) {
	for _, tc := range []struct {
		placement   string
		order, want []uint64
	}{
		{"last", []uint64{1, 6, 7, 51}, []uint64{1, 6, 7, 51, 33}},
		{"before-greater-id", []uint64{1, 6, 7, 51}, []uint64{1, 6, 7, 33, 51}},
		{"before-greater-id", []uint64{51, 7, 1, 6}, []uint64{33, 51, 7, 1, 6}},
	} {
		t.Run(tc.placement+fmt.Sprint(tc.order), func(t *testing.T) {
			pol := behavior.Legacy()
			pol["h3.grease_setting_n_min"], pol["h3.grease_setting_n_max"] = json.RawMessage("0"), json.RawMessage("0")
			pol["h3.grease_setting_placement"], _ = json.Marshal(tc.placement)
			built, err := buildHTTP3Transport(&http3Config{behavior: pol, http3Settings: map[uint64]uint64{1: 65536, 6: 262144, 7: 100, 51: 1}, http3SettingsOrder: tc.order})
			if err != nil {
				t.Fatal(err)
			}
			_, order := built.(*http3.Transport).SettingsForConnection()
			if !slices.Equal(order, tc.want) {
				t.Fatal(order, "want", tc.want)
			}
		})
	}
}
