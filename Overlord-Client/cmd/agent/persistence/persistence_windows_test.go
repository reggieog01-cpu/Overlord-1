//go:build windows
// +build windows

package persistence

import (
	"strings"
	"testing"
)

func TestFormatRunRegistryCommand_QuotesUnquotedPath(t *testing.T) {
	in := `C:\Users\Test User\AppData\Roaming\Overlord\agent.exe`
	got := formatRunRegistryCommand(in)
	want := `"C:\Users\Test User\AppData\Roaming\Overlord\agent.exe"`
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunRegistryCommand_LeavesQuotedPath(t *testing.T) {
	in := `"C:\Users\Test User\AppData\Roaming\Overlord\agent.exe"`
	got := formatRunRegistryCommand(in)
	if got != in {
		t.Fatalf("expected %q, got %q", in, got)
	}
}

func TestGenerateStartupValueName(t *testing.T) {
	name, err := generateStartupValueName()
	if err != nil {
		t.Fatalf("generateStartupValueName failed: %v", err)
	}
	if !strings.HasPrefix(name, registryValuePrefix) {
		t.Fatalf("expected prefix %q, got %q", registryValuePrefix, name)
	}
	if len(name) != len(registryValuePrefix)+12 {
		t.Fatalf("expected random suffix length 12, got name=%q", name)
	}
}

func TestIsOverlordRunValueName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{name: "Legacy", in: "OverlordAgent", want: true},
		{name: "LegacyCaseInsensitive", in: "overlordagent", want: true},
		{name: "Randomized", in: "OverlordAgent-a1b2c3d4e5f6", want: true},
		{name: "RandomizedCaseInsensitive", in: "overlordagent-deadbeefcafe", want: true},
		{name: "OtherApp", in: "OneDrive", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOverlordRunValueName(tt.in); got != tt.want {
				t.Fatalf("isOverlordRunValueName(%q)=%v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
