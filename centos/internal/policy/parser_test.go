package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadPolicy_Valid verifies a well-formed policy JSON is loaded correctly.
func TestLoadPolicy_Valid(t *testing.T) {
	content := `{
  "version": "1.1",
  "rules": [
    {
      "id": "SX-COS-TEST-01",
      "name": "Test Rule",
      "severity": "High",
      "platform": "centos",
      "type": "command",
      "check": { "cmd": "echo", "args": ["ok"], "expect_pattern": "ok" },
      "remediation": { "type": "command", "cmd": "echo", "args": ["fixed"] },
      "rollback":    { "type": "command", "cmd": "echo", "args": ["rolled"] }
    }
  ]
}`
	tmp := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	pol, err := LoadPolicy(tmp)
	if err != nil {
		t.Fatalf("LoadPolicy error: %v", err)
	}
	if pol.Version != "1.1" {
		t.Errorf("version: want '1.1', got %q", pol.Version)
	}
	if len(pol.Rules) != 1 {
		t.Fatalf("want 1 rule, got %d", len(pol.Rules))
	}
	r := pol.Rules[0]
	if r.ID != "SX-COS-TEST-01" {
		t.Errorf("rule ID: want 'SX-COS-TEST-01', got %q", r.ID)
	}
	if r.Platform != "centos" {
		t.Errorf("platform: want 'centos', got %q", r.Platform)
	}
	if r.Check.Cmd != "echo" {
		t.Errorf("check.cmd: want 'echo', got %q", r.Check.Cmd)
	}
}

// TestLoadPolicy_InvalidJSON returns an error on malformed JSON.
func TestLoadPolicy_InvalidJSON(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(tmp, []byte(`{ invalid json `), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadPolicy(tmp)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// TestLoadPolicy_MissingFile returns an error when the file does not exist.
func TestLoadPolicy_MissingFile(t *testing.T) {
	_, err := LoadPolicy("/tmp/this-file-does-not-exist-sentinelx.json")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestLoadPolicy_EmptyRules verifies a policy with no rules loads without error.
func TestLoadPolicy_EmptyRules(t *testing.T) {
	content := `{"version": "1.0", "rules": []}`
	tmp := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	pol, err := LoadPolicy(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pol.Rules) != 0 {
		t.Errorf("want 0 rules, got %d", len(pol.Rules))
	}
}

// TestLoadPolicy_PlatformFieldPreserved verifies platform field is not modified.
func TestLoadPolicy_PlatformFieldPreserved(t *testing.T) {
	content := `{
  "version": "1.0",
  "rules": [
    {"id":"R1","platform":"centos","type":"command","check":{"cmd":"echo"},"remediation":{"type":"command"},"rollback":{"type":"command"}},
    {"id":"R2","platform":"ubuntu","type":"command","check":{"cmd":"echo"},"remediation":{"type":"command"},"rollback":{"type":"command"}},
    {"id":"R3","platform":"","type":"command","check":{"cmd":"echo"},"remediation":{"type":"command"},"rollback":{"type":"command"}}
  ]
}`
	tmp := filepath.Join(t.TempDir(), "mixed.json")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	pol, err := LoadPolicy(tmp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, r := range pol.Rules {
		switch r.ID {
		case "R1":
			if r.Platform != "centos" {
				t.Errorf("R1: want platform 'centos', got %q", r.Platform)
			}
		case "R2":
			if r.Platform != "ubuntu" {
				t.Errorf("R2: want platform 'ubuntu', got %q", r.Platform)
			}
		case "R3":
			if r.Platform != "" {
				t.Errorf("R3: want empty platform, got %q", r.Platform)
			}
		}
	}
}

// TestLoadPolicy_CentOSHardeningFile verifies the real CentOS policy file loads.
// This test is skipped if the file is not present (e.g., different working directory).
func TestLoadPolicy_CentOSHardeningFile(t *testing.T) {
	// Attempt from the centos/ directory root — policies are relative there.
	path := "../../policies/centos_hardening.json"
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("centos_hardening.json not found relative to test directory — skipping")
	}

	pol, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy(centos_hardening.json): %v", err)
	}
	if len(pol.Rules) == 0 {
		t.Error("centos_hardening.json: expected at least 1 rule")
	}
	for _, r := range pol.Rules {
		if r.Platform != "centos" && r.Platform != "" {
			t.Errorf("rule %s has platform %q — expected 'centos' or '' in CentOS policy", r.ID, r.Platform)
		}
		if r.ID == "" {
			t.Errorf("rule has empty ID — all rules must have a stable ID")
		}
	}
}
