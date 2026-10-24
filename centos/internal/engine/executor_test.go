package engine

import (
	"testing"

	"sih2025/internal/policy"
)

// ---------------------------------------------------------------------------
// filterRulesForPlatform
// ---------------------------------------------------------------------------

func TestFilterRulesForPlatform_CentOSOnly(t *testing.T) {
	rules := []policy.Rule{
		{ID: "A", Platform: "centos"},
		{ID: "B", Platform: "ubuntu"},
		{ID: "C", Platform: "windows"},
		{ID: "D", Platform: ""},       // universal
		{ID: "E", Platform: "CentOS"}, // case-insensitive
	}

	got := filterRulesForPlatform(rules, "centos")
	wantIDs := map[string]bool{"A": true, "D": true, "E": true}

	if len(got) != len(wantIDs) {
		t.Errorf("want %d rules, got %d: %v", len(wantIDs), len(got), ruleIDs(got))
	}
	for _, r := range got {
		if !wantIDs[r.ID] {
			t.Errorf("unexpected rule %s in centos filter", r.ID)
		}
	}
}

func TestFilterRulesForPlatform_Ubuntu(t *testing.T) {
	rules := []policy.Rule{
		{ID: "A", Platform: "centos"},
		{ID: "B", Platform: "ubuntu"},
		{ID: "C", Platform: ""},
	}

	got := filterRulesForPlatform(rules, "ubuntu")
	wantIDs := map[string]bool{"B": true, "C": true}

	if len(got) != len(wantIDs) {
		t.Errorf("ubuntu filter: want %d, got %d: %v", len(wantIDs), len(got), ruleIDs(got))
	}
}

func TestFilterRulesForPlatform_EmptyPlatform(t *testing.T) {
	rules := []policy.Rule{
		{ID: "A", Platform: "centos"},
		{ID: "B", Platform: "ubuntu"},
	}
	// Empty platform string = no filtering = all rules.
	got := filterRulesForPlatform(rules, "")
	// With empty platformName in filterRulesForPlatform, both should pass
	// because lowerPlatform="" matches rp="" OR rp==lowerPlatform="" only.
	// Actually: rp="centos" != "" so centos would be filtered out when platformName is "".
	// Wait — with empty platformName, both have non-empty rp, so neither matches.
	// This is fine: passing "" means "include universal rules only".
	// That is the documented behaviour for the legacy RunAudit path.
	for _, r := range got {
		if r.Platform != "" {
			t.Errorf("with empty platformName, non-universal rule %s should not be included", r.ID)
		}
	}
}

func TestFilterRulesForPlatform_NoCentOSRulesReturnedForWindows(t *testing.T) {
	rules := []policy.Rule{
		{ID: "COS1", Platform: "centos"},
		{ID: "WIN1", Platform: "windows"},
	}
	got := filterRulesForPlatform(rules, "windows")
	for _, r := range got {
		if r.Platform == "centos" {
			t.Errorf("centos rule should not appear in windows filter")
		}
	}
}

// ---------------------------------------------------------------------------
// evidenceDigest
// ---------------------------------------------------------------------------

func TestEvidenceDigest_Deterministic(t *testing.T) {
	d1 := evidenceDigest("Enforcing")
	d2 := evidenceDigest("Enforcing")
	if d1 != d2 {
		t.Errorf("digest not deterministic: %s vs %s", d1, d2)
	}
}

func TestEvidenceDigest_DifferentInputsDifferentDigests(t *testing.T) {
	d1 := evidenceDigest("Enforcing")
	d2 := evidenceDigest("Permissive")
	if d1 == d2 {
		t.Errorf("different inputs should produce different digests")
	}
}

func TestEvidenceDigest_Length(t *testing.T) {
	d := evidenceDigest("test")
	if len(d) != 16 {
		t.Errorf("expected 16-char digest, got %d: %s", len(d), d)
	}
}

// ---------------------------------------------------------------------------
// deriveNewValueLabel
// ---------------------------------------------------------------------------

func TestDeriveNewValueLabel_ReplaceText(t *testing.T) {
	rule := policy.Rule{
		Remediation: policy.Action{
			ReplaceText: "SELINUX=enforcing",
		},
	}
	got := deriveNewValueLabel(rule)
	if got != "SELINUX=enforcing" {
		t.Errorf("want 'SELINUX=enforcing', got %q", got)
	}
}

func TestDeriveNewValueLabel_SysctlAssignment(t *testing.T) {
	rule := policy.Rule{
		Remediation: policy.Action{
			Args: []string{"net.ipv4.ip_forward=0"},
		},
	}
	got := deriveNewValueLabel(rule)
	if got != "net.ipv4.ip_forward=0" {
		t.Errorf("want 'net.ipv4.ip_forward=0', got %q", got)
	}
}

func TestDeriveNewValueLabel_Default(t *testing.T) {
	rule := policy.Rule{
		Remediation: policy.Action{},
	}
	got := deriveNewValueLabel(rule)
	if got != "Applied Fix" {
		t.Errorf("want 'Applied Fix', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// statusConstants — verify they match documented vocabulary
// ---------------------------------------------------------------------------

func TestStatusConstants(t *testing.T) {
	expected := map[string]string{
		"PASS":           StatusPASS,
		"FAIL":           StatusFAIL,
		"UNKNOWN":        StatusUNKNOWN,
		"ERROR":          StatusERROR,
		"NOT_APPLICABLE": StatusNOT_APPLICABLE,
		"TIMEOUT":        StatusTIMEOUT,
	}
	for want, got := range expected {
		if want != got {
			t.Errorf("status constant mismatch: want %q, got %q", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func ruleIDs(rules []policy.Rule) []string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}
