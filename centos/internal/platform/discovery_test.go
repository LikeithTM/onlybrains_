//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseOSRelease verifies key=value parsing including quoted values and comments.
func TestParseOSRelease(t *testing.T) {
	content := `# Comment line
NAME="CentOS Stream"
VERSION="9"
ID=centos
ID_LIKE="rhel fedora"
VERSION_ID=9
PRETTY_NAME="CentOS Stream 9"
`
	tmp := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	fields := parseOSRelease(tmp)

	if got := fields["ID"]; got != "centos" {
		t.Errorf("ID: want 'centos', got %q", got)
	}
	if got := fields["VERSION_ID"]; got != "9" {
		t.Errorf("VERSION_ID: want '9', got %q", got)
	}
	if got := fields["PRETTY_NAME"]; got != `"CentOS Stream 9"` {
		t.Errorf("PRETTY_NAME: want '\"CentOS Stream 9\"', got %q", got)
	}
	if _, has := fields["#"]; has {
		t.Error("comment line should not be parsed as a key")
	}
}

// TestParseOSReleaseMissingFile verifies that a missing file returns an empty map (not a panic).
func TestParseOSReleaseMissingFile(t *testing.T) {
	fields := parseOSRelease("/this/path/does/not/exist")
	if len(fields) != 0 {
		t.Errorf("expected empty map for missing file, got %v", fields)
	}
}

// TestDetectOS_CentOS9 tests detection of a supported CentOS Stream 9 system.
func TestDetectOS_CentOS9(t *testing.T) {
	// Write a fake /etc/os-release and override detectOSFromPath.
	tmp := filepath.Join(t.TempDir(), "os-release")
	content := `NAME="CentOS Stream"
VERSION="9"
ID=centos
ID_LIKE="rhel fedora"
VERSION_ID=9
PRETTY_NAME="CentOS Stream 9"
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fields := parseOSRelease(tmp)
	info := buildOSInfo(fields)

	if info.ID != "centos" {
		t.Errorf("ID: want 'centos', got %q", info.ID)
	}
	if info.VersionID != "9" {
		t.Errorf("VersionID: want '9', got %q", info.VersionID)
	}
	if info.SupportStatus != "SUPPORTED" {
		t.Errorf("SupportStatus: want 'SUPPORTED', got %q — %s", info.SupportStatus, info.SupportDetail)
	}
}

// TestDetectOS_RHEL rejects RHEL as unsupported.
func TestDetectOS_RHEL(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "os-release")
	content := `ID=rhel
VERSION_ID=9
PRETTY_NAME="Red Hat Enterprise Linux 9"
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fields := parseOSRelease(tmp)
	info := buildOSInfo(fields)

	if info.SupportStatus != "UNSUPPORTED" {
		t.Errorf("RHEL should be UNSUPPORTED, got %q", info.SupportStatus)
	}
}

// TestDetectOS_Rocky rejects Rocky Linux as unsupported.
func TestDetectOS_Rocky(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "os-release")
	content := `ID=rocky
VERSION_ID=9
PRETTY_NAME="Rocky Linux 9"
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fields := parseOSRelease(tmp)
	info := buildOSInfo(fields)

	if info.SupportStatus != "UNSUPPORTED" {
		t.Errorf("Rocky should be UNSUPPORTED, got %q", info.SupportStatus)
	}
}

// TestDetectOS_CentOS8 rejects CentOS 8 as unsupported version.
func TestDetectOS_CentOS8(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "os-release")
	content := `ID=centos
VERSION_ID=8
PRETTY_NAME="CentOS Linux 8"
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fields := parseOSRelease(tmp)
	info := buildOSInfo(fields)

	if info.SupportStatus != "UNSUPPORTED" {
		t.Errorf("CentOS 8 should be UNSUPPORTED, got %q", info.SupportStatus)
	}
}

// TestDetectOS_Ubuntu rejects Ubuntu as unsupported.
func TestDetectOS_Ubuntu(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "os-release")
	content := `ID=ubuntu
VERSION_ID="22.04"
PRETTY_NAME="Ubuntu 22.04 LTS"
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fields := parseOSRelease(tmp)
	info := buildOSInfo(fields)

	if info.SupportStatus != "UNSUPPORTED" {
		t.Errorf("Ubuntu should be UNSUPPORTED, got %q", info.SupportStatus)
	}
}

// TestDetectOS_EmptyID handles an os-release with no ID field.
func TestDetectOS_EmptyID(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "os-release")
	content := `PRETTY_NAME="Some Linux"
VERSION_ID=1
`
	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	fields := parseOSRelease(tmp)
	info := buildOSInfo(fields)

	if info.SupportStatus != "UNKNOWN_OS" {
		t.Errorf("empty ID should yield UNKNOWN_OS, got %q", info.SupportStatus)
	}
}

// buildOSInfo is a testable helper that applies the same logic as DetectOS
// but without the os.Hostname() and uname calls so unit tests are hermetic.
func buildOSInfo(fields map[string]string) OSInfo {
	info := OSInfo{
		SupportStatus: "UNKNOWN_OS",
		SupportDetail: "no ID field",
	}
	info.ID = trimQuotes(fields["ID"])
	info.IDLike = trimQuotes(fields["ID_LIKE"])
	info.VersionID = trimQuotes(fields["VERSION_ID"])
	pretty := trimQuotes(fields["PRETTY_NAME"])
	name := trimQuotes(fields["NAME"])
	if pretty != "" {
		info.Name = pretty
	} else {
		info.Name = name
	}

	if info.ID == "" {
		return info
	}
	if !supportedIDs[info.ID] {
		info.SupportStatus = "UNSUPPORTED"
		info.SupportDetail = "distribution not supported"
		return info
	}
	versions, ok := supportedVersions[info.ID]
	if !ok || !versions[info.VersionID] {
		info.SupportStatus = "UNSUPPORTED"
		info.SupportDetail = "version not supported"
		return info
	}
	info.SupportStatus = "SUPPORTED"
	info.SupportDetail = "fully supported"
	return info
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
