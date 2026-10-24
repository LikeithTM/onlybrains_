//go:build linux

package platform

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// OSInfo holds the detected operating system information for this host.
// It is populated once at startup via DetectOS().
type OSInfo struct {
	// ID is the value of the ID field in /etc/os-release (e.g. "centos").
	ID string
	// IDLike is the value of ID_LIKE (e.g. "rhel fedora").
	IDLike string
	// Name is the PRETTY_NAME or NAME field (e.g. "CentOS Stream 9").
	Name string
	// VersionID is the VERSION_ID field (e.g. "9").
	VersionID string
	// Arch is the host CPU architecture reported by Go (e.g. "amd64").
	Arch string
	// KernelVersion is the output of `uname -r`.
	KernelVersion string
	// Hostname is the system hostname.
	Hostname string
	// SupportStatus is one of: SUPPORTED, UNSUPPORTED, UNKNOWN_OS.
	SupportStatus string
	// SupportDetail is a human-readable explanation.
	SupportDetail string
}

// supportedIDs lists the exact /etc/os-release ID values we support.
// Do NOT add "rhel", "rocky", "almalinux" here without separate validation.
var supportedIDs = map[string]bool{
	"centos": true,
}

// supportedVersions lists the exact VERSION_ID values we support for each ID.
var supportedVersions = map[string]map[string]bool{
	"centos": {"9": true},
}

// DetectOS reads /etc/os-release and system utilities to populate OSInfo.
// It does not assume the target is CentOS just because it is Linux.
func DetectOS() OSInfo {
	info := OSInfo{
		Arch:          runtime.GOARCH,
		SupportStatus: "UNKNOWN_OS",
		SupportDetail: "/etc/os-release could not be read",
	}

	// --- Read /etc/os-release ---
	fields := parseOSRelease("/etc/os-release")
	info.ID = strings.ToLower(strings.Trim(fields["ID"], `"`))
	info.IDLike = strings.ToLower(strings.Trim(fields["ID_LIKE"], `"`))
	info.VersionID = strings.Trim(fields["VERSION_ID"], `"`)

	prettyName := strings.Trim(fields["PRETTY_NAME"], `"`)
	name := strings.Trim(fields["NAME"], `"`)
	if prettyName != "" {
		info.Name = prettyName
	} else {
		info.Name = name
	}

	// --- Kernel version ---
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(out))
	}

	// --- Hostname ---
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}

	// --- Determine support status ---
	if info.ID == "" {
		info.SupportStatus = "UNKNOWN_OS"
		info.SupportDetail = "/etc/os-release has no ID field"
		return info
	}

	if !supportedIDs[info.ID] {
		info.SupportStatus = "UNSUPPORTED"
		info.SupportDetail = fmt.Sprintf(
			"Distribution '%s' is not a supported target (supported: centos)",
			info.ID,
		)
		return info
	}

	versions, ok := supportedVersions[info.ID]
	if !ok || !versions[info.VersionID] {
		info.SupportStatus = "UNSUPPORTED"
		info.SupportDetail = fmt.Sprintf(
			"Version '%s' of '%s' is not supported (supported versions: 9)",
			info.VersionID, info.ID,
		)
		return info
	}

	info.SupportStatus = "SUPPORTED"
	info.SupportDetail = fmt.Sprintf(
		"CentOS Stream %s detected on %s — fully supported target",
		info.VersionID, info.Arch,
	)
	return info
}

// parseOSRelease reads the key=value file at path and returns a map.
// Lines that are blank or start with # are skipped.
func parseOSRelease(path string) map[string]string {
	result := make(map[string]string)

	f, err := os.Open(path)
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		result[key] = val
	}
	return result
}
