# CentOS Platform — SentinelX Implementation Guide

## 1. Overview

This document describes the CentOS platform implementation within the SentinelX autonomous
hardening tool (`centos/` subdirectory). It covers supported targets, required software,
build and launch commands, supported controls, privilege requirements, demonstration
instructions, rollback behaviour, test instructions, and known limitations.

**Supported target:** CentOS Stream 9 (x86_64 or aarch64)

**Not supported:** CentOS Stream 10, CentOS Linux 8 or earlier, RHEL, Rocky Linux, AlmaLinux.
These distributions will be detected, reported as `UNSUPPORTED`, and the tool will warn
— it will not silently treat them as CentOS.

---

## 2. Architecture

The SentinelX CentOS implementation is a **single Go binary** that:

1. Detects the host OS accurately via `/etc/os-release` parsing.
2. Loads the CentOS-specific policy file (`policies/centos_hardening.json`).
3. Filters rules by `platform=="centos"` so Ubuntu and Windows rules never run.
4. Assesses each applicable control concurrently with a 5-second timeout.
5. Returns structured JSON results via a REST API on `:8080`.
6. Logs state to SQLite before every mutation to enable rollback.
7. Serves a web dashboard for interactive scanning, fixing and PDF export.

The binary does **not** require a separate controller, Python service, or Kafka.

---

## 3. Repository Layout

```
centos/
├── cmd/app/main.go                      # Entry point, Gin HTTP server
├── internal/
│   ├── platform/
│   │   ├── platform.go                  # HardenerInterface definition
│   │   ├── lin_fs.go                    # LinuxHardener implementation
│   │   ├── discovery.go                 # CentOS OS detection (DetectOS)
│   │   └── win_reg.go                   # Windows stubs (build:windows)
│   ├── engine/
│   │   ├── executor.go                  # RunAuditForPlatform, ApplyFix, RevertFix
│   │   ├── secedit_utils.go             # Windows secedit (build:windows)
│   │   └── secedit_linux_stub.go        # Linux no-op stubs
│   ├── policy/
│   │   ├── types.go                     # Rule, Policy structs
│   │   └── parser.go                    # LoadPolicy (JSON)
│   ├── state/
│   │   └── db.go                        # SQLite state capture & rollback log
│   ├── dag/
│   │   └── scheduler.go                 # Kahn topological sort for rule dependencies
│   └── report/
│       └── pdf_gen.go                   # PDF audit report generation
├── policies/
│   ├── centos_hardening.json            # CentOS-only policy (primary)
│   └── annexure_b.json                  # Mixed legacy policy (fallback only)
├── ui/
│   └── templates/index.html             # Web dashboard
└── go.mod
```

---

## 4. Prerequisites

### On the CentOS Stream 9 target machine

| Requirement | Purpose |
|---|---|
| Go 1.24+ | Build from source |
| `sudo` / root | Privilege escalation for privileged checks and remediations |
| `systemctl` | Service state checks |
| `rpm`, `dnf` | Package state checks and package remediation |
| `getenforce` / `setenforce` | SELinux mode checks |
| `grep`, `stat`, `sysctl` | Various assessments |
| `sshd_config` readable | SSH configuration assessment |

The binary runs as the user invoking it. Most **read-only** assessments require no elevated
privilege. Remediation operations (file writes, systemctl changes, chmod) require `sudo`
or running the binary as root.

> **Security note:** Do not run the entire web server as root in production. Instead, run the
> server as an unprivileged user and use a narrowly-scoped sudoers rule for only the required
> remediation commands. Running as root is acceptable only for isolated lab/demo environments.

---

## 5. Build Instructions

### Cross-compile from Windows (developer machine)

```powershell
# From the centos/ directory
cd centos

# Set Linux target
$env:GOOS = "linux"
$env:GOARCH = "amd64"

go mod tidy
go build -o hardening-tool-centos ./cmd/app/
```

Copy `hardening-tool-centos` and the `policies/`, `ui/` directories to the CentOS target.

### Build directly on CentOS target

```bash
cd centos
go mod tidy
go build -o hardening-tool ./cmd/app/
```

### Run tests (on Linux)

```bash
cd centos
go test ./...
```

---

## 6. Running the Tool

### On the CentOS target

```bash
# Minimum: read-only scan (no root required for most checks)
./hardening-tool

# With privileges for full remediation support
sudo ./hardening-tool
```

The tool starts a web server at `http://localhost:8080`.

**On startup the tool prints:**

```
==================================================
   SIH 2025 HARDENING ORCHESTRATOR (v2.1)
   DETECTED OS : CentOS Stream 9
   VERSION ID  : 9
   ARCH        : amd64
   KERNEL      : 5.14.0-437.el9.x86_64
   HOSTNAME    : centos-lab-01
   SUPPORT     : SUPPORTED — CentOS Stream 9 detected on amd64 — fully supported target
==================================================
```

If the tool detects an unsupported distribution, it prints a warning but continues running.

---

## 7. API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | OS info + online status |
| GET | `/api/discovery` | Full target profile (ID, arch, kernel, hostname, support status) |
| GET | `/api/scan?level=strict` | Run platform-filtered assessment |
| POST | `/api/fix` | Apply remediation for a rule (body: `{"id":"SX-COS-6-01"}`) |
| POST | `/api/rollback` | Rollback a rule (body: `{"id":"SX-COS-6-01"}`) |
| GET | `/api/export?level=strict` | Download PDF audit report |
| POST | `/api/reset` | Rollback all rules (caution: irreversible) |

### `/api/scan` response format

```json
{
  "results": [
    {
      "id": "SX-COS-6-01",
      "name": "SELinux Enforcing Mode (Runtime)",
      "severity": "Critical",
      "status": "PASS",
      "actual": "Enforcing",
      "expected": "Enforcing",
      "evidence_digest": "a3f7c1d2e8b09f4e"
    }
  ]
}
```

**Status vocabulary:**

| Status | Meaning |
|---|---|
| `PASS` | Expected secure state confirmed |
| `FAIL` | Control verified non-compliant |
| `UNKNOWN` | Evidence insufficient to decide |
| `ERROR` | Assessment could not complete (command failed to execute) |
| `NOT_APPLICABLE` | Control does not apply to this target |
| `TIMEOUT` | Assessment exceeded 5-second limit |

---

## 8. Supported Controls

All controls use internal SentinelX IDs prefixed `SX-COS-`. CIS benchmark mappings are
provided as reference only, sourced from CIS CentOS Linux 8 Benchmark v1.0.0. They have
**not been independently verified** against the CIS CentOS Stream 9 Benchmark (not yet published).
Do not cite these as verified CIS coverage.

### Tier-1 Controls (implemented and testable)

| ID | Name | Severity | Category | Automated Fix | Rollback |
|---|---|---|---|---|---|
| SX-COS-6-01 | SELinux Enforcing Mode (Runtime) | Critical | SELinux | ✅ setenforce 1 | ✅ setenforce 0 |
| SX-COS-6-02 | SELinux Persistent Config | Critical | SELinux | ✅ file_edit | ✅ file_edit |
| SX-COS-9-01 | SSH — Disable Root Login | High | SSH | ✅ file_edit | ✅ file_edit |
| SX-COS-9-02 | SSH — Disable Password Auth | High | SSH | ✅ file_edit | ✅ file_edit |
| SX-COS-9-03 | SSH — Disable Empty Passwords | Critical | SSH | ✅ file_edit | ✅ file_edit |
| SX-COS-8-01 | auditd — Package Installed | High | Audit | ✅ dnf install | ⚠️ manual |
| SX-COS-8-02 | auditd — Service Active | High | Audit | ✅ systemctl enable | ✅ systemctl disable |
| SX-COS-3-01 | Chrony — Package Installed | Medium | Time Sync | ✅ dnf install | ⚠️ manual |
| SX-COS-3-02 | Chrony — Service Active | Medium | Time Sync | ✅ systemctl enable | ✅ systemctl disable |
| SX-COS-3-03 | Telnet Client — Not Installed | High | Legacy Services | ✅ dnf remove | ⚠️ manual |
| SX-COS-3-04 | ABRT — Disabled | Medium | Crash Reporting | ✅ systemctl disable | ⚠️ manual |
| SX-COS-3-05 | Default Target — Multi-User | High | Services | ✅ systemctl set-default | ✅ set-default graphical |
| SX-COS-4-01 | Sysctl — IP Forwarding Disabled | Medium | Network | ✅ file_edit sysctl.d | ✅ file_edit |
| SX-COS-4-02 | Sysctl — ICMP Redirects Disabled | Medium | Network | ✅ file_edit sysctl.d | ✅ file_edit |
| SX-COS-4-03 | Sysctl — TCP SYN Cookies | Medium | Network | ✅ file_edit sysctl.d | ✅ file_edit |
| SX-COS-7-01 | /etc/passwd — Mode 0644 | High | File Perms | ✅ chmod | ✅ chmod |
| SX-COS-7-02 | /etc/shadow — Mode 0000 | Critical | File Perms | ✅ chmod | ✅ chmod |
| SX-COS-7-03 | /etc/group — Mode 0644 | Medium | File Perms | ✅ chmod | ✅ chmod |

**Legend:** ✅ = automated | ⚠️ = manual only (rollback would violate security policy)

### Controls present but manual

- Rollback of `dnf remove` and `dnf install` operations is marked manual because re-installing
  an insecure package (telnet) or removing auditd to "rollback" would violate the security goal.

### Controls not implemented (out of scope for Tier-1)

- Firewall configuration (firewalld rules — risk of lockout on remote systems)
- IPv6 disable (significant network disruption risk — environment-specific)
- SELinux policy module management (requires site-specific policy knowledge)
- SSH protocol version, ciphers, MACs (require sshd_config validation + reload test)
- Cron file permissions (requires full cron directory scan)
- sysctl persistence via `sysctl -p` (not applied at assessment time — file-only remediation)

---

## 9. State Capture and Rollback

Before every mutation, the tool:

1. Reads the current effective value via the check command.
2. Serialises it as `CapturedState{StateType: "raw_value", Value: "..."}`.
3. Computes a SHA-256 digest of the captured value.
4. Writes to the SQLite `rollback_log` table with `rule_id`, `prev_value` (JSON), `new_value`.
5. Aborts the mutation if the DB write fails.

On rollback, the tool:

1. Queries the DB for the most recent captured state for the rule.
2. If a `CapturedState` JSON is found and the rollback type is `file_edit`, it restores
   using the captured value rather than the static inverse command.
3. Otherwise, falls back to the static `rollback` definition in the policy.

> **Limitation:** Raw-value capture is sufficient for string-valued settings. File-content
> rollback is byte-for-byte only if the value does not span multiple lines. Full file backup
> (atomic copy before edit) is not yet implemented.

---

## 10. Safe Demonstration Sequence

### Read-only scan (safe for any environment)

```bash
curl http://localhost:8080/api/scan?level=strict | python3 -m json.tool
```

### Examine a specific finding

```bash
# SELinux status
curl http://localhost:8080/api/scan | python3 -c "
import json,sys
for r in json.load(sys.stdin)['results']:
    print(r['id'], r['status'], r['actual'])
"
```

### Apply a low-risk fix (in a lab VM only)

```bash
# Fix /etc/passwd permissions (safe, idempotent)
curl -X POST http://localhost:8080/api/fix \
  -H 'Content-Type: application/json' \
  -d '{"id":"SX-COS-7-01"}'
```

### Rollback that fix

```bash
curl -X POST http://localhost:8080/api/rollback \
  -H 'Content-Type: application/json' \
  -d '{"id":"SX-COS-7-01"}'
```

### Export PDF report

```bash
curl http://localhost:8080/api/export?level=strict -o audit.pdf
```

> **DO NOT** apply SSH controls (SX-COS-9-*) without ensuring an alternative recovery path
> (console, out-of-band access, VM snapshot) is available. Disabling password authentication
> without valid SSH keys installed will lock you out.

---

## 11. Running Tests

```bash
cd centos

# All tests (Linux only — discovery tests have //go:build linux)
go test ./... -v

# Platform discovery tests only
go test ./internal/platform/... -v -run TestDetectOS

# Engine/executor tests only
go test ./internal/engine/... -v

# Policy loader tests only
go test ./internal/policy/... -v
```

**Expected baseline results (on developer machine — no CentOS VM):**

- `internal/platform`: discovery tests require Linux build tag — SKIPPED on Windows
- `internal/engine`: all unit tests PASS (hermetic, no system calls)
- `internal/policy`: all unit tests PASS except `TestLoadPolicy_CentOSHardeningFile` which
  requires the correct working directory or is SKIPPED

---

## 12. Known Limitations and Security Concerns

| Concern | Status | Recommendation |
|---|---|---|
| `bash -c "..."` in policy commands | Present in some rules | Replaced with direct args where possible; bash still used for complex multi-command sequences |
| No sshd_config syntax validation before reload | Not implemented | Add `sshd -t` validation before writing config |
| No atomic file backup | Not implemented | Implement temp-file + rename pattern in EditConfigFile |
| Sysctl remediations write to /etc/sysctl.d/ but don't call sysctl -p | Known | Changes take effect on next reboot; call sysctl -p manually or after reboot |
| No sandbox/QEMU VM integration | Not implemented | QEMU provider interface not present in codebase |
| No mTLS or Controller authentication | Not in this architecture | Architecture uses local binary, not Controller/Agent |
| No approval workflow | Not in this architecture | Implement rate-limiting middleware if multi-user access is required |
| SQLite file (hardening.db) not encrypted | Known | Use file-system-level encryption or SQLCipher for production |
| tests don't run on Windows | By design | linux build tag on discovery tests |

---

## 13. Completion Status

| Item | Status |
|---|---|
| OS detection (accurate CentOS Stream 9) | COMPLETE |
| Platform filtering (Ubuntu rules excluded) | COMPLETE |
| Status vocabulary (PASS/FAIL/UNKNOWN/ERROR/NOT_APPLICABLE) | COMPLETE |
| CentOS-only policy catalogue (18 controls) | COMPLETE |
| Structured state capture before mutation | COMPLETE |
| DB-based rollback (raw_value type) | COMPLETE |
| Evidence digest on every result | COMPLETE |
| /api/discovery endpoint | COMPLETE |
| Unit tests — platform discovery | COMPLETE |
| Unit tests — executor/filtering | COMPLETE |
| Unit tests — policy loader | COMPLETE |
| QEMU sandbox integration | NOT IMPLEMENTED (infrastructure not present) |
| mTLS Agent/Controller authentication | NOT APPLICABLE (architecture is single binary) |
| SSH config syntax validation + reload | PARTIAL (assessment only; no sshd -t check) |
| Atomic file backup before edit | NOT IMPLEMENTED |
| sysctl -p after sysctl.d write | NOT IMPLEMENTED |
| CentOS VM integration tests | NOT RUN (no CentOS VM available in dev environment) |
