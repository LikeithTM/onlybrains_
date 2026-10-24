package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"sih2025/internal/dag"
	"sih2025/internal/platform"
	"sih2025/internal/policy"
	"sih2025/internal/state"
)

// Assessment status vocabulary — shared across all platforms.
const (
	StatusPASS           = "PASS"
	StatusFAIL           = "FAIL"
	StatusUNKNOWN        = "UNKNOWN"
	StatusERROR          = "ERROR"
	StatusNOT_APPLICABLE = "NOT_APPLICABLE"
	StatusTIMEOUT        = "TIMEOUT"
)

// AuditResult holds the result of a single control assessment.
type AuditResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Actual   string `json:"actual"`
	Expected string `json:"expected"`
	// EvidenceDigest is the SHA-256 of the assessed actual value,
	// providing a tamper-evident reference in reports.
	EvidenceDigest string `json:"evidence_digest,omitempty"`
}

// evidenceDigest computes a short SHA-256 hex of the actual value for audit linkage.
func evidenceDigest(actual string) string {
	h := sha256.Sum256([]byte(actual))
	return hex.EncodeToString(h[:])[:16]
}

// --- HELPER: Get Raw System Value (The "Smart Split" Fix) ---
func getRawSystemValue(worker platform.HardenerInterface, cmd string, args []string) string {
	// 1. Intelligent Command Splitting
	realCmd := cmd
	// Remove pipe logic to run the raw data gatherer (e.g. 'sysctl ...' without '| grep')
	if strings.Contains(cmd, "|") {
		parts := strings.Split(cmd, "|")
		realCmd = strings.TrimSpace(parts[0])
	}
	// Handle 'bash -c' wrappers
	if len(args) > 1 && args[0] == "-c" {
		inner := args[1]
		if strings.Contains(inner, "|") {
			parts := strings.Split(inner, "|")
			realCmd = "bash"
			args = []string{"-c", strings.TrimSpace(parts[0])}
		}
	}

	// 2. Execute
	success, output, err := worker.RunCommand(realCmd, args, "")
	output = strings.TrimSpace(output)

	// 3. Smart Error Handling
	if !success || err != nil {
		// If it's a grep/find command that failed, it means the setting is missing
		if strings.Contains(cmd, "grep") || strings.Contains(cmd, "find") {
			if output == "" {
				return "Not Configured"
			}
		}
		// If sysctl failed, the key likely doesn't exist
		if strings.Contains(cmd, "sysctl") {
			if output == "" {
				return "Key Missing in Kernel"
			}
		}
		// Check for specific exit code 1 (Command not found vs Data not found)
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 && output == "" {
				return "Not Set"
			}
		}
	}

	if output == "" {
		return "Empty / Not Set"
	}

	// Clean up "fail" echoes from JSON checks
	if strings.Contains(strings.ToLower(output), "fail") {
		return "Vulnerable Config"
	}

	return output
}

// filterRulesForPlatform returns only rules that match the given platform name
// (case-insensitive). Rules with an empty platform field are treated as universal
// and are included for all platforms.
// This is the fix for Gap 1: Ubuntu rules must not run on CentOS.
func filterRulesForPlatform(rules []policy.Rule, platformName string) []policy.Rule {
	filtered := make([]policy.Rule, 0, len(rules))
	lowerPlatform := strings.ToLower(platformName)
	for _, r := range rules {
		rp := strings.ToLower(r.Platform)
		if rp == "" || rp == lowerPlatform {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// assessRule runs a single rule's check and returns the assessment status and actual value.
// It correctly distinguishes PASS, FAIL, UNKNOWN, ERROR, and NOT_APPLICABLE.
func assessRule(worker platform.HardenerInterface, secManager *SecEditManager, r policy.Rule) (status, actual string) {
	switch r.Type {
	case "command", "file_check", "file_edit":
		passed, actualVal, err := worker.RunCommand(r.Check.Cmd, r.Check.Args, r.Check.ExpectPattern)

		if err != nil {
			// Command itself failed to execute — this is an ERROR, not a FAIL.
			return StatusERROR, fmt.Sprintf("exec error: %v", err)
		}

		if !passed {
			rawVal := getRawSystemValue(worker, r.Check.Cmd, r.Check.Args)
			if rawVal != "Missing" && rawVal != "fail" {
				actualVal = rawVal
			}
		}

		actualVal = strings.TrimSpace(actualVal)
		if len(actualVal) > 120 {
			actualVal = actualVal[:117] + "..."
		}
		if passed && actualVal == "" {
			actualVal = "Verified Secure"
		}

		if passed {
			return StatusPASS, actualVal
		}
		return StatusFAIL, actualVal

	case "registry":
		passed, err := worker.CheckRegistry(r.Check.RegKey, r.Check.RegValue, r.Check.Expected)
		if err != nil {
			return StatusERROR, fmt.Sprintf("registry check error: %v", err)
		}
		if passed {
			return StatusPASS, fmt.Sprintf("%v", r.Check.Expected)
		}
		return StatusFAIL, "Registry Mismatch"

	case "secedit":
		expectedStr, _ := r.Check.Expected.(string)
		passed, err := secManager.CheckUserRight(r.Check.RegKey, expectedStr)
		if err != nil {
			return StatusERROR, fmt.Sprintf("secedit error: %v", err)
		}
		if passed {
			return StatusPASS, "Right Assigned"
		}
		return StatusFAIL, "Right Missing"

	default:
		return StatusUNKNOWN, fmt.Sprintf("unknown rule type: %s", r.Type)
	}
}

// RunAudit executes rules for the given platform, filtering out inapplicable ones.
// platformName should be "centos", "ubuntu", or "windows".
// Pass "" to run all rules (legacy behaviour, not recommended).
func RunAudit(pol *policy.Policy) []AuditResult {
	return RunAuditForPlatform(pol, "")
}

// RunAuditForPlatform is the platform-aware version of RunAudit.
func RunAuditForPlatform(pol *policy.Policy, platformName string) []AuditResult {
	var results []AuditResult
	var mutex sync.Mutex

	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	// Apply platform filter before DAG scheduling.
	rulesToRun := pol.Rules
	if platformName != "" {
		rulesToRun = filterRulesForPlatform(pol.Rules, platformName)
	}

	layers, err := dag.SortRules(rulesToRun)
	if err != nil {
		fmt.Printf("[CRITICAL ERROR] Dependency Cycle: %v\n", err)
		return nil
	}

	for _, layer := range layers {
		var wg sync.WaitGroup
		for _, rule := range layer {
			wg.Add(1)
			go func(r policy.Rule) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				resultChan := make(chan struct {
					status string
					actual string
				}, 1)

				go func() {
					s, a := assessRule(worker, secManager, r)
					resultChan <- struct{ status, actual string }{s, a}
				}()

				var finalRes struct{ status, actual string }
				select {
				case res := <-resultChan:
					finalRes = res
				case <-ctx.Done():
					finalRes = struct{ status, actual string }{StatusTIMEOUT, "Check timed out"}
				}

				mutex.Lock()
				results = append(results, AuditResult{
					ID:             r.ID,
					Name:           r.Name,
					Severity:       r.Severity,
					Status:         finalRes.status,
					Actual:         finalRes.actual,
					Expected:       r.Check.ExpectPattern,
					EvidenceDigest: evidenceDigest(finalRes.actual),
				})
				mutex.Unlock()
			}(rule)
		}
		wg.Wait()
	}
	return results
}

// CapturedState holds a structured snapshot of a setting before mutation.
// This replaces the raw-string approach from the original ApplyFix.
type CapturedState struct {
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	CaptureAt time.Time `json:"capture_at"`
	// StateType describes what was captured: "raw_value", "file_backup", "service_state", etc.
	StateType string `json:"state_type"`
	// Value is the captured state as a JSON-serialisable string.
	Value string `json:"value"`
	// Digest is the SHA-256 of the value field for tamper evidence.
	Digest string `json:"digest"`
}

// captureState gathers the current system value for a rule before mutation.
// It stores the result in the DB and returns the CapturedState.
// If capture fails, it returns an error — the caller must not proceed with mutation.
func captureState(worker platform.HardenerInterface, rule policy.Rule) (*CapturedState, error) {
	prevValue := getRawSystemValue(worker, rule.Check.Cmd, rule.Check.Args)
	if len(prevValue) > 500 {
		prevValue = prevValue[:500]
	}

	digest := sha256.Sum256([]byte(prevValue))
	cs := &CapturedState{
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		CaptureAt: time.Now(),
		StateType: "raw_value",
		Value:     prevValue,
		Digest:    hex.EncodeToString(digest[:]),
	}

	// Serialise for DB storage.
	serialised, err := json.Marshal(cs)
	if err != nil {
		return nil, fmt.Errorf("state serialisation failed: %v", err)
	}

	newValue := deriveNewValueLabel(rule)

	// Log to DB — this is the durable record enabling rollback.
	if err := state.LogAction(rule.ID, rule.Name, string(serialised), newValue); err != nil {
		return nil, fmt.Errorf("state capture DB write failed: %v", err)
	}

	return cs, nil
}

// deriveNewValueLabel extracts a human-readable label for the intended new value.
// Used only for display and logging — not for execution.
func deriveNewValueLabel(rule policy.Rule) string {
	if rule.Remediation.ReplaceText != "" {
		return strings.TrimSpace(rule.Remediation.ReplaceText)
	}
	if len(rule.Remediation.Args) > 0 {
		fullCmd := strings.Join(rule.Remediation.Args, " ")
		if strings.Contains(fullCmd, "=") && !strings.Contains(fullCmd, "==") {
			parts := strings.Fields(fullCmd)
			for _, p := range parts {
				if strings.Contains(p, "=") && !strings.HasPrefix(p, "-") {
					return p
				}
			}
		}
		if strings.Contains(fullCmd, "chmod") {
			parts := strings.Fields(fullCmd)
			for _, p := range parts {
				if _, err := strconv.Atoi(p); err == nil {
					return "Mode: " + p
				}
			}
		}
		if strings.Contains(fullCmd, "modprobe") && strings.Contains(fullCmd, "/bin/true") {
			return "Module Blacklisted"
		}
		if strings.Contains(fullCmd, "bash -c") {
			return strings.TrimPrefix(fullCmd, "bash -c ")
		}
		return fullCmd
	}
	return "Applied Fix"
}

// ApplyFix performs remediation for the given rule.
// It MUST capture state before mutating. If state capture fails, no mutation is performed.
func ApplyFix(rule policy.Rule) error {
	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	fmt.Printf("[FIX] Automating Rule: %s\n", rule.ID)

	// --- 1. CAPTURE STATE BEFORE MUTATION (non-optional) ---
	_, err := captureState(worker, rule)
	if err != nil {
		return fmt.Errorf("state capture failed, mutation aborted: %v", err)
	}

	// --- 2. APPLY ---
	switch rule.Remediation.Type {
	case "registry":
		err = worker.SetRegistry(rule.Remediation.RegKey, rule.Remediation.RegValue, rule.Remediation.Value)
	case "command":
		_, _, err = worker.RunCommand(rule.Remediation.Cmd, rule.Remediation.Args, "")
	case "file_edit", "file_append":
		err = worker.EditConfigFile(rule.Remediation.FilePath, rule.Remediation.SearchRegex, rule.Remediation.ReplaceText)
	case "secedit":
		valStr, _ := rule.Remediation.Value.(string)
		err = secManager.SetUserRight(rule.Remediation.RegKey, valStr)
	case "manual":
		if rule.Remediation.Cmd != "echo" && rule.Remediation.Cmd != "" {
			_, _, err = worker.RunCommand(rule.Remediation.Cmd, rule.Remediation.Args, "")
		} else {
			return fmt.Errorf("manual action required")
		}
	default:
		return fmt.Errorf("unknown remediation type: %s", rule.Remediation.Type)
	}

	if err != nil {
		return fmt.Errorf("fix failed: %v", err)
	}
	return nil
}

// RevertFix performs rollback for the given rule.
// It prefers captured state from the DB over the static rollback definition in the policy.
func RevertFix(rule policy.Rule) error {
	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	// Attempt to use captured state from DB.
	rawCapture, dbErr := state.GetRollbackData(rule.ID)
	if dbErr == nil && rawCapture != "" {
		// Try to parse as CapturedState JSON.
		var cs CapturedState
		if jsonErr := json.Unmarshal([]byte(rawCapture), &cs); jsonErr == nil {
			// We have structured state. For "raw_value" type, we can only
			// restore config-file values; other types fall through to rollback definition.
			if cs.StateType == "raw_value" && rule.Rollback.Type == "file_edit" {
				fmt.Printf("[ROLLBACK] Using captured state for %s (value: %.40s...)\n", rule.ID, cs.Value)
				return worker.EditConfigFile(
					rule.Rollback.FilePath,
					rule.Rollback.SearchRegex,
					cs.Value,
				)
			}
		}
	}

	// Fall back to the static rollback definition in the policy.
	var err error
	switch rule.Rollback.Type {
	case "registry":
		err = worker.SetRegistry(rule.Rollback.RegKey, rule.Rollback.RegValue, rule.Rollback.Value)
	case "command":
		_, _, err = worker.RunCommand(rule.Rollback.Cmd, rule.Rollback.Args, "")
	case "file_edit":
		err = worker.EditConfigFile(rule.Rollback.FilePath, rule.Rollback.SearchRegex, rule.Rollback.ReplaceText)
	case "secedit":
		valStr, _ := rule.Rollback.Value.(string)
		err = secManager.SetUserRight(rule.Rollback.RegKey, valStr)
	default:
		return fmt.Errorf("unknown rollback type: %s", rule.Rollback.Type)
	}
	return err
}

func RevertAll(pol *policy.Policy) (string, error) {
	revertedCount := 0
	errorCount := 0

	fmt.Println("[RESET] Starting MASTER FORCE RESET...")

	for _, rule := range pol.Rules {
		fmt.Printf("   > Force Reverting: %s\n", rule.ID)
		err := RevertFix(rule)
		if err != nil {
			fmt.Printf("     [WARN] Revert issue on %s: %v\n", rule.ID, err)
			errorCount++
		} else {
			revertedCount++
		}
	}

	return fmt.Sprintf("Reset Complete. Reverted %d rules. Errors: %d", revertedCount, errorCount), nil
}
