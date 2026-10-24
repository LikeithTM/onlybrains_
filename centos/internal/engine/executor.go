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
	"sih2025/internal/events"
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
	ID             string `json:"id"`
	Name           string `json:"name"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	Actual         string `json:"actual"`
	Expected       string `json:"expected"`
	EvidenceDigest string `json:"evidence_digest,omitempty"`
}

func evidenceDigest(actual string) string {
	h := sha256.Sum256([]byte(actual))
	return hex.EncodeToString(h[:])[:16]
}

func getRawSystemValue(worker platform.HardenerInterface, cmd string, args []string) string {
	realCmd := cmd
	if strings.Contains(cmd, "|") {
		parts := strings.Split(cmd, "|")
		realCmd = strings.TrimSpace(parts[0])
	}
	if len(args) > 1 && args[0] == "-c" {
		inner := args[1]
		if strings.Contains(inner, "|") {
			parts := strings.Split(inner, "|")
			realCmd = "bash"
			args = []string{"-c", strings.TrimSpace(parts[0])}
		}
	}

	success, output, err := worker.RunCommand(realCmd, args, "")
	output = strings.TrimSpace(output)

	if !success || err != nil {
		if strings.Contains(cmd, "grep") || strings.Contains(cmd, "find") {
			if output == "" {
				return "Not Configured"
			}
		}
		if strings.Contains(cmd, "sysctl") {
			if output == "" {
				return "Key Missing in Kernel"
			}
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 && output == "" {
				return "Not Set"
			}
		}
	}

	if output == "" {
		return "Empty / Not Set"
	}
	if strings.Contains(strings.ToLower(output), "fail") {
		return "Vulnerable Config"
	}
	return output
}

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

func assessRule(worker platform.HardenerInterface, secManager *SecEditManager, r policy.Rule) (status, actual string) {
	switch r.Type {
	case "command", "file_check", "file_edit":
		passed, actualVal, err := worker.RunCommand(r.Check.Cmd, r.Check.Args, r.Check.ExpectPattern)
		if err != nil {
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

// RunAudit is the legacy (no-event) wrapper.
func RunAudit(pol *policy.Policy) []AuditResult {
	return RunAuditForPlatform(pol, "")
}

// RunAuditForPlatform runs a platform-filtered assessment, emitting structured
// events into the event bus so the live console can show real progress.
func RunAuditForPlatform(pol *policy.Policy, platformName string) []AuditResult {
	return RunAuditForPlatformWithJob(pol, platformName, "")
}

// RunAuditForPlatformWithJob is the event-producing version.
// jobID links all events to the live console stream.
func RunAuditForPlatformWithJob(pol *policy.Policy, platformName, jobID string) []AuditResult {
	var results []AuditResult
	var mutex sync.Mutex

	bus := events.GlobalBus
	emit := func(ev *events.Event) {
		if jobID != "" {
			bus.Emit(jobID, ev)
		}
	}

	emit(events.New(jobID, "", events.TypeAssessmentStarted, events.LevelInfo,
		fmt.Sprintf("Assessment started — platform: %s, policy rules: %d", platformName, len(pol.Rules)),
		map[string]any{"platform": platformName, "rule_count": len(pol.Rules)}))

	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	rulesToRun := pol.Rules
	if platformName != "" {
		rulesToRun = filterRulesForPlatform(pol.Rules, platformName)
	}

	emit(events.New(jobID, "", events.TypePolicyValidationCompleted, events.LevelInfo,
		fmt.Sprintf("Policy filtered: %d applicable controls for platform '%s'", len(rulesToRun), platformName),
		map[string]any{"applicable_count": len(rulesToRun)}))

	layers, err := dag.SortRules(rulesToRun)
	if err != nil {
		emit(events.New(jobID, "", events.TypeJobFailed, events.LevelError,
			fmt.Sprintf("Dependency cycle detected: %v", err), nil))
		return nil
	}

	for _, layer := range layers {
		var wg sync.WaitGroup
		for _, rule := range layer {
			wg.Add(1)
			go func(r policy.Rule) {
				defer wg.Done()
				start := time.Now()

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

				durMs := time.Since(start).Milliseconds()

				lvl := events.LevelInfo
				if finalRes.status == StatusFAIL {
					lvl = events.LevelWarn
				} else if finalRes.status == StatusERROR || finalRes.status == StatusTIMEOUT {
					lvl = events.LevelError
				} else if finalRes.status == StatusPASS {
					lvl = events.LevelSuccess
				}

				emit(&events.Event{
					EventID:    fmt.Sprintf("%s-%s-%d", jobID, r.ID, time.Now().UnixNano()),
					JobID:      jobID,
					ControlID:  r.ID,
					EventType:  events.TypeControlAssessmentCompleted,
					Level:      lvl,
					Status:     finalRes.status,
					Message:    fmt.Sprintf("[%s] Assessment completed for %s", finalRes.status, r.Name),
					DurationMs: durMs,
					Details: map[string]any{
						"control_id": r.ID,
						"severity":   r.Severity,
					},
				})

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

	pass, fail := 0, 0
	for _, r := range results {
		if r.Status == StatusPASS {
			pass++
		} else if r.Status == StatusFAIL {
			fail++
		}
	}
	emit(events.New(jobID, "", events.TypeJobCompleted, events.LevelSuccess,
		fmt.Sprintf("Assessment complete — PASS: %d, FAIL: %d, Total: %d", pass, fail, len(results)),
		map[string]any{"pass": pass, "fail": fail, "total": len(results)}))

	return results
}

// CapturedState holds a structured snapshot of a setting before mutation.
type CapturedState struct {
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	CaptureAt time.Time `json:"capture_at"`
	StateType string    `json:"state_type"`
	Value     string    `json:"value"`
	Digest    string    `json:"digest"`
}

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

	serialised, err := json.Marshal(cs)
	if err != nil {
		return nil, fmt.Errorf("state serialisation failed: %v", err)
	}

	newValue := deriveNewValueLabel(rule)
	if err := state.LogAction(rule.ID, rule.Name, string(serialised), newValue); err != nil {
		return nil, fmt.Errorf("state capture DB write failed: %v", err)
	}
	return cs, nil
}

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

// ApplyFixWithJob applies a remediation and emits events to the live console.
func ApplyFixWithJob(rule policy.Rule, jobID string) error {
	bus := events.GlobalBus
	emit := func(ev *events.Event) {
		if jobID != "" {
			bus.Emit(jobID, ev)
		}
	}

	worker := platform.GetPlatform()
	secManager := NewSecEditManager()
	if rule.Remediation.Type == "manual" {
		emit(events.New(jobID, rule.ID, events.TypeJobBlocked, events.LevelWarn,
			"Manual action required — automated execution is blocked for this control", nil))
		return fmt.Errorf("manual action required")
	}

	// 1. State capture — mandatory before mutation.
	emit(events.New(jobID, rule.ID, events.TypeStateCaptureStarted, events.LevelInfo,
		fmt.Sprintf("Capturing pre-change state for %s", rule.ID), nil))

	cs, err := captureState(worker, rule)
	if err != nil {
		emit(events.New(jobID, rule.ID, events.TypeJobFailed, events.LevelError,
			fmt.Sprintf("State capture failed — mutation aborted: %v", err), nil))
		return fmt.Errorf("state capture failed, mutation aborted: %v", err)
	}

	emit(&events.Event{
		JobID:     jobID,
		ControlID: rule.ID,
		EventType: events.TypeStateCaptureCompleted,
		Level:     events.LevelInfo,
		Message:   fmt.Sprintf("Pre-change state captured (digest: %s…)", cs.Digest[:12]),
		Details:   map[string]any{"digest": cs.Digest, "state_type": cs.StateType},
	})

	// 2. Execute remediation.
	emit(events.New(jobID, rule.ID, events.TypeActionStarted, events.LevelInfo,
		fmt.Sprintf("Executing remediation: type=%s", rule.Remediation.Type),
		map[string]any{"remediation_type": rule.Remediation.Type}))

	operationEvent := events.TypeActionCompleted
	if rule.Remediation.Type == "command" {
		operationEvent = events.TypeCommandCompleted
		emit(events.New(jobID, rule.ID, events.TypeCommandStarted, events.LevelInfo,
			"Starting allowlisted operation for control "+rule.ID,
			map[string]any{"operation_type": rule.Remediation.Type}))
	}

	start := time.Now()
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
		return fmt.Errorf("manual action required")
	default:
		emit(events.New(jobID, rule.ID, events.TypeJobBlocked, events.LevelWarn,
			"Unsupported remediation type — no operation was executed", map[string]any{"remediation_type": rule.Remediation.Type}))
		return fmt.Errorf("unknown remediation type: %s", rule.Remediation.Type)
	}

	durMs := time.Since(start).Milliseconds()

	if err != nil {
		emit(&events.Event{
			JobID:      jobID,
			ControlID:  rule.ID,
			EventType:  operationEvent,
			Level:      events.LevelError,
			Status:     "FAILED",
			Message:    fmt.Sprintf("Remediation command failed: %v", err),
			DurationMs: durMs,
		})
		emit(events.New(jobID, rule.ID, events.TypeJobFailed, events.LevelError,
			fmt.Sprintf("Fix failed for %s: %v", rule.ID, err), nil))
		return fmt.Errorf("fix failed: %v", err)
	}

	emit(&events.Event{
		JobID:      jobID,
		ControlID:  rule.ID,
		EventType:  operationEvent,
		Level:      events.LevelInfo,
		Status:     "OK",
		Message:    "Operation completed — checking resulting state",
		DurationMs: durMs,
	})

	// 3. Verification — re-read actual state.
	emit(events.New(jobID, rule.ID, events.TypeVerificationStarted, events.LevelInfo,
		"Reading effective target configuration to verify outcome", nil))

	verifyStart := time.Now()
	vStatus, _ := assessRule(worker, secManager, rule)
	vDurMs := time.Since(verifyStart).Milliseconds()

	if vStatus == StatusPASS {
		emit(&events.Event{
			JobID:      jobID,
			ControlID:  rule.ID,
			EventType:  events.TypeVerificationCompleted,
			Level:      events.LevelSuccess,
			Status:     "VERIFIED",
			Message:    "Expected state confirmed by verification logic",
			DurationMs: vDurMs,
		})
		emit(events.New(jobID, rule.ID, events.TypeJobCompleted, events.LevelSuccess,
			fmt.Sprintf("Remediation verified successfully for %s", rule.ID),
			map[string]any{"control_id": rule.ID, "verification_status": "VERIFIED"}))
	} else {
		emit(&events.Event{
			JobID:      jobID,
			ControlID:  rule.ID,
			EventType:  events.TypeVerificationCompleted,
			Level:      events.LevelWarn,
			Status:     vStatus,
			Message:    fmt.Sprintf("Verification did not confirm the expected state — status: %s", vStatus),
			DurationMs: vDurMs,
		})
		emit(events.New(jobID, rule.ID, events.TypeJobFailed, events.LevelError,
			fmt.Sprintf("Remediation could not be verified — status: %s", vStatus),
			map[string]any{"verification_status": vStatus}))
		return fmt.Errorf("remediation was not verified (status: %s)", vStatus)
	}

	return nil
}

// ApplyFix applies remediation without a job ID (legacy path).
func ApplyFix(rule policy.Rule) error {
	return ApplyFixWithJob(rule, "")
}

func RevertFix(rule policy.Rule) error {
	worker := platform.GetPlatform()
	secManager := NewSecEditManager()

	rawCapture, dbErr := state.GetRollbackData(rule.ID)
	if dbErr == nil && rawCapture != "" {
		var cs CapturedState
		if jsonErr := json.Unmarshal([]byte(rawCapture), &cs); jsonErr == nil {
			if cs.StateType == "raw_value" && rule.Rollback.Type == "file_edit" {
				return worker.EditConfigFile(rule.Rollback.FilePath, rule.Rollback.SearchRegex, cs.Value)
			}
		}
	}

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

// RevertFixWithJob records the recovery attempt while preserving the legacy
// rollback implementation. The current rollback path has no independent
// post-recovery check, so success is explicitly marked unverified.
func RevertFixWithJob(rule policy.Rule, jobID string) error {
	emit := func(ev *events.Event) {
		if jobID != "" {
			events.GlobalBus.Emit(jobID, ev)
		}
	}
	emit(events.New(jobID, rule.ID, events.TypeRecoveryStarted, events.LevelInfo,
		"Starting rollback operation for control "+rule.ID, nil))
	err := RevertFix(rule)
	if err != nil {
		emit(&events.Event{JobID: jobID, ControlID: rule.ID, EventType: events.TypeRecoveryCompleted,
			Level: events.LevelError, Status: "FAILED", Message: "Rollback operation failed", ErrorCode: "RECOVERY_FAILED"})
		emit(events.New(jobID, rule.ID, events.TypeJobFailed, events.LevelError, "Recovery failed", nil))
		return err
	}
	emit(&events.Event{JobID: jobID, ControlID: rule.ID, EventType: events.TypeRecoveryCompleted,
		Level: events.LevelWarn, Status: "APPLIED_UNVERIFIED",
		Message: "Rollback operation returned successfully; restored state was not independently verified"})
	emit(&events.Event{JobID: jobID, ControlID: rule.ID, EventType: events.TypeJobCompleted,
		Level: events.LevelWarn, Status: "APPLIED_UNVERIFIED",
		Message: "Recovery operation completed; restored state remains unverified"})
	return nil
}

func RevertAll(pol *policy.Policy) (string, error) {
	revertedCount := 0
	errorCount := 0
	for _, rule := range pol.Rules {
		err := RevertFix(rule)
		if err != nil {
			errorCount++
		} else {
			revertedCount++
		}
	}
	return fmt.Sprintf("Reset Complete. Reverted %d rules. Errors: %d", revertedCount, errorCount), nil
}
