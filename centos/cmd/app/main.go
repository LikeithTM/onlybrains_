package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"sih2025/internal/engine"
	"sih2025/internal/events"
	"sih2025/internal/platform"
	"sih2025/internal/policy"
	"sih2025/internal/report"
	"sih2025/internal/state"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

var detectedOS platform.OSInfo
var jobCounter atomic.Uint64

func main() {
	if runtime.GOOS == "linux" {
		detectedOS = platform.DetectOS()
		fmt.Println("==================================================")
		fmt.Printf("   SENTINELX HARDENING ORCHESTRATOR (v3.0)\n")
		fmt.Printf("   DETECTED OS : %s\n", detectedOS.Name)
		fmt.Printf("   VERSION ID  : %s\n", detectedOS.VersionID)
		fmt.Printf("   ARCH        : %s\n", detectedOS.Arch)
		fmt.Printf("   KERNEL      : %s\n", detectedOS.KernelVersion)
		fmt.Printf("   HOSTNAME    : %s\n", detectedOS.Hostname)
		fmt.Printf("   SUPPORT     : %s — %s\n", detectedOS.SupportStatus, detectedOS.SupportDetail)
		fmt.Println("==================================================")

		if detectedOS.SupportStatus == "UNSUPPORTED" {
			fmt.Printf("[WARN] Distribution (%s %s) is not a supported CentOS target.\n",
				detectedOS.ID, detectedOS.VersionID)
		}
	} else {
		fmt.Println("==================================================")
		fmt.Printf("   SENTINELX HARDENING ORCHESTRATOR (v3.0)\n")
		fmt.Printf("   DETECTED OS: %s\n", strings.ToUpper(runtime.GOOS))
		fmt.Println("==================================================")
	}

	state.InitDB()
	bus, err := events.NewPersistentBus(state.DB)
	if err != nil {
		log.Fatalf("initialize event store: %v", err)
	}
	events.GlobalBus = bus
	fmt.Println("[SUCCESS] State Manager Ready (Rollback Enabled)")
	startServer()
}

func currentPlatformName() string {
	if runtime.GOOS == "linux" {
		if detectedOS.ID != "" {
			return detectedOS.ID
		}
		return "linux"
	}
	return "windows"
}

// newJobID generates a short time-based job ID for event correlation.
func newJobID() string {
	return fmt.Sprintf("job-%d-%d", time.Now().UnixMilli(), jobCounter.Add(1))
}

func validJobID(jobID string) bool {
	return len(jobID) > 0 && len(jobID) <= 80 && strings.Trim(jobID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == ""
}

func startServer() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.LoadHTMLGlob("ui/templates/*")
	r.Static("/static", "./ui/static")

	r.GET("/", func(c *gin.Context) { c.HTML(200, "index.html", nil) })

	api := r.Group("/api")
	{
		// STATUS
		api.GET("/status", func(c *gin.Context) {
			if runtime.GOOS == "linux" {
				c.JSON(200, gin.H{
					"status":         "online",
					"os":             detectedOS.Name,
					"os_id":          detectedOS.ID,
					"version_id":     detectedOS.VersionID,
					"arch":           detectedOS.Arch,
					"kernel":         detectedOS.KernelVersion,
					"hostname":       detectedOS.Hostname,
					"support_status": detectedOS.SupportStatus,
					"support_detail": detectedOS.SupportDetail,
					"version":        "3.0",
				})
			} else {
				h, _ := os.Hostname()
				c.JSON(200, gin.H{
					"status":         "online",
					"os":             runtime.GOOS,
					"hostname":       h,
					"arch":           runtime.GOARCH,
					"support_status": "SUPPORTED",
					"version":        "3.0",
				})
			}
		})

		// DISCOVERY
		api.GET("/discovery", func(c *gin.Context) {
			if runtime.GOOS == "linux" {
				c.JSON(200, gin.H{
					"target_platform": detectedOS.ID,
					"os_name":         detectedOS.Name,
					"version_id":      detectedOS.VersionID,
					"id_like":         detectedOS.IDLike,
					"arch":            detectedOS.Arch,
					"kernel":          detectedOS.KernelVersion,
					"hostname":        detectedOS.Hostname,
					"support_status":  detectedOS.SupportStatus,
					"support_detail":  detectedOS.SupportDetail,
				})
			} else {
				h, _ := os.Hostname()
				c.JSON(200, gin.H{
					"target_platform": "windows",
					"os_name":         "Windows",
					"arch":            runtime.GOARCH,
					"hostname":        h,
					"support_status":  "SUPPORTED",
				})
			}
		})

		// SCAN — now emits real events into the bus.
		// Returns job_id so the browser can subscribe to the SSE stream.
		api.GET("/scan", func(c *gin.Context) {
			profile := c.DefaultQuery("level", "strict")
			jobID := c.Query("job_id")
			if jobID == "" {
				jobID = newJobID()
			}
			if !validJobID(jobID) {
				c.JSON(400, gin.H{"error": "invalid job_id"})
				return
			}
			if len(events.GlobalBus.History(jobID)) > 0 {
				c.JSON(409, gin.H{"error": "job_id already exists"})
				return
			}

			pol := loadCurrentPolicy()
			if pol == nil {
				events.GlobalBus.Emit(jobID, events.New(jobID, "", events.TypeJobFailed, events.LevelError, "Policy could not be loaded", nil))
				c.JSON(500, gin.H{"error": "Failed to load policy"})
				return
			}

			// Emit job accepted immediately so the browser can open SSE before we start.
			events.GlobalBus.Emit(jobID, events.New(jobID, "", events.TypeJobAccepted, events.LevelInfo,
				fmt.Sprintf("Assessment job accepted — profile: %s, platform: %s", profile, currentPlatformName()),
				map[string]any{"profile": profile, "platform": currentPlatformName()}))

			events.GlobalBus.Emit(jobID, events.New(jobID, "", events.TypeTargetDiscoveryStarted, events.LevelInfo,
				"Detecting target operating system and architecture", nil))
			// Emit discovery result based on the detected host.
			osLabel := runtime.GOOS
			if runtime.GOOS == "linux" {
				osLabel = fmt.Sprintf("%s %s / %s", detectedOS.Name, detectedOS.VersionID, detectedOS.Arch)
			}
			events.GlobalBus.Emit(jobID, events.New(jobID, "", events.TypeTargetDiscoveryCompleted, events.LevelInfo,
				fmt.Sprintf("Target: %s", osLabel),
				map[string]any{"os": osLabel, "platform": currentPlatformName()}))

			pol.Rules = filterBySeverity(pol.Rules, profile)
			results := engine.RunAuditForPlatformWithJob(pol, currentPlatformName(), jobID)
			if err := events.GlobalBus.TakeError(jobID); err != nil {
				c.JSON(500, gin.H{"error": "assessment completed but event history could not be persisted", "job_id": jobID})
				return
			}

			c.JSON(200, gin.H{
				"job_id":  jobID,
				"results": results,
			})
		})

		// FIX — emits real events through the live console.
		api.POST("/fix", func(c *gin.Context) {
			var req struct {
				ID    string `json:"id"`
				JobID string `json:"job_id,omitempty"` // optional: caller can pass job_id for live console
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			jobID := req.JobID
			if jobID == "" {
				jobID = newJobID()
			}
			if !validJobID(jobID) || len(events.GlobalBus.History(jobID)) > 0 {
				c.JSON(409, gin.H{"error": "invalid or already used job_id"})
				return
			}
			pol := loadCurrentPolicy()
			if pol == nil {
				events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobFailed, events.LevelError, "Policy could not be loaded", nil))
				c.JSON(500, gin.H{"error": "Failed to load policy", "job_id": jobID})
				return
			}
			for _, rule := range pol.Rules {
				if rule.ID == req.ID {
					rp := strings.ToLower(rule.Platform)
					cp := currentPlatformName()
					if rp != "" && rp != cp {
						events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobBlocked, events.LevelWarn,
							"Control does not apply to the current platform", map[string]any{"platform": cp}))
						c.JSON(400, gin.H{"error": fmt.Sprintf(
							"rule %s is for platform '%s', current platform is '%s'",
							req.ID, rule.Platform, cp)})
						return
					}

					events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobAccepted, events.LevelInfo,
						"Remediation job accepted", map[string]any{"control_id": req.ID}))
					fixErr := engine.ApplyFixWithJob(rule, jobID)
					if eventErr := events.GlobalBus.TakeError(jobID); eventErr != nil {
						c.JSON(500, gin.H{"error": "operation outcome could not be durably recorded", "job_id": jobID})
						return
					}
					if fixErr != nil {
						c.JSON(500, gin.H{"error": fixErr.Error(), "job_id": jobID})
						return
					}
					c.JSON(200, gin.H{"status": "fixed", "id": req.ID, "job_id": jobID})
					return
				}
			}
			events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobFailed, events.LevelError, "Control was not found", nil))
			c.JSON(404, gin.H{"error": "Rule not found"})
		})

		// ROLLBACK
		api.POST("/rollback", func(c *gin.Context) {
			var req struct {
				ID    string `json:"id"`
				JobID string `json:"job_id,omitempty"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			jobID := req.JobID
			if jobID == "" {
				jobID = newJobID()
			}
			if !validJobID(jobID) || len(events.GlobalBus.History(jobID)) > 0 {
				c.JSON(409, gin.H{"error": "invalid or already used job_id"})
				return
			}
			pol := loadCurrentPolicy()
			if pol == nil {
				events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobFailed, events.LevelError, "Policy could not be loaded", nil))
				c.JSON(500, gin.H{"error": "Failed to load policy", "job_id": jobID})
				return
			}
			for _, rule := range pol.Rules {
				if rule.ID == req.ID {
					events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobAccepted, events.LevelInfo,
						"Recovery job accepted", map[string]any{"control_id": req.ID}))
					if err := engine.RevertFixWithJob(rule, jobID); err != nil {
						c.JSON(500, gin.H{"error": err.Error(), "job_id": jobID})
						return
					}
					if eventErr := events.GlobalBus.TakeError(jobID); eventErr != nil {
						c.JSON(500, gin.H{"error": "recovery outcome could not be durably recorded", "job_id": jobID})
						return
					}
					c.JSON(200, gin.H{"status": "rollback_applied_unverified", "id": req.ID, "job_id": jobID})
					return
				}
			}
			events.GlobalBus.Emit(jobID, events.New(jobID, req.ID, events.TypeJobFailed, events.LevelError, "Control was not found", nil))
			c.JSON(404, gin.H{"error": "Rule not found"})
		})

		// EXPORT PDF REPORT
		api.GET("/export", func(c *gin.Context) {
			profile := c.DefaultQuery("level", "strict")
			pol := loadCurrentPolicy()
			pol.Rules = filterBySeverity(pol.Rules, profile)
			results := engine.RunAuditForPlatform(pol, currentPlatformName())

			hostname, _ := os.Hostname()
			osLabel := runtime.GOOS
			if runtime.GOOS == "linux" {
				osLabel = detectedOS.Name
			}
			targetLabel := fmt.Sprintf("%s SERVER (%s)", strings.ToUpper(osLabel), hostname)

			filename, err := report.GenerateReport(results, targetLabel)
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to generate PDF"})
				return
			}
			c.Header("Content-Disposition", "attachment; filename="+filename)
			c.Header("Content-Type", "application/pdf")
			c.File(filename)
		})

		// MASTER RESET
		api.POST("/reset", func(c *gin.Context) {
			pol := loadCurrentPolicy()
			summary, _ := engine.RevertAll(pol)
			c.JSON(200, gin.H{"status": "reset_complete", "message": summary})
		})

		// SSE EVENT STREAM — GET /api/events/stream?job=<job_id>
		// The browser opens this after starting a scan or fix to get live events.
		api.GET("/events/stream", func(c *gin.Context) {
			events.SSEHandler(c.Writer, c.Request)
		})

		// EVENT HISTORY — GET /api/events/history?job=<job_id>
		// Returns all stored events for a completed or running job.
		api.GET("/events/history", func(c *gin.Context) {
			jobID := c.Query("job")
			if jobID == "" {
				c.JSON(400, gin.H{"error": "job parameter required"})
				return
			}
			after, parseErr := strconv.ParseInt(c.DefaultQuery("after", "0"), 10, 64)
			if parseErr != nil || after < 0 {
				c.JSON(400, gin.H{"error": "after must be a non-negative sequence number"})
				return
			}
			limit, _ := strconv.Atoi(c.DefaultQuery("limit", "200"))
			history, err := events.GlobalBus.HistoryAfter(jobID, after, limit)
			if err != nil {
				c.JSON(500, gin.H{"error": "event history unavailable"})
				return
			}
			next := after
			if len(history) > 0 {
				next = history[len(history)-1].SeqNum
			}
			c.JSON(200, gin.H{"job_id": jobID, "events": history, "count": len(history), "next_after": next})
		})
	}

	// Legacy: serve SSEHandler directly at /events/stream for compatibility.
	r.GET("/events/stream", func(c *gin.Context) {
		http.HandlerFunc(events.SSEHandler).ServeHTTP(c.Writer, c.Request)
	})

	fmt.Println("\n[UI] Dashboard → http://localhost:8080")
	if err := r.Run("127.0.0.1:8080"); err != nil {
		log.Fatal(err)
	}
}

func filterBySeverity(rules []policy.Rule, profile string) []policy.Rule {
	var out []policy.Rule
	for _, rule := range rules {
		switch profile {
		case "strict":
			out = append(out, rule)
		case "moderate":
			if rule.Severity == "Critical" || rule.Severity == "High" || rule.Severity == "Medium" {
				out = append(out, rule)
			}
		case "basic":
			if rule.Severity == "Critical" || rule.Severity == "High" {
				out = append(out, rule)
			}
		}
	}
	return out
}

func loadCurrentPolicy() *policy.Policy {
	var filePath string
	if runtime.GOOS == "windows" {
		filePath = "policies/annexure_a.json"
	} else {
		if _, err := os.Stat("policies/centos_hardening.json"); err == nil {
			filePath = "policies/centos_hardening.json"
		} else if _, err := os.Stat("policies/annexure_b.json"); err == nil {
			filePath = "policies/annexure_b.json"
		} else {
			log.Printf("[ERROR] No policy file found")
			return nil
		}
	}

	pol, err := policy.LoadPolicy(filePath)
	if err != nil {
		log.Printf("[ERROR] Failed to load policy %s: %v", filePath, err)
		return nil
	}
	return pol
}
