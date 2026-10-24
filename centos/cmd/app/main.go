package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"sih2025/internal/engine"
	"sih2025/internal/platform"
	"sih2025/internal/policy"
	"sih2025/internal/report"
	"sih2025/internal/state"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

// detectedOS holds the result of DetectOS() called once at startup.
// On non-Linux builds this is a zero-value struct.
var detectedOS platform.OSInfo

func main() {
	// --- OS Detection ---
	if runtime.GOOS == "linux" {
		detectedOS = platform.DetectOS()
		fmt.Println("==================================================")
		fmt.Printf("   SIH 2025 HARDENING ORCHESTRATOR (v2.1)\n")
		fmt.Printf("   DETECTED OS : %s\n", detectedOS.Name)
		fmt.Printf("   VERSION ID  : %s\n", detectedOS.VersionID)
		fmt.Printf("   ARCH        : %s\n", detectedOS.Arch)
		fmt.Printf("   KERNEL      : %s\n", detectedOS.KernelVersion)
		fmt.Printf("   HOSTNAME    : %s\n", detectedOS.Hostname)
		fmt.Printf("   SUPPORT     : %s — %s\n", detectedOS.SupportStatus, detectedOS.SupportDetail)
		fmt.Println("==================================================")

		if detectedOS.SupportStatus == "UNSUPPORTED" {
			fmt.Printf("[WARN] This distribution (%s %s) is not a supported CentOS target.\n",
				detectedOS.ID, detectedOS.VersionID)
			fmt.Println("[WARN] Scans will still run but results may be inaccurate.")
		}
	} else {
		fmt.Println("==================================================")
		fmt.Printf("   SIH 2025 HARDENING ORCHESTRATOR (v2.1)\n")
		fmt.Printf("   DETECTED OS: %s\n", strings.ToUpper(runtime.GOOS))
		fmt.Println("==================================================")
	}

	initDB()
	startServer()
}

func initDB() {
	state.InitDB()
	fmt.Println("[SUCCESS] State Manager Ready (Rollback Enabled)")
}

// currentPlatformName returns the lowercase platform name for use in policy filtering.
// On Linux it is the detected distro ID (e.g. "centos").
// On Windows it is "windows".
func currentPlatformName() string {
	if runtime.GOOS == "linux" {
		if detectedOS.ID != "" {
			return detectedOS.ID // "centos", "ubuntu", etc.
		}
		return "linux"
	}
	return "windows"
}

func startServer() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.LoadHTMLGlob("ui/templates/*")
	r.Static("/static", "./ui/static")

	r.GET("/", func(c *gin.Context) { c.HTML(200, "index.html", nil) })

	api := r.Group("/api")
	{
		// 1. STATUS — now includes full OS info
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
				})
			} else {
				c.JSON(200, gin.H{
					"status":         "online",
					"os":             runtime.GOOS,
					"support_status": "SUPPORTED",
				})
			}
		})

		// 2. DISCOVERY — dedicated endpoint for full target profile
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

		// 3. SCAN — now uses platform-aware RunAuditForPlatform
		api.GET("/scan", func(c *gin.Context) {
			profile := c.DefaultQuery("level", "strict")
			fmt.Printf("[API] Scanning with Profile: %s\n", profile)

			pol := loadCurrentPolicy()
			if pol == nil {
				c.JSON(500, gin.H{"error": "Failed to load policy"})
				return
			}

			// Filter by severity profile.
			filteredRules := filterBySeverity(pol.Rules, profile)
			pol.Rules = filteredRules

			// Run platform-filtered audit.
			results := engine.RunAuditForPlatform(pol, currentPlatformName())
			c.JSON(200, gin.H{"results": results})
		})

		// 4. FIX
		api.POST("/fix", func(c *gin.Context) {
			var req struct {
				ID string `json:"id"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			pol := loadCurrentPolicy()
			for _, rule := range pol.Rules {
				if rule.ID == req.ID {
					// Only allow fixing rules that apply to this platform.
					rp := strings.ToLower(rule.Platform)
					cp := currentPlatformName()
					if rp != "" && rp != cp {
						c.JSON(400, gin.H{"error": fmt.Sprintf(
							"rule %s is for platform '%s', current platform is '%s'",
							req.ID, rule.Platform, cp)})
						return
					}

					if err := engine.ApplyFix(rule); err != nil {
						c.JSON(500, gin.H{"error": err.Error()})
						return
					}
					c.JSON(200, gin.H{"status": "fixed", "id": req.ID})
					return
				}
			}
			c.JSON(404, gin.H{"error": "Rule not found"})
		})

		// 5. ROLLBACK
		api.POST("/rollback", func(c *gin.Context) {
			var req struct {
				ID string `json:"id"`
			}
			if err := c.BindJSON(&req); err != nil {
				c.JSON(400, gin.H{"error": "Invalid request"})
				return
			}

			pol := loadCurrentPolicy()
			for _, rule := range pol.Rules {
				if rule.ID == req.ID {
					if err := engine.RevertFix(rule); err != nil {
						c.JSON(500, gin.H{"error": err.Error()})
						return
					}
					c.JSON(200, gin.H{"status": "rolled_back", "id": req.ID})
					return
				}
			}
			c.JSON(404, gin.H{"error": "Rule not found"})
		})

		// 6. EXPORT REPORT
		api.GET("/export", func(c *gin.Context) {
			profile := c.DefaultQuery("level", "strict")
			pol := loadCurrentPolicy()

			filteredRules := filterBySeverity(pol.Rules, profile)
			pol.Rules = filteredRules

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

		// 7. MASTER RESET
		api.POST("/reset", func(c *gin.Context) {
			pol := loadCurrentPolicy()
			summary, _ := engine.RevertAll(pol)
			c.JSON(200, gin.H{
				"status":  "reset_complete",
				"message": summary,
			})
		})
	}

	fmt.Println("\n[UI] Dashboard available at http://localhost:8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

// filterBySeverity returns rules matching the selected profile severity levels.
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

// loadCurrentPolicy loads the CentOS policy on Linux and the Windows policy on Windows.
// It selects the correct per-platform policy file rather than relying on distro detection
// within policy loading (policy files must already be platform-specific).
func loadCurrentPolicy() *policy.Policy {
	var filePath string

	if runtime.GOOS == "windows" {
		filePath = "policies/annexure_a.json"
	} else {
		// On Linux: prefer the dedicated CentOS policy, fall back to annexure_b.
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
