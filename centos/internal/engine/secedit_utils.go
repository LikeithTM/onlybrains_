//go:build windows

package engine

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type SecEditManager struct {
	ExportPath string
	ImportPath string
	DbPath     string
}

func NewSecEditManager() *SecEditManager {
	return &SecEditManager{
		ExportPath: "temp_export.inf",
		ImportPath: "temp_import.inf",
		DbPath:     "temp_secedit.sdb", // We use a temp DB to avoid corrupting the real one
	}
}

// CheckUserRight verifies if a specific user right is set correctly.
func (s *SecEditManager) CheckUserRight(rightName string, expectedUsers string) (bool, error) {
	// 1. Export current security policy
	cmd := exec.Command("secedit", "/export", "/cfg", s.ExportPath, "/areas", "USER_RIGHTS")
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("secedit export failed: %v", err)
	}
	defer os.Remove(s.ExportPath)

	// 2. Read and Parse
	data, err := os.ReadFile(s.ExportPath)
	if err != nil {
		return false, err
	}
	
	content := string(data)
	lines := strings.Split(content, "\n")
	currentVal := ""
	
	for _, line := range lines {
		// Clean the line (handle different encodings/whitespace)
		line = strings.TrimSpace(line)
		if strings.Contains(line, rightName) && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				currentVal = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	// 3. Logic Check
	// If expected is "No One" (empty), and we found nothing or empty string -> PASS
	if (expectedUsers == "No One" || expectedUsers == "") && (currentVal == "" || currentVal == "failed") {
		return true, nil
	}
	
	// Check if our expected users are present
	// We do a simple contains check for the Hackathon
	if strings.Contains(currentVal, expectedUsers) {
		return true, nil
	}

	return false, nil
}

// SetUserRight automates the complex process of creating an INF and applying it
func (s *SecEditManager) SetUserRight(rightName string, users string) error {
	// 1. Handle "No One" case (Clear the right)
	valToWrite := users
	if users == "No One" {
		valToWrite = "" 
	}

	// 2. Create the INF content
	// This format is strict Windows Security Template format
	infContent := fmt.Sprintf(`
[Unicode]
Unicode=yes
[Privilege Rights]
%s = %s
[Version]
signature="$CHICAGO$"
Revision=1
`, rightName, valToWrite)

	// 3. Write INF file
	if err := os.WriteFile(s.ImportPath, []byte(infContent), 0644); err != nil {
		return fmt.Errorf("failed to write temp INF: %v", err)
	}
	defer os.Remove(s.ImportPath)
	defer os.Remove(s.DbPath) // Clean up the temp database

	// 4. Apply using secedit /configure
	// /db is required, so we generate a temp one
	cmd := exec.Command("secedit", "/configure", "/db", s.DbPath, "/cfg", s.ImportPath, "/areas", "USER_RIGHTS")
	
	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("secedit configure failed: %s", string(output))
	}

	return nil
}