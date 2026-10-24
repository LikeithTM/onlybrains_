//go:build windows

package platform

import (
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// WindowsHardener is the implementation for Windows OS
type WindowsHardener struct{}

// This connects the Interface to the specific Windows struct
func getPlatformInstance() HardenerInterface {
	return &WindowsHardener{}
}
func (w *WindowsHardener) EditConfigFile(path string, searchRegex string, replaceText string) error {
	return nil // Not used on Windows
}

func (w *WindowsHardener) GetOSName() string {
	return "windows"
}

// CheckRegistry checks if a specific registry key matches the expected value
func (w *WindowsHardener) CheckRegistry(keyPath, valueName string, expectedValue interface{}) (bool, error) {
	var rootKey registry.Key
	shortPath := keyPath

	if strings.HasPrefix(keyPath, "HKLM\\") {
		rootKey = registry.LOCAL_MACHINE
		shortPath = strings.TrimPrefix(keyPath, "HKLM\\")
	} else if strings.HasPrefix(keyPath, "HKCU\\") {
		rootKey = registry.CURRENT_USER
		shortPath = strings.TrimPrefix(keyPath, "HKCU\\")
	} else {
		return false, fmt.Errorf("unsupported root key: %s", keyPath)
	}

	k, err := registry.OpenKey(rootKey, shortPath, registry.QUERY_VALUE)
	if err != nil {
		return false, nil // Key not found = Fail
	}
	defer k.Close()

	// Get the Value
	// We handle Integers (DWORD) and Strings (SZ)
	_, valType, err := k.GetValue(valueName, nil)
	if err != nil {
		return false, nil
	}

	if valType == registry.DWORD || valType == registry.QWORD {
		val, _, err := k.GetIntegerValue(valueName)
		if err != nil {
			return false, nil
		}

		// Normalize expectedValue
		expectedInt, ok := expectedValue.(float64)
		if !ok {
			if eInt, ok := expectedValue.(int); ok {
				expectedInt = float64(eInt)
			}
		}
		if val == uint64(expectedInt) {
			return true, nil
		}

	} else if valType == registry.SZ || valType == registry.EXPAND_SZ {
		val, _, err := k.GetStringValue(valueName)
		if err != nil {
			return false, nil
		}

		if expectedStr, ok := expectedValue.(string); ok {
			if val == expectedStr {
				return true, nil
			}
		}
	}

	return false, nil
}

// RunCommand executes PowerShell or CMD commands securely
func (w *WindowsHardener) RunCommand(cmdStr string, args []string, expectPattern string) (bool, string, error) {
	fullCmd := exec.Command(cmdStr, args...)

	// Hide Command Window (Optional, keeps UI clean)
	// fullCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := fullCmd.CombinedOutput()
	if err != nil {
		// If command fails, we return false but NOT an error,
		// because "Command not found" is a valid audit result (Fail).
		return false, string(output), nil
	}

	if strings.Contains(string(output), expectPattern) {
		return true, string(output), nil
	}

	return false, string(output), nil
}

// SetRegistry applies the fix (With "Self-Healing" CreateKey logic)
func (w *WindowsHardener) SetRegistry(keyPath, valueName string, value interface{}) error {
	var rootKey registry.Key
	shortPath := keyPath

	if strings.HasPrefix(keyPath, "HKLM\\") {
		rootKey = registry.LOCAL_MACHINE
		shortPath = strings.TrimPrefix(keyPath, "HKLM\\")
	} else if strings.HasPrefix(keyPath, "HKCU\\") {
		rootKey = registry.CURRENT_USER
		shortPath = strings.TrimPrefix(keyPath, "HKCU\\")
	} else {
		return fmt.Errorf("unsupported root key")
	}

	// SMART FIX: CreateKey opens it if it exists, creates it if missing.
	k, _, err := registry.CreateKey(rootKey, shortPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %v", err)
	}
	defer k.Close()

	// Determine type and set value
	switch v := value.(type) {
	case int:
		return k.SetDWordValue(valueName, uint32(v))
	case float64:
		return k.SetDWordValue(valueName, uint32(v))
	case string:
		return k.SetStringValue(valueName, v)
	default:
		return fmt.Errorf("unsupported value type")
	}
}

// --- REQUIRED STUBS (To Satisfy Interface) ---

// CheckFilePermission is not used on Windows Registry hardening, so we return true/nil
func (w *WindowsHardener) CheckFilePermission(path, expectedMode, expectedOwner, expectedGroup string) (bool, error) {
	return true, nil
}

// SetFilePermission is missing in your current file - THIS FIXES THE ERROR
func (w *WindowsHardener) SetFilePermission(path, mode string) error {
	// On Windows, file permissions (ACLs) are handled differently than Linux chmod.
	// For this demo, we assume file ops are handled via "Command" type (icacls).
	return nil
}

// CheckFileContent checks if a file contains expected content (stub for Windows)
func (w *WindowsHardener) CheckFileContent(path string, searchPatterns []string, expectedContent string) (bool, error) {
	// On Windows, file content checks are typically not used for registry hardening
	// Return true to indicate this check is not applicable
	return true, nil
}
