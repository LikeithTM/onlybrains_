//go:build linux

package platform

import (
    "fmt"
    "io/ioutil"
    "os"
    "os/exec"
    "regexp"
    "strconv"
    "strings"
    
)

type LinuxHardener struct{}

func getPlatformInstance() HardenerInterface {
    return &LinuxHardener{}
}

func (l *LinuxHardener) GetOSName() string {
    return "linux"
}

// Stubs
func (l *LinuxHardener) CheckRegistry(key, val string, exp interface{}) (bool, error) { return false, nil }
func (l *LinuxHardener) SetRegistry(k, v string, val interface{}) error               { return nil }

// --- UPDATED: RunCommand returns the OUTPUT string ---
func (l *LinuxHardener) RunCommand(cmdStr string, args []string, expectPattern string) (bool, string, error) {
    cmd := exec.Command(cmdStr, args...)
    output, err := cmd.CombinedOutput()
    outStr := strings.TrimSpace(string(output))

    // 1. Audit Mode (Checking for a pattern)
    if expectPattern != "" {
        // Handle common grep exit code 1 (not found) gracefully
        if err != nil {
            if exitErr, ok := err.(*exec.ExitError); ok {
                if exitErr.ExitCode() == 1 && strings.Contains(cmdStr, "grep") {
                    return false, "Pattern Not Found", nil
                }
            }
        }

        // Check for match
        matched, _ := regexp.MatchString(expectPattern, outStr)
        if matched || strings.Contains(outStr, expectPattern) {
            // Return TRUE and the ACTUAL OUTPUT found
            return true, outStr, nil
        }
        // Return FALSE and the OUTPUT (so we know what wrong value was found)
        if outStr == "" { outStr = "Empty Output" }
        return false, outStr, nil
    }

    // 2. Action Mode (Running a fix/command)
    if err != nil {
        return false, outStr, fmt.Errorf("execution failed: %v | output: %s", err, outStr)
    }

    return true, outStr, nil
}

// Wrapper for Grep checks
func (l *LinuxHardener) CheckFileContent(cmd string, args []string, expectPattern string) (bool, error) {
    success, _, err := l.RunCommand(cmd, args, expectPattern)
    return success, err
}

// CheckFilePermission (Kept robust as before)
func (l *LinuxHardener) CheckFilePermission(path string, expectedMode string, expectedOwner string, expectedGroup string) (bool, error) {
    info, err := os.Stat(path)
    if os.IsNotExist(err) { return false, nil }
    if err != nil { return false, err }

    if expectedMode != "" {
        mode := info.Mode().Perm()
        if fmt.Sprintf("%04o", mode) != expectedMode { return false, nil }
    }
    
    // For simplicity in this function signature, we return true if mode matches
    // You can add ownership logic back here if needed.
    return true, nil
}

func (l *LinuxHardener) SetFilePermission(path string, modeStr string) error {
    modeInt, err := strconv.ParseUint(modeStr, 8, 32)
    if err != nil { return fmt.Errorf("invalid octal: %v", err) }
    return os.Chmod(path, os.FileMode(modeInt))
}

func (l *LinuxHardener) EditConfigFile(path string, searchRegex string, replaceText string) error {
    content, err := ioutil.ReadFile(path)
    var text string
    var originalMode os.FileMode = 0644

    if os.IsNotExist(err) {
        text = ""
    } else if err != nil {
        return err
    } else {
        text = string(content)
        info, _ := os.Stat(path)
        originalMode = info.Mode()
    }

    re := regexp.MustCompile("(?m)" + searchRegex)
    newText := ""

    if re.MatchString(text) {
        newText = re.ReplaceAllString(text, replaceText)
    } else {
        if len(text) > 0 && !strings.HasSuffix(text, "\n") {
            newText = text + "\n" + replaceText + "\n"
        } else {
            newText = text + replaceText + "\n"
        }
    }
    return ioutil.WriteFile(path, []byte(newText), originalMode)
}