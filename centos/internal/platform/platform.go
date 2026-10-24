package platform

// HardenerInterface defines the methods required for any OS implementation
type HardenerInterface interface {
    GetOSName() string
    
    // Updated: Returns (success, output, error)
    RunCommand(cmdStr string, args []string, expectPattern string) (bool, string, error)
    
    // Updated: Checks content via RunCommand wrapper
    CheckFileContent(cmd string, args []string, expectPattern string) (bool, error)

    // Updated: Now accepts owner and group
    CheckFilePermission(path string, expectedMode string, expectedOwner string, expectedGroup string) (bool, error)
    SetFilePermission(path string, modeStr string) error

    // Registry (Windows)
    CheckRegistry(key, val string, exp interface{}) (bool, error)
    SetRegistry(k, v string, val interface{}) error

    // File Editing (Linux)
    EditConfigFile(path string, searchRegex string, replaceText string) error
}

// Global instance variable
var currentPlatform HardenerInterface

// GetPlatform returns the singleton instance
func GetPlatform() HardenerInterface {
    if currentPlatform == nil {
        // Simple factory logic
        currentPlatform = getPlatformInstance()
    }
    return currentPlatform
}