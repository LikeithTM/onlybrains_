package policy

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadPolicy reads a JSON file and returns the Policy struct.
func LoadPolicy(filePath string) (*Policy, error) {
	// 1. Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy file: %v", err)
	}
	defer file.Close()

	// 2. Decode the JSON
	var policy Policy
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode JSON: %v", err)
	}

	return &policy, nil
}