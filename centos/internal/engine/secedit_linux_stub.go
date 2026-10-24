//go:build linux

package engine

// SecEditManager is a no-op stub on Linux.
// The real implementation is in secedit_utils.go which is Windows-only.
type SecEditManager struct{}

func NewSecEditManager() *SecEditManager {
	return &SecEditManager{}
}

// CheckUserRight always returns false on Linux (Windows-only feature).
func (s *SecEditManager) CheckUserRight(rightName string, expectedUsers string) (bool, error) {
	return false, nil
}

// SetUserRight is a no-op on Linux (Windows-only feature).
func (s *SecEditManager) SetUserRight(rightName string, users string) error {
	return nil
}
