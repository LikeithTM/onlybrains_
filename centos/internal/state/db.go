package state

import (
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

// InitDB creates the table (Keep existing code)
func InitDB() {
	var err error
	DB, err = sql.Open("sqlite", "hardening.db")
	if err != nil {
		log.Fatal(err)
	}

	query := `
    CREATE TABLE IF NOT EXISTS rollback_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id TEXT,
        rule_name TEXT,
        prev_value TEXT,
        new_value TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );`
	_, err = DB.Exec(query)
	if err != nil {
		log.Fatalf("Failed to create DB table: %v", err)
	}
}

// LogAction (Keep existing code)
func LogAction(ruleID, ruleName, prevVal, newVal string) error {
	query := `INSERT INTO rollback_log (rule_id, rule_name, prev_value, new_value, timestamp) VALUES (?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, ruleID, ruleName, prevVal, newVal, time.Now())
	return err
}

// --- NEW FUNCTION ---
// GetRuleHistory fetches the most recent Previous and New values for a rule
func GetRuleHistory(ruleID string) (string, string, bool) {
	var prevVal, newVal string
	// Get the latest log entry for this rule
	query := `SELECT prev_value, new_value FROM rollback_log WHERE rule_id = ? ORDER BY timestamp DESC LIMIT 1`
	err := DB.QueryRow(query, ruleID).Scan(&prevVal, &newVal)
	if err != nil {
		return "", "", false // No history found
	}
	return prevVal, newVal, true
}

func GetRollbackData(ruleID string) (string, error) {
    var prevVal string
    query := `SELECT prev_value FROM rollback_log WHERE rule_id = ? ORDER BY timestamp DESC LIMIT 1`
    err := DB.QueryRow(query, ruleID).Scan(&prevVal)
    if err != nil {
        return "", err
    }
    return prevVal, nil
}

// IsRuleFixed checks if a rule is currently marked as FIXED in the DB
func IsRuleFixed(ruleID string) bool {
    var status string
    // Query the DB for the status of this rule ID
    row := DB.QueryRow("SELECT status FROM rules_state WHERE id = ?", ruleID)
    err := row.Scan(&status)
    if err != nil {
        return false // Not found or error = Not fixed
    }
    return status == "FIXED"
}