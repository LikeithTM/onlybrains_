package policy

// Rule maps directly to the JSON object in your Annexure files
type Rule struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Severity    string      `json:"severity"` // "Critical", "High", "Medium", "Low"
	Platform    string      `json:"platform"` // "windows", "linux"
	Type        string      `json:"type"`     // "registry", "command", "file_check", "file_edit", "secedit", "manual"
	Tags        []string    `json:"tags"`     // e.g. ["firewall", "account"]
	DependsOn   []string    `json:"depends_on"`
	
	Check       CheckAction `json:"check"`
	Remediation Action      `json:"remediation"`
	Rollback    Action      `json:"rollback"`
}

type CheckAction struct {
	// Command based checks
	Cmd           string   `json:"cmd,omitempty"`
	Args          []string `json:"args,omitempty"`
	ExpectPattern string   `json:"expect_pattern,omitempty"`

	// Registry (Windows only)
	RegKey   string      `json:"reg_key,omitempty"`
	RegValue string      `json:"reg_value,omitempty"`
	Expected interface{} `json:"expected,omitempty"` // Can be int (4) or string ("No One")

	// File based checks
	FilePath string `json:"file_path,omitempty"`
	FileMode string `json:"file_mode,omitempty"`
}

type Action struct {
	Type string `json:"type"` // "command", "registry", "file_edit", "manual"

	// Command
	Cmd  string   `json:"cmd,omitempty"`
	Args []string `json:"args,omitempty"`

	// Registry
	RegKey   string      `json:"reg_key,omitempty"`
	RegValue string      `json:"reg_value,omitempty"`
	Value    interface{} `json:"value,omitempty"` // The new value to set

	// File editing (Linux specific)
	FilePath    string `json:"file_path,omitempty"`
	SearchRegex string `json:"search_regex,omitempty"`
	ReplaceText string `json:"replace_text,omitempty"`
}

type Policy struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}
