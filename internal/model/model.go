package model

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type ProfileID string

const (
	ProfileBaseline                ProfileID = "baseline"
	ProfileStrict                  ProfileID = "strict"
	ProfileSocketFirewall          ProfileID = "socket-firewall"
	ProfileVeracodePackageFirewall ProfileID = "veracode-package-firewall"
	ProfilePrivateRegistry         ProfileID = "private-registry"
)

type Report struct {
	SchemaVersion string    `json:"schema_version"`
	Target        string    `json:"target"`
	Inventory     Inventory `json:"inventory"`
	Findings      []Finding `json:"findings"`
	Rules         []Rule    `json:"rules"`
	Profiles      []Profile `json:"profiles"`
	Policy        Policy    `json:"policy"`
}

type Inventory struct {
	Ecosystems                []InventoryItem `json:"ecosystems"`
	PackageManagers           []InventoryItem `json:"package_managers"`
	Manifests                 []InventoryItem `json:"manifests"`
	Lockfiles                 []InventoryItem `json:"lockfiles"`
	CIWorkflows               []InventoryItem `json:"ci_workflows"`
	DependencyBots            []InventoryItem `json:"dependency_bots"`
	PackageManagerConfigFiles []InventoryItem `json:"package_manager_config_files"`
}

type InventoryItem struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      string     `json:"kind"`
	Locations []Location `json:"locations"`
}

type Location struct {
	Path        string `json:"path"`
	StartLine   int    `json:"start_line,omitempty"`
	StartColumn int    `json:"start_column,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	EndColumn   int    `json:"end_column,omitempty"`
}

type Finding struct {
	ID             string      `json:"id"`
	RuleID         string      `json:"rule_id"`
	Title          string      `json:"title"`
	Severity       Severity    `json:"severity"`
	Category       string      `json:"category"`
	Confidence     Confidence  `json:"confidence"`
	Locations      []Location  `json:"locations"`
	Evidence       []Evidence  `json:"evidence"`
	Recommendation string      `json:"recommendation"`
	References     []Reference `json:"references"`
	Autofix        Autofix     `json:"autofix"`
}

type Evidence struct {
	Description string     `json:"description"`
	Locations   []Location `json:"locations"`
}

type Reference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

type Autofix struct {
	Available   bool   `json:"available"`
	Description string `json:"description,omitempty"`
}

type Rule struct {
	ID          string      `json:"id"`
	Ecosystem   string      `json:"ecosystem"`
	Category    string      `json:"category"`
	Severity    Severity    `json:"severity"`
	Profiles    []ProfileID `json:"profiles"`
	Remediation string      `json:"remediation"`
	References  []Reference `json:"references"`
	Enabled     bool        `json:"enabled"`
}

type Profile struct {
	ID          ProfileID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type Policy struct {
	Profiles []ProfileID `json:"profiles"`
	Rules    RulePolicy  `json:"rules"`
}

type RulePolicy struct {
	Enabled  []string `json:"enabled"`
	Disabled []string `json:"disabled"`
}

func EmptyInventory() Inventory {
	return Inventory{
		Ecosystems:                []InventoryItem{},
		PackageManagers:           []InventoryItem{},
		Manifests:                 []InventoryItem{},
		Lockfiles:                 []InventoryItem{},
		CIWorkflows:               []InventoryItem{},
		DependencyBots:            []InventoryItem{},
		PackageManagerConfigFiles: []InventoryItem{},
	}
}

func DefaultProfiles() []Profile {
	return []Profile{
		{ID: ProfileBaseline, Name: "Baseline", Description: "Default hardening checks for common repository package-manager configuration."},
		{ID: ProfileStrict, Name: "Strict", Description: "Higher-signal hardening checks for repositories that want a more restrictive posture."},
		{ID: ProfileSocketFirewall, Name: "Socket Firewall", Description: "Checks relevant to repositories using Socket Firewall controls."},
		{ID: ProfileVeracodePackageFirewall, Name: "Veracode Package Firewall", Description: "Checks relevant to repositories using Veracode Package Firewall controls."},
		{ID: ProfilePrivateRegistry, Name: "Private Registry", Description: "Checks relevant to repositories that route dependencies through private registries."},
	}
}

func EmptyPolicy() Policy {
	return Policy{
		Profiles: []ProfileID{},
		Rules: RulePolicy{
			Enabled:  []string{},
			Disabled: []string{},
		},
	}
}
