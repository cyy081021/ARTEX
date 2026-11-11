package collab

// BranchSetupReport is a device-local configuration check, not a claim that a
// model, tool server, or external target has been contacted successfully.
type BranchSetupReport struct {
	Version int                        `json:"version"`
	Roles   map[string]BranchSetupRole `json:"roles"`
}

type BranchSetupRole struct {
	Ready        bool     `json:"ready"`
	Capabilities []string `json:"capabilities"`
	Issues       []string `json:"issues"`
}
