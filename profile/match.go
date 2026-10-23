package profile

import "errors"

type MatchPolicy string

const (
	RecordedOnly    MatchPolicy = "recorded_only"
	AllowCompatible MatchPolicy = "allow_compatible"
	// Deprecated: rejected by v2; translate UA to canonical IDs in the caller.
	LegacyUAFirst MatchPolicy = "legacy_ua_first"
)

var (
	ErrInvalidOptions   = errors.New("invalid profile options")
	ErrInvalidUserAgent = errors.New("invalid user agent")
	ErrIdentityConflict = errors.New("profile identity conflict")
)

// Defaults accepts an explicit canonical Selector. Version/platform inference is
// deprecated; business defaults and legacy translation belong to the caller.
type Defaults struct {
	Selector        string `json:"selector,omitempty"`
	ChromiumVersion int    `json:"chromium_version,omitempty"`
	FirefoxVersion  int    `json:"firefox_version,omitempty"`
	Platform        string `json:"platform,omitempty"`
}

// Match describes configuration selection separately from real-client evidence.
type Match struct {
	ProviderID         string       `json:"provider_id,omitempty"`
	ProviderVersion    string       `json:"provider_version,omitempty"`
	DataRevision       string       `json:"data_revision,omitempty"`
	ContractVersion    string       `json:"contract_version,omitempty"`
	ProfileID          string       `json:"profile_id"`
	Selector           string       `json:"selector"`
	Kind               string       `json:"kind"`
	Product            string       `json:"product"`
	ProductVersion     string       `json:"product_version"`
	EngineVersion      string       `json:"engine_version,omitempty"`
	Platform           string       `json:"platform"`
	Device             string       `json:"device,omitempty"`
	UserAgent          string       `json:"user_agent"`
	BaselineID         string       `json:"baseline_id"`
	Method             string       `json:"method"`
	VerifiedFields     []string     `json:"verified_fields"`
	CompatibilityNotes []string     `json:"compatibility_notes"`
	Source             LegacySource `json:"source"`
}

// MatchError keeps historical error text while providing errors.Is support.
type MatchError struct {
	Reason error
	Detail string
}

func (e *MatchError) Error() string { return e.Detail }
func (e *MatchError) Unwrap() error { return e.Reason }
