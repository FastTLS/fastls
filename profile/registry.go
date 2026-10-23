package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Catalog is neutral source data, not proof that a backend implements its features.
type Catalog struct {
	SchemaVersion int      `json:"schema_version"`
	Baselines     []Spec   `json:"baselines"`
	Records       []Record `json:"records"`
	Aliases       []Alias  `json:"aliases"`
}
type Alias struct {
	Name   string `json:"name"`
	Target string `json:"target"`
}
type Record struct {
	ID       string `json:"id"`
	Baseline string `json:"baseline,omitempty"`
	Spec     *Spec  `json:"spec,omitempty"`
	Patch    *Patch `json:"patch,omitempty"`
}

// Pointer presence distinguishes missing, zero, false and explicit empty arrays.
type Patch struct {
	Metadata      *Metadata     `json:"metadata,omitempty"`
	TLS           *TLSPatch     `json:"tls,omitempty"`
	HTTP2         *HTTP2Config  `json:"http2,omitempty"`
	Headers       *HeaderConfig `json:"headers,omitempty"`
	Identity      *Identity     `json:"identity,omitempty"`
	ClearIdentity *bool         `json:"clear_identity,omitempty"`
	Capabilities  *Capabilities `json:"capabilities,omitempty"`
	Evidence      *[]Evidence   `json:"evidence,omitempty"`
}
type TLSPatch struct {
	MinVersion         *Code        `json:"min_version,omitempty"`
	MaxVersion         *Code        `json:"max_version,omitempty"`
	RecordVersion      *Code        `json:"record_version,omitempty"`
	LegacyVersion      *Code        `json:"legacy_version,omitempty"`
	CipherSuites       *[]Code      `json:"cipher_suites,omitempty"`
	Extensions         *[]Extension `json:"extensions,omitempty"`
	OptionalExtensions *[]Code      `json:"optional_extensions,omitempty"`
	ExtensionOrder     *string      `json:"extension_order,omitempty"`
	GREASEPolicy       *string      `json:"grease_policy,omitempty"`
	SessionPolicy      *string      `json:"session_policy,omitempty"`
}
type Registry struct {
	records map[string]Spec
	aliases map[string]string
}

// DecodeCatalog rejects duplicate keys before decoding into the typed schema.
func DecodeCatalog(data []byte) (Catalog, error) {
	var c Catalog
	if len(data) > 8<<20 {
		return c, fmt.Errorf("%w: catalog exceeds 8 MiB", ErrInvalidProfile)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := checkValue(d, 0); err != nil {
		return c, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return c, fmt.Errorf("%w: expected one document", ErrInvalidProfile)
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	return c, nil
}
func checkValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("JSON nesting exceeds 64")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok {
				return fmt.Errorf("invalid object key")
			}
			if seen[s] {
				return fmt.Errorf("duplicate JSON key %q at byte %d", s, d.InputOffset())
			}
			seen[s] = true
			if err = checkValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 10000 {
				return fmt.Errorf("array exceeds 10000 entries")
			}
			if err := checkValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected closing delimiter")
	}
	_, err = d.Token()
	return err
}

func NewRegistry(c Catalog) (*Registry, error) {
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("%w: unsupported catalog schema", ErrInvalidProfile)
	}
	if len(c.Records) == 0 || len(c.Records) > 10000 {
		return nil, fmt.Errorf("%w: catalog needs 1..10000 records", ErrInvalidProfile)
	}
	r := &Registry{records: map[string]Spec{}, aliases: map[string]string{}}
	baselines := map[string]Spec{}
	for _, s := range c.Baselines {
		if _, ok := baselines[s.ID]; ok {
			return nil, invalid(s.ID, "baseline", "duplicate ID")
		}
		if err := Validate(s); err != nil {
			return nil, err
		}
		baselines[s.ID] = Clone(s)
	}
	for _, rec := range c.Records {
		if _, ok := r.records[rec.ID]; ok {
			return nil, invalid(rec.ID, "id", "duplicate record")
		}
		if _, ok := baselines[rec.ID]; ok {
			return nil, invalid(rec.ID, "id", "record collides with baseline")
		}
		var spec Spec
		if rec.Baseline != "" {
			if rec.Spec != nil {
				return nil, invalid(rec.ID, "spec", "baseline and full spec cannot coexist")
			}
			b, ok := baselines[rec.Baseline]
			if !ok {
				return nil, invalid(rec.ID, "baseline", "missing baseline; references may not target other records")
			}
			spec = Clone(b)
			spec.ID = rec.ID
			// Metadata.ID is a derived listing identity, not an inherited baseline identity.
			if spec.Metadata.ID != "" {
				spec.Metadata.ID = rec.ID
			}
			if rec.Patch != nil {
				applyPatch(&spec, *rec.Patch)
			}
		} else {
			if rec.Spec == nil || rec.Patch != nil {
				return nil, invalid(rec.ID, "spec", "full spec required without baseline")
			}
			spec = Clone(*rec.Spec)
			if spec.ID != rec.ID {
				return nil, invalid(rec.ID, "id", "record/spec mismatch")
			}
		}
		if err := Validate(spec); err != nil {
			return nil, err
		}
		if err := validateID(spec); err != nil {
			return nil, err
		}
		r.records[rec.ID] = Clone(spec)
	}
	for _, a := range c.Aliases {
		if a.Name == "" || a.Name != strings.ToLower(strings.TrimSpace(a.Name)) {
			return nil, invalid(a.Name, "alias", "must be normalized")
		}
		if _, ok := r.records[a.Name]; ok {
			return nil, invalid(a.Name, "alias", "alias collides with record")
		}
		if _, ok := r.aliases[a.Name]; ok {
			return nil, invalid(a.Name, "alias", "duplicate alias")
		}
		if _, ok := r.records[a.Target]; !ok {
			return nil, invalid(a.Name, "alias", "target must be a record in this catalog")
		}
		r.aliases[a.Name] = a.Target
	}
	return r, nil
}
func validateID(s Spec) error {
	parts := strings.Split(s.ID, "/")
	m := s.Metadata
	if m.Kind == "browser" {
		if (len(parts) != 3 && len(parts) != 4) || m.Product == "library" || m.Product == "client" {
			return invalid(s.ID, "id", "invalid or reserved browser ID shape")
		}
	} else if len(parts) != 5 {
		return invalid(s.ID, "id", "library/client IDs require five components")
	}
	prefix := []string{m.Product, m.ProductVersion, m.Platform}
	if m.Kind != "browser" {
		prefix = append([]string{m.Kind}, prefix...)
		prefix = append(prefix, m.Variant)
	} else if len(parts) == 4 {
		prefix = append(prefix, m.Variant)
	}
	for _, component := range prefix {
		if strings.Contains(component, "/") {
			return invalid(s.ID, "id", "metadata components must not contain a path separator")
		}
	}
	if strings.Join(prefix, "/") != s.ID {
		return invalid(s.ID, "id", "canonical ID does not match metadata")
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || p != strings.ToLower(p) {
			return invalid(s.ID, "id", "noncanonical path component")
		}
	}
	return nil
}
func applyPatch(s *Spec, p Patch) {
	if p.Metadata != nil {
		s.Metadata = *p.Metadata
	}
	if p.HTTP2 != nil {
		s.HTTP2 = *p.HTTP2
	}
	if p.Headers != nil {
		s.Headers = *p.Headers
	}
	if p.Identity != nil {
		s.Identity = p.Identity
	}
	if p.ClearIdentity != nil && *p.ClearIdentity {
		s.Identity = nil
	}
	if p.Capabilities != nil {
		s.Capabilities = *p.Capabilities
	}
	if p.Evidence != nil {
		s.Evidence = *p.Evidence
	}
	if t := p.TLS; t != nil {
		if t.MinVersion != nil {
			s.TLS.MinVersion = *t.MinVersion
		}
		if t.MaxVersion != nil {
			s.TLS.MaxVersion = *t.MaxVersion
		}
		if t.RecordVersion != nil {
			s.TLS.RecordVersion = *t.RecordVersion
		}
		if t.LegacyVersion != nil {
			s.TLS.LegacyVersion = *t.LegacyVersion
		}
		if t.CipherSuites != nil {
			s.TLS.CipherSuites = *t.CipherSuites
		}
		if t.Extensions != nil {
			s.TLS.Extensions = *t.Extensions
		}
		if t.OptionalExtensions != nil {
			s.TLS.OptionalExtensions = *t.OptionalExtensions
		}
		if t.ExtensionOrder != nil {
			s.TLS.ExtensionOrder = *t.ExtensionOrder
		}
		if t.GREASEPolicy != nil {
			s.TLS.GREASEPolicy = *t.GREASEPolicy
		}
		if t.SessionPolicy != nil {
			s.TLS.SessionPolicy = *t.SessionPolicy
		}
	}
}
func (r *Registry) Lookup(selector string) (Spec, error) {
	key := strings.ToLower(strings.TrimSpace(selector))
	if target, ok := r.aliases[key]; ok {
		key = target
	}
	spec, ok := r.records[key]
	if !ok {
		return Spec{}, fmt.Errorf("%w: %s", ErrUnknownProfile, selector)
	}
	return Clone(spec), nil
}
func (r *Registry) List() []Metadata {
	keys := []string{}
	for k := range r.records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := make([]Metadata, 0, len(keys))
	for _, k := range keys {
		metadata := r.records[k].Metadata
		metadata.ID = k
		result = append(result, metadata)
	}
	return result
}

// ValidateID validates canonical identity without requiring protocol fields.
func ValidateID(s Spec) error { return validateID(s) }

// CheckJSONValue rejects duplicate JSON keys and excessive resource usage.
func CheckJSONValue(d *json.Decoder, depth int) error { return checkValue(d, depth) }
