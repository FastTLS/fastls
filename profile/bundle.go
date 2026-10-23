package profile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Bundle is closed offline data. It contains no callbacks or executable scripts.
type Bundle struct {
	SchemaVersion   int          `json:"schema_version"`
	ProviderID      string       `json:"provider_id"`
	ProviderVersion string       `json:"provider_version"`
	DataRevision    string       `json:"data_revision"`
	Records         []Resolution `json:"records"`
	Aliases         []Alias      `json:"aliases,omitempty"`
}
type BundleProvider struct {
	records map[string]Resolution
	aliases map[string]string
}

func DecodeBundle(data []byte) (*BundleProvider, error) {
	if len(data) > 8<<20 {
		return nil, fmt.Errorf("%w: bundle exceeds 8 MiB", ErrInvalidProfile)
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := checkValue(d, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: expected one document", ErrInvalidProfile)
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var b Bundle
	if err := d.Decode(&b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	if b.SchemaVersion != SchemaVersion || b.ProviderID == "" || b.ProviderVersion == "" || b.DataRevision == "" || len(b.Records) == 0 || len(b.Records) > 10000 {
		return nil, fmt.Errorf("%w: bundle identity/version required", ErrInvalidProfile)
	}
	p := &BundleProvider{records: map[string]Resolution{}, aliases: map[string]string{}}
	for _, r := range b.Records {
		if err := ValidateResolution(r); err != nil {
			return nil, err
		}
		id := r.Match.ProfileID
		if id == "" || id != strings.ToLower(strings.TrimSpace(id)) {
			return nil, ErrInvalidProfile
		}
		if _, ok := p.records[id]; ok {
			return nil, fmt.Errorf("%w: duplicate bundle ID", ErrInvalidProfile)
		}
		r.Match.ProviderID = b.ProviderID
		r.Match.ProviderVersion = b.ProviderVersion
		r.Match.DataRevision = b.DataRevision
		r.Match.ContractVersion = ContractVersion
		p.records[id] = CloneResolution(r)
	}
	for _, a := range b.Aliases {
		if _, ok := p.records[a.Target]; !ok {
			return nil, ErrInvalidProfile
		}
		if a.Name == "" || a.Name != strings.ToLower(strings.TrimSpace(a.Name)) || p.aliases[a.Name] != "" {
			return nil, ErrInvalidProfile
		}
		if _, ok := p.records[a.Name]; ok {
			return nil, ErrInvalidProfile
		}
		p.aliases[a.Name] = a.Target
	}
	return p, nil
}
func (p *BundleProvider) Resolve(ctx context.Context, r ResolveRequest) (Resolution, error) {
	if err := ctx.Err(); err != nil {
		return Resolution{}, err
	}
	if p == nil {
		return Resolution{}, ErrInvalidOptions
	}
	id := strings.ToLower(strings.TrimSpace(r.Selector))
	if id == "" {
		id = r.Defaults.Selector
	}
	if a := p.aliases[id]; a != "" {
		id = a
	}
	result, ok := p.records[id]
	if !ok {
		return Resolution{}, fmt.Errorf("%w: %s", ErrUnknownProfile, id)
	}
	if r.Policy != "" && r.Policy != RecordedOnly && r.Policy != AllowCompatible {
		return Resolution{}, ErrInvalidOptions
	}
	if r.Policy == RecordedOnly && result.Match.Method != "recorded" {
		return Resolution{}, fmt.Errorf("%w: snapshot is not recorded", ErrUnknownProfile)
	}
	result = CloneResolution(result)
	result.Match.Selector = r.Selector
	return result, nil
}

func ValidateResolution(r Resolution) error {
	if (r.Spec == nil) == (r.Legacy == nil) {
		return fmt.Errorf("%w: exactly one Spec or Legacy required", ErrInvalidProfile)
	}
	if r.Match.ContractVersion != "" && r.Match.ContractVersion != ContractVersion {
		return &UnsupportedFeature{Field: "match.contract_version", Feature: r.Match.ContractVersion}
	}
	if r.Spec != nil {
		if err := Validate(*r.Spec); err != nil {
			return err
		}
		if r.Match.ProfileID != "" && r.Match.ProfileID != r.Spec.ID {
			return fmt.Errorf("%w: match/spec ID conflict", ErrInvalidProfile)
		}
	}
	if l := r.Legacy; l != nil {
		if (l.Format != "ja3" && l.Format != "ja4r") || l.Hello == "" || len(l.Hello) > 65536 || strings.ContainsAny(l.Hello, "\r\n\x00") {
			return fmt.Errorf("%w: malformed legacy definition", ErrInvalidProfile)
		}
		if strings.ContainsAny(l.UserAgent, "\r\n\x00") {
			return ErrInvalidUserAgent
		}
		if l.HTTP2 != nil {
			if err := validateHTTP2(*l.HTTP2); err != nil {
				return err
			}
		}
		if err := validateOrder(l.HeaderOrder, l.PseudoOrder); err != nil {
			return err
		}
	}
	if len(r.Headers.Rules) > 1024 || len(r.Headers.Remove) > 1024 || len(r.Headers.RemovePrefixes) > 64 {
		return ErrInvalidProfile
	}
	headers := []Header{}
	for _, rule := range r.Headers.Rules {
		if len(rule.IfEquals) > 64 {
			return ErrInvalidProfile
		}
		for _, v := range rule.IfEquals {
			if strings.ContainsAny(v, "\r\n\x00") {
				return ErrInvalidProfile
			}
		}
		if rule.Mode != "default" && rule.Mode != "replace" || len(rule.Values) == 0 {
			return fmt.Errorf("%w: header policy mode/values", ErrInvalidProfile)
		}
		if strings.EqualFold(rule.Name, "user-agent") {
			if len(rule.Values) != 1 {
				return ErrInvalidProfile
			}
			if r.Legacy != nil && r.Legacy.UserAgent != rule.Values[0] {
				return ErrIdentityConflict
			}
			if r.Spec != nil && r.Spec.Identity != nil && r.Spec.Identity.UserAgent != rule.Values[0] {
				return ErrIdentityConflict
			}
		}
		headers = append(headers, rule.Header)
	}
	if err := validateHeaders(headers); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProfile, err)
	}
	for _, key := range append(append([]string{}, r.Headers.Remove...), r.Headers.RemovePrefixes...) {
		if !headerToken(key) {
			return fmt.Errorf("%w: invalid header removal", ErrInvalidProfile)
		}
	}
	return nil
}
