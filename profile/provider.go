package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

const ContractVersion = "1"

type Provider interface {
	Resolve(context.Context, ResolveRequest) (Resolution, error)
}
type ResolveRequest struct {
	Selector  string
	UserAgent *string // Deprecated: request header overrides belong to the request options.
	Defaults  Defaults
	Policy    MatchPolicy
}
type LegacySource struct {
	Path   string `json:"path"`
	Head   string `json:"head"`
	SHA256 string `json:"sha256_before_data_migration"`
}
type LegacyFormat string

const (
	JA3Format  LegacyFormat = "ja3"
	JA4RFormat LegacyFormat = "ja4r"
)

type LegacyDefinition struct {
	// SignatureAlgorithms overrides the list omitted by JA3. These are wire
	// declarations, not a statement of backend signature verification support.
	SignatureAlgorithms []Code       `json:"signature_algorithms,omitempty"`
	Format              LegacyFormat `json:"format"`
	Hello               string       `json:"hello"`
	UserAgent           string       `json:"user_agent"`
	HTTP2               *HTTP2Config `json:"http2,omitempty"`
	HTTP2Settings       string       `json:"http2_settings,omitempty"`
	HeaderOrder         []string     `json:"header_order,omitempty"`
	PseudoOrder         []string     `json:"pseudo_order,omitempty"`
}

// HeaderRule stores each value once; Mode is default or replace.
type HeaderRule struct {
	Header
	Mode string `json:"mode"`
	// IfEquals adds exact caller values that a default rule must replace.
	IfEquals []string `json:"if_equals,omitempty"`
}
type HeaderPolicy struct {
	Rules          []HeaderRule `json:"rules,omitempty"`
	Remove         []string     `json:"remove,omitempty"`
	RemovePrefixes []string     `json:"remove_prefixes,omitempty"`
}
type Resolution struct {
	Spec    *Spec             `json:"spec,omitempty"`
	Legacy  *LegacyDefinition `json:"legacy,omitempty"`
	Headers HeaderPolicy      `json:"headers"`
	Match   Match             `json:"match"`
}

var ErrUnsupportedFeature = errors.New("unsupported profile feature")

type UnsupportedFeature struct {
	Field   string
	Feature string
}

func (e *UnsupportedFeature) Error() string {
	return fmt.Sprintf("%s: %s (%s)", ErrUnsupportedFeature, e.Field, e.Feature)
}
func (e *UnsupportedFeature) Unwrap() error { return ErrUnsupportedFeature }

// CloneResolution detaches all provider-owned slices and pointers.
func CloneResolution(r Resolution) Resolution {
	b, _ := json.Marshal(r)
	var result Resolution
	_ = json.Unmarshal(b, &result)
	return result
}

// RegistryProvider serves closed, validated offline data without a generator.
type RegistryProvider struct{ registry *Registry }

func NewProvider(c Catalog) (*RegistryProvider, error) {
	r, err := NewRegistry(c)
	if err != nil {
		return nil, err
	}
	return &RegistryProvider{r}, nil
}
func (p *RegistryProvider) Resolve(ctx context.Context, r ResolveRequest) (Resolution, error) {
	if err := ctx.Err(); err != nil {
		return Resolution{}, err
	}
	if p == nil || p.registry == nil {
		return Resolution{}, fmt.Errorf("%w: nil registry", ErrInvalidOptions)
	}
	s, err := p.registry.Lookup(r.Selector)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{Spec: &s, Match: Match{ProfileID: s.ID, Selector: r.Selector, Kind: s.Metadata.Kind, Product: s.Metadata.Product, ProductVersion: s.Metadata.ProductVersion, Platform: s.Metadata.Platform, Method: "offline-catalog", ProviderID: "profile.registry", ContractVersion: ContractVersion}}, nil
}
