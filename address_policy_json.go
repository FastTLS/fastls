package fastls

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// WithAddressPolicyJSON returns a copy with an immutable, client-level policy.
// The JSON is trusted operator configuration, not request input. Adapters can
// detect this method through a Go interface and fail startup on older cores.
// Existing copies of client are unchanged, including when validation fails.
func (client Fastls) WithAddressPolicyJSON(data []byte) (Fastls, error) {
	config, err := decodeAddressPolicyJSON(data)
	if err != nil {
		return client, err
	}
	policy, err := NewAddressPolicy(config)
	if err != nil {
		return client, err
	}
	client.addressPolicy = policy
	return client, nil
}

func decodeAddressPolicyJSON(data []byte) (AddressPolicyConfig, error) {
	var config AddressPolicyConfig
	invalid := errors.New("invalid address policy JSON (expected strict object, at most 1 MiB)")
	if len(data) > 1<<20 || !utf8.Valid(data) {
		return config, invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return config, invalid
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return config, invalid
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return config, invalid
		}
		seen[key] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return config, invalid
		}
		var value any
		switch key {
		case "allow_schemes":
			value = &config.AllowSchemes
		case "allow_hosts":
			value = &config.AllowHosts
		case "allow_ports":
			value = &config.AllowPorts
		case "allow_cidrs":
			value = &config.AllowCIDRs
		case "deny_cidrs":
			value = &config.DenyCIDRs
		default:
			return config, invalid
		}
		if err := json.Unmarshal(raw, value); err != nil {
			return config, invalid
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return config, invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return config, invalid
	}
	return config, nil
}
