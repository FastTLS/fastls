package fastls

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go"
)

// HTTP3Config controls local receive budgets on explicit HTTPVersion3 clients.
// Window sizes and header limits are bytes. Zero selects the documented default,
// except KeepAlivePeriod: nil selects the H3 default; a pointer to zero disables it.
// Configuration is copied at request preparation or NewSession; do not mutate it
// concurrently with those calls. No field changes peer trust or request deadlines.
type HTTP3Config struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                *time.Duration
	MaxResponseHeaderBytes         int64
}

// HTTP3EffectiveConfig is a value snapshot of normalized local limits, not a
// negotiated connection result or a promise about total process memory.
type HTTP3EffectiveConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	KeepAlivePeriod                time.Duration
	MaxResponseHeaderBytes         int64
}

// HTTP3ParameterSupport describes one supported Go configuration field.
type HTTP3ParameterSupport struct{ Name, Unit, Default, Range string }

// HTTP3Capabilities returns a fresh discovery list. These fields are not exposed
// through ABI, SDK or service request DTOs. All require explicit HTTPVersion3.
func HTTP3Capabilities() []HTTP3ParameterSupport {
	return []HTTP3ParameterSupport{
		{"InitialStreamReceiveWindow", "bytes", "524288", "4096..67108864; <= MaxStreamReceiveWindow"},
		{"MaxStreamReceiveWindow", "bytes", "6291456", "4096..67108864; >= InitialStreamReceiveWindow"},
		{"InitialConnectionReceiveWindow", "bytes", "524288", "4096..67108864; <= MaxConnectionReceiveWindow"},
		{"MaxConnectionReceiveWindow", "bytes", "15728640", "4096..67108864; >= InitialConnectionReceiveWindow"},
		{"MaxIdleTimeout", "duration", "30s", "100ms..24h; whole milliseconds"},
		{"KeepAlivePeriod", "duration", "min(10s, MaxIdleTimeout/2)", "0 (disabled), or 10ms..MaxIdleTimeout/2"},
		{"MaxResponseHeaderBytes", "bytes", "10485760", "1024..16777216"},
	}
}

func cloneHTTP3Config(c *HTTP3Config) *HTTP3Config {
	if c == nil {
		return nil
	}
	copy := *c
	if c.KeepAlivePeriod != nil {
		value := *c.KeepAlivePeriod
		copy.KeepAlivePeriod = &value
	}
	return &copy
}

func normalizeHTTP3(input *HTTP3Config) (HTTP3EffectiveConfig, error) {
	c := HTTP3Config{}
	if input != nil {
		c = *input
	}
	e := HTTP3EffectiveConfig{c.InitialStreamReceiveWindow, c.MaxStreamReceiveWindow,
		c.InitialConnectionReceiveWindow, c.MaxConnectionReceiveWindow, c.MaxIdleTimeout, 0, c.MaxResponseHeaderBytes}
	windows := []*uint64{&e.InitialStreamReceiveWindow, &e.MaxStreamReceiveWindow, &e.InitialConnectionReceiveWindow, &e.MaxConnectionReceiveWindow}
	defaults := []uint64{512 << 10, 6 << 20, 512 << 10, 15 << 20}
	names := []string{"InitialStreamReceiveWindow", "MaxStreamReceiveWindow", "InitialConnectionReceiveWindow", "MaxConnectionReceiveWindow"}
	for i, p := range windows {
		if *p == 0 {
			*p = defaults[i]
		}
		if *p < 4<<10 || *p > 64<<20 {
			return HTTP3EffectiveConfig{}, fmt.Errorf("fastls: HTTP3 %s must be zero or 4096..67108864 bytes", names[i])
		}
	}
	if e.InitialStreamReceiveWindow > e.MaxStreamReceiveWindow || e.InitialConnectionReceiveWindow > e.MaxConnectionReceiveWindow {
		return HTTP3EffectiveConfig{}, fmt.Errorf("fastls: HTTP3 initial receive window exceeds its maximum")
	}
	if e.MaxIdleTimeout == 0 {
		e.MaxIdleTimeout = 30 * time.Second
	}
	if e.MaxIdleTimeout < 100*time.Millisecond || e.MaxIdleTimeout > 24*time.Hour || e.MaxIdleTimeout%time.Millisecond != 0 {
		return HTTP3EffectiveConfig{}, fmt.Errorf("fastls: HTTP3 MaxIdleTimeout must be zero or whole milliseconds in 100ms..24h")
	}
	e.KeepAlivePeriod = min(10*time.Second, e.MaxIdleTimeout/2)
	if c.KeepAlivePeriod != nil {
		e.KeepAlivePeriod = *c.KeepAlivePeriod
		if e.KeepAlivePeriod != 0 && (e.KeepAlivePeriod < 10*time.Millisecond || e.KeepAlivePeriod > e.MaxIdleTimeout/2) {
			return HTTP3EffectiveConfig{}, fmt.Errorf("fastls: HTTP3 KeepAlivePeriod must be zero or 10ms..MaxIdleTimeout/2")
		}
	}
	if e.MaxResponseHeaderBytes == 0 {
		e.MaxResponseHeaderBytes = 10 << 20
	}
	if e.MaxResponseHeaderBytes < 1<<10 || e.MaxResponseHeaderBytes > 16<<20 {
		return HTTP3EffectiveConfig{}, fmt.Errorf("fastls: HTTP3 MaxResponseHeaderBytes must be zero or 1024..16777216")
	}
	return e, nil
}

// EffectiveHTTP3Config validates all fixed protocol conflicts and returns a copy
// of the local defaults and requested limits. It performs no DNS or network I/O.
func (o Options) EffectiveHTTP3Config() (HTTP3EffectiveConfig, error) {
	if o.HTTPVersion != HTTPVersion3 {
		return HTTP3EffectiveConfig{}, fmt.Errorf("fastls: effective HTTP3 configuration requires explicit HTTPVersion3")
	}
	if err := o.validateHTTPVersion(); err != nil {
		return HTTP3EffectiveConfig{}, err
	}
	return normalizeHTTP3(o.HTTP3)
}

func (o Options) effectiveHTTP3() *HTTP3EffectiveConfig {
	if o.HTTPVersion != HTTPVersion3 {
		return nil
	}
	e, _ := normalizeHTTP3(o.HTTP3) // processRequest already validated.
	return &e
}

// EffectiveHTTP3Config returns a value copy of this Session's fixed local limits.
// The boolean is false for legacy automatic/q selection and H1/H2 sessions.
func (s *Session) EffectiveHTTP3Config() (HTTP3EffectiveConfig, bool) {
	if s.options.HTTPVersion != HTTPVersion3 {
		return HTTP3EffectiveConfig{}, false
	}
	e, _ := normalizeHTTP3(s.options.HTTP3)
	return e, true
}

func (e HTTP3EffectiveConfig) quicConfig() *quic.Config {
	return &quic.Config{
		InitialStreamReceiveWindow: e.InitialStreamReceiveWindow, MaxStreamReceiveWindow: e.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: e.InitialConnectionReceiveWindow, MaxConnectionReceiveWindow: e.MaxConnectionReceiveWindow,
		MaxIdleTimeout: e.MaxIdleTimeout, KeepAlivePeriod: e.KeepAlivePeriod,
		MaxIncomingStreams: -1, // Preserve http3.Transport's default rejection of server bidirectional streams.
	}
}
