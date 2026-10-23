package fastls

import (
	"context"
	"io"
	"sync"
	"time"

	http "github.com/FastTLS/fhttp"
	"github.com/FastTLS/fhttp/httptrace"
)

// Timeouts applies per redirect hop; zero disables the corresponding phase limit.
// The request context remains the overall deadline, including consumer pauses.
type Timeouts struct{ Connect, Headers, Read time.Duration }

type TimeoutError struct{ Phase string }

func (e *TimeoutError) Error() string { return "fastls: " + e.Phase + " timeout" }
func (*TimeoutError) Timeout() bool   { return true }
func (*TimeoutError) Temporary() bool { return true }
func (*TimeoutError) Unwrap() error   { return context.DeadlineExceeded }

type requestTransport struct {
	base   http.RoundTripper
	limits Timeouts
}

func (t *requestTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

type phaseClock struct {
	mu                 sync.Mutex
	timer              *time.Timer
	generation         uint64
	finished, gotFirst bool
	cancel             context.CancelCauseFunc
	limits             Timeouts
}

func (p *phaseClock) armLocked(phase string, duration time.Duration) {
	if p.finished {
		return
	}
	p.generation++
	if p.timer != nil {
		p.timer.Stop()
	}
	if duration == 0 {
		return
	}
	id := p.generation
	p.timer = time.AfterFunc(duration, func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.finished && id == p.generation {
			p.cancel(&TimeoutError{Phase: phase})
		}
	})
}

func (t *requestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.limits == (Timeouts{}) {
		return t.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancelCause(req.Context())
	p := &phaseClock{cancel: cancel, limits: t.limits}
	p.mu.Lock()
	p.armLocked("connect", t.limits.Connect)
	p.mu.Unlock()
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.gotFirst {
				p.armLocked("connect", p.limits.Connect)
			}
			p.gotFirst = true
		},
		GotConn: func(httptrace.GotConnInfo) { p.mu.Lock(); defer p.mu.Unlock(); p.armLocked("connect", 0) },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				p.mu.Lock()
				defer p.mu.Unlock()
				p.armLocked("headers", p.limits.Headers)
			}
		},
	}
	req = req.Clone(httptrace.WithClientTrace(ctx, trace))
	response, err := t.base.RoundTrip(req)
	p.mu.Lock()
	p.finished = true
	p.generation++
	if p.timer != nil {
		p.timer.Stop()
	}
	p.mu.Unlock()
	if ctx.Err() != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		err = context.Cause(ctx)
		cancel(nil)
		return nil, err
	}
	if err != nil {
		cancel(nil)
		return response, err
	}
	response.Body = &phaseBody{ReadCloser: response.Body, ctx: ctx, cancel: cancel, timeout: t.limits.Read}
	return response, nil
}

// Only a blocked network-body Read is timed; time spent in the caller is excluded.
type phaseBody struct {
	io.ReadCloser
	ctx        context.Context
	cancel     context.CancelCauseFunc
	timeout    time.Duration
	mu         sync.Mutex
	generation uint64
	eof        bool
}

func (b *phaseBody) Read(dst []byte) (int, error) {
	b.mu.Lock()
	if b.eof {
		b.mu.Unlock()
		return 0, io.EOF
	}
	if b.ctx.Err() != nil {
		b.mu.Unlock()
		return 0, context.Cause(b.ctx)
	}
	b.generation++
	id := b.generation
	var timer *time.Timer
	if b.timeout > 0 {
		timer = time.AfterFunc(b.timeout, func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if id == b.generation {
				b.cancel(&TimeoutError{Phase: "read"})
			}
		})
	}
	b.mu.Unlock()
	n, err := b.ReadCloser.Read(dst)
	b.mu.Lock()
	b.generation++
	if timer != nil {
		timer.Stop()
	}
	if b.ctx.Err() != nil {
		err = context.Cause(b.ctx)
	}
	if err == io.EOF {
		b.eof = true
	}
	b.mu.Unlock()
	if err != nil {
		b.cancel(nil)
	}
	return n, err
}

func (b *phaseBody) Close() error { b.cancel(nil); return b.ReadCloser.Close() }
