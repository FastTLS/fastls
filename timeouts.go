package fastls

import (
	"context"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

// Timeouts applies per redirect hop; zero disables the corresponding phase limit.
// The request context remains the overall deadline, including consumer pauses.
type Timeouts struct{ Connect, Headers, Read, Write time.Duration }

type TimeoutError struct{ Phase string }

func (e *TimeoutError) Error() string { return "fastls: " + e.Phase + " timeout" }
func (*TimeoutError) Timeout() bool   { return true }
func (*TimeoutError) Temporary() bool { return true }
func (*TimeoutError) Unwrap() error   { return context.DeadlineExceeded }

type requestTransport struct {
	base   http.RoundTripper
	limits Timeouts
	duplex bool
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

func (p *phaseClock) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.finished = true
	p.generation++
	if p.timer != nil {
		p.timer.Stop()
	}
}

func (t *requestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.limits == (Timeouts{}) {
		return t.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancelCause(req.Context())
	p := &phaseClock{cancel: cancel, limits: t.limits}
	writeClock := &phaseClock{cancel: cancel, limits: t.limits}
	p.mu.Lock()
	p.armLocked("connect", t.limits.Connect)
	p.mu.Unlock()
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			writeClock.mu.Lock()
			writeClock.armLocked("write", 0)
			writeClock.mu.Unlock()
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.gotFirst {
				p.armLocked("connect", p.limits.Connect)
			}
			p.gotFirst = true
		},
		GotConn: func(httptrace.GotConnInfo) {
			p.mu.Lock()
			p.armLocked("connect", 0)
			p.mu.Unlock()
			writeClock.mu.Lock()
			writeClock.armLocked("write", t.limits.Write)
			writeClock.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			writeClock.mu.Lock()
			writeClock.armLocked("write", 0)
			writeClock.mu.Unlock()
			if info.Err == nil {
				p.mu.Lock()
				defer p.mu.Unlock()
				p.armLocked("headers", p.limits.Headers)
			}
		},
	}
	req = req.Clone(httptrace.WithClientTrace(ctx, trace))
	if req.Body != nil && t.limits.Write > 0 {
		req.Body = &uploadPhaseBody{ReadCloser: req.Body, clock: writeClock}
	}
	stopBody := context.AfterFunc(ctx, func() {
		if req.Body != nil {
			req.Body.Close()
		}
		writeClock.finish()
	})
	cleanup := func() {
		stopBody()
		writeClock.finish()
		cancel(nil)
		if req.Body != nil {
			req.Body.Close()
		}
	}
	response, err := t.base.RoundTrip(req)
	p.finish()
	if !t.duplex {
		stopBody()
		writeClock.finish()
	}
	if ctx.Err() != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		err = context.Cause(ctx)
		cleanup()
		return nil, err
	}
	if err != nil {
		cleanup()
		return response, err
	}
	response.Body = &phaseBody{ReadCloser: response.Body, ctx: ctx, cancel: cancel, timeout: t.limits.Read}
	if t.duplex {
		response.Body = &duplexPhaseBody{ReadCloser: response.Body, cleanup: cleanup}
	}
	return response, nil
}

type duplexPhaseBody struct {
	io.ReadCloser
	once    sync.Once
	cleanup func()
}

func (b *duplexPhaseBody) Close() error { b.once.Do(b.cleanup); return b.ReadCloser.Close() }

// Write inactivity includes waiting for the producer and transport consumption.
// Reset only when transport consumes data, never when the caller queues data.
type uploadPhaseBody struct {
	io.ReadCloser
	clock *phaseClock
}

func (b *uploadPhaseBody) Read(dst []byte) (int, error) {
	n, err := b.ReadCloser.Read(dst)
	if n > 0 {
		b.clock.mu.Lock()
		b.clock.armLocked("write", b.clock.limits.Write)
		b.clock.mu.Unlock()
	}
	return n, err
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
