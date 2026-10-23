package fastls

import (
	"context"
	"errors"
	"io"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/FastTLS/fastls/profile"
	http "github.com/FastTLS/fhttp"
)

// Session owns reusable connections for a fixed transport configuration.
// It is safe for concurrent requests. Close cancels active bodies and prevents new requests.
type Session struct {
	options Options
	client  http.Client
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

// RequestOptions contains fields which may vary without changing the transport identity.
type RequestOptions struct {
	Timeouts        Timeouts
	DecodeContent   bool
	MaxDecodedBytes int64
	Headers         map[string]string
	Body            string
	DisableRedirect bool
}

// NewSession fixes the transport identity. Set request deadlines through DoContext's context;
// Options.Timeout does not apply to reusable sessions.
func NewSession(options Options) (*Session, error) {
	if options.CookieJar == nil {
		options.CookieJar = NewCookieStore()
	}
	if options.Profile != nil {
		cloned := profile.Clone(*options.Profile)
		options.Profile = &cloned
	}
	if options.TLSRootCAs != nil {
		options.TLSRootCAs = options.TLSRootCAs.Clone()
	}
	ctx, cancel := context.WithCancel(context.Background())
	options.reuseConnections, options.lifetime = true, ctx
	// Prepare and validate the fixed profile once, without making a network request.
	options.URL, options.Method = "https://localhost/", "GET"
	prepared, err := processRequest(&options)
	if err != nil {
		cancel()
		return nil, err
	}
	prepared.client.Timeout = 0 // Each request's context owns its total deadline.
	return &Session{options: options, client: prepared.client, ctx: ctx, cancel: cancel}, nil
}

func (s *Session) DoContext(ctx context.Context, url string, request RequestOptions, method string) (Response, error) {
	for _, limit := range []time.Duration{request.Timeouts.Connect, request.Timeouts.Headers, request.Timeouts.Read} {
		if limit < 0 || limit > 24*time.Hour {
			return Response{}, errors.New("phase timeout must be 0..24 hours")
		}
	}
	if request.MaxDecodedBytes < 0 || request.MaxDecodedBytes > 1<<40 {
		return Response{}, errors.New("max_decoded_bytes must be 1..1099511627776 or zero for default")
	}
	if ctx == nil {
		return Response{}, errors.New("nil request context")
	}
	if s.ctx.Err() != nil {
		return Response{}, errors.New("session is closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	release := func() {
		stop()
		cancel()
		if s.ctx.Err() != nil {
			s.client.CloseIdleConnections()
		}
	}
	opts := s.options
	opts.URL, opts.Method, opts.Body = url, method, request.Body
	opts.Headers = maps.Clone(s.options.Headers)
	if opts.Headers == nil {
		opts.Headers = make(map[string]string)
	}
	opts.HeaderValues = maps.Clone(s.options.HeaderValues)
	for name, value := range request.Headers {
		for existing := range opts.Headers {
			if strings.EqualFold(existing, name) {
				delete(opts.Headers, existing)
			}
		}
		for existing := range opts.HeaderValues {
			if strings.EqualFold(existing, name) {
				delete(opts.HeaderValues, existing)
			}
		}
		opts.Headers[name] = value
	}
	client := s.client // Transport is shared; redirect policy is local to the request.
	client.Transport = &requestTransport{base: client.Transport, limits: request.Timeouts}
	for name := range opts.HeaderValues {
		if strings.EqualFold(name, "Cookie") {
			client.Jar = outgoingCookieOverride{CookieJar: client.Jar}
			break
		}
	}
	for name := range opts.Headers {
		if strings.EqualFold(name, "Cookie") {
			client.Jar = outgoingCookieOverride{CookieJar: client.Jar}
			break
		}
	}
	client.CheckRedirect = nil
	if request.DisableRedirect {
		client.CheckRedirect = disabledRedirect
	}
	prepared, err := processRequest(&opts, client)
	if err != nil {
		release()
		return Response{}, err
	}
	prepared.req = prepared.req.WithContext(ctx)
	response, err := dispatcher(prepared)
	if err != nil {
		if response.Body != nil {
			response.Body.Close()
		}
		release()
		return response, err
	}
	if request.DecodeContent {
		if err := decodeResponse(ctx, &response, strings.ToUpper(method), request.MaxDecodedBytes); err != nil {
			response.Body.Close()
			release()
			return Response{}, err
		}
	}
	response.Body = &sessionBody{ReadCloser: response.Body, release: release}
	return response, nil
}

type sessionBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *sessionBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil {
		b.once.Do(b.release)
	}
	return n, err
}
func (b *sessionBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

func (s *Session) CloseIdleConnections() { s.client.CloseIdleConnections() }
func (s *Session) Close()                { s.once.Do(func() { s.cancel(); s.client.CloseIdleConnections() }) }
