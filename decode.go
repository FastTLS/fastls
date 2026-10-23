package fastls

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

const DefaultMaxDecodedBytes int64 = 256 << 20

type DecodeError struct{ Err error }

func (e *DecodeError) Error() string { return "fastls: content decoding: " + e.Err.Error() }
func (e *DecodeError) Unwrap() error { return e.Err }

// Decoding is lazy; context checks between layers bound cancellation latency.
func decodeResponse(ctx context.Context, response *Response, method string, maximum int64) error {
	if method == "HEAD" || response.Status == 204 || response.Status == 304 {
		return nil
	}
	var encodings []string
	for name, values := range response.HeaderValues {
		if strings.EqualFold(name, "Content-Encoding") {
			for _, value := range values {
				for _, part := range strings.Split(value, ",") {
					coding := strings.ToLower(strings.TrimSpace(part))
					if coding == "" || coding == "identity" {
						continue
					}
					switch coding {
					case "gzip", "x-gzip", "deflate", "br", "zstd":
					default:
						return &DecodeError{fmt.Errorf("unsupported content encoding %q", coding)}
					}
					encodings = append(encodings, coding)
				}
			}
		}
	}
	if len(encodings) == 0 {
		return nil
	}
	if len(encodings) > 4 {
		return &DecodeError{errors.New("more than four encoding layers")}
	}
	if maximum == 0 {
		maximum = DefaultMaxDecodedBytes
	}
	if maximum < 1 || maximum > 1<<40 {
		return errors.New("max_decoded_bytes must be 1..1099511627776")
	}
	response.WireHeaderValues = response.HeaderValues
	response.HeaderValues = make(map[string][]string, len(response.WireHeaderValues))
	response.Headers = make(map[string]string, len(response.Headers))
	for name, values := range response.WireHeaderValues {
		if strings.EqualFold(name, "Content-Encoding") || strings.EqualFold(name, "Content-Length") {
			continue
		}
		response.HeaderValues[name] = append([]string{}, values...)
		if len(values) > 0 {
			response.Headers[name] = values[0]
			if name == "Set-Cookie" {
				response.Headers[name] = strings.Join(values, "/,/")
			}
		}
	}
	response.Decoded = true
	response.Body = &decodedBody{ctx: ctx, source: response.Body, encodings: encodings, maximum: maximum}
	return nil
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

type decodedBody struct {
	ctx           context.Context
	source        io.ReadCloser
	encodings     []string
	reader        io.Reader
	closers       []io.Closer
	maximum, read int64
	err           error
}

func (b *decodedBody) initialize() error {
	b.reader = &contextReader{ctx: b.ctx, reader: b.source}
	for i := len(b.encodings) - 1; i >= 0; i-- {
		switch b.encodings[i] {
		case "gzip", "x-gzip":
			r, err := gzip.NewReader(b.reader)
			if err != nil {
				return err
			}
			b.closers = append(b.closers, r)
			b.reader = r
		case "deflate":
			buffered := bufio.NewReader(b.reader)
			header, err := buffered.Peek(2)
			if err != nil {
				return err
			}
			var r io.ReadCloser
			if header[0]&15 == 8 && (uint16(header[0])<<8|uint16(header[1]))%31 == 0 {
				r, err = zlib.NewReader(buffered)
			} else {
				r = flate.NewReader(buffered)
			}
			if err != nil {
				return err
			}
			b.closers = append(b.closers, r)
			b.reader = r
		case "br":
			b.reader = brotli.NewReader(b.reader)
		case "zstd":
			r, err := zstd.NewReader(b.reader, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
			if err != nil {
				return err
			}
			b.closers = append(b.closers, closeFunc(func() error { r.Close(); return nil }))
			b.reader = r
		}
		b.reader = &contextReader{ctx: b.ctx, reader: b.reader}
	}
	return nil
}

func (b *decodedBody) Read(dst []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.ctx.Err() != nil {
		return 0, context.Cause(b.ctx)
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if b.reader == nil {
		if err := b.initialize(); err != nil {
			b.err = &DecodeError{err}
			return 0, b.err
		}
	}
	remaining := b.maximum - b.read
	if int64(len(dst)) > remaining+1 {
		dst = dst[:remaining+1]
	}
	n, err := b.reader.Read(dst)
	if int64(n) > remaining {
		n = int(remaining)
		err = errors.New("decoded response exceeds max_decoded_bytes")
	}
	b.read += int64(n)
	if err != nil && err != io.EOF {
		b.err = &DecodeError{err}
		return n, b.err
	}
	if err == io.EOF {
		b.err = io.EOF
	}
	return n, err
}

func (b *decodedBody) Close() error {
	for i := len(b.closers) - 1; i >= 0; i-- {
		b.closers[i].Close()
	}
	return b.source.Close()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, context.Cause(r.ctx)
	}
	return r.reader.Read(p)
}
