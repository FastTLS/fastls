package fastls

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type h3ResourceSample struct {
	Seconds        float64
	RSS, Heap      uint64
	FD, Goroutines int
}

func h3ResourceSnapshot(start time.Time) h3ResourceSample {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	status, _ := os.ReadFile("/proc/self/statm")
	fields := strings.Fields(string(status))
	var rss uint64
	if len(fields) > 1 {
		pages, _ := strconv.ParseUint(fields[1], 10, 64)
		rss = pages * uint64(os.Getpagesize())
	}
	fds, _ := os.ReadDir("/proc/self/fd")
	return h3ResourceSample{time.Since(start).Seconds(), rss, m.HeapAlloc, len(fds), runtime.NumGoroutine()}
}

// TestHTTP3ConfigResource is opt-in and runs once on frozen Linux source, without
// race instrumentation. Budgets and scenario are fixed in H3_CONFIG.md before run.
func TestHTTP3ConfigResource(t *testing.T) {
	if os.Getenv("FASTLS_H3_RESOURCE") != "1" {
		t.Skip("one opt-in five-minute Linux acceptance")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("resource observation requires Linux /proc")
	}
	var active atomic.Int64
	endpoint, roots := configH3Origin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		switch r.URL.Path {
		case "/cancel":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/headers":
			w.Header().Set("X-Large", strings.Repeat("x", 4096))
			io.WriteString(w, "ok")
		default:
			io.CopyN(w, &h3PatternReader{}, 256<<10)
		}
	}), nil)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	errors := make(chan error, 4)
	var cycles atomic.Uint64
	var workerCycles [4]atomic.Uint64
	var wg sync.WaitGroup
	for worker := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var config *HTTP3Config
			if worker >= 2 {
				config = &HTTP3Config{InitialStreamReceiveWindow: 16 << 10, MaxStreamReceiveWindow: 64 << 10, InitialConnectionReceiveWindow: 32 << 10, MaxConnectionReceiveWindow: 128 << 10, MaxResponseHeaderBytes: 1024, KeepAlivePeriod: durationPointer(0)}
			}
			for ctx.Err() == nil {
				s, err := NewSession(Options{HTTPVersion: HTTPVersion3, HTTP3: config, VerifyTLS: true, TLSRootCAs: roots})
				if err != nil {
					errors <- err
					return
				}
				for _, path := range []string{"/body", "/headers", "/cancel"} {
					requestCtx, stop := context.WithTimeout(ctx, 2*time.Second)
					if path == "/cancel" {
						stop()
						requestCtx, stop = context.WithTimeout(ctx, 20*time.Millisecond)
					}
					response, e := s.DoContext(requestCtx, endpoint+path, RequestOptions{DecodeContent: true, MaxDecodedBytes: 256 << 10}, "GET")
					var n int64
					if e == nil {
						n, e = io.Copy(io.Discard, io.LimitReader(response.Body, (256<<10)+1))
						response.Body.Close()
					}
					requestErr := requestCtx.Err()
					stop()
					if ctx.Err() != nil {
						break
					}
					expectedError := path == "/cancel" || (path == "/headers" && config != nil)
					if (!expectedError && e != nil) || (expectedError && e == nil) || (path == "/body" && n != 256<<10) || (path == "/cancel" && requestErr == nil) || (path == "/headers" && config != nil && e != nil && !strings.Contains(strings.ToLower(e.Error()), "header")) {
						s.Close()
						errors <- fmt.Errorf("worker=%d path=%s bytes=%d err=%v request=%v", worker, path, n, e, requestErr)
						return
					}
				}
				s.Close()
				cycles.Add(1)
				workerCycles[worker].Add(1)
				select {
				case <-time.After(50 * time.Millisecond):
				case <-ctx.Done():
				}
			}
		}()
	}
	var samples []h3ResourceSample
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	running := true
	for running {
		select {
		case e := <-errors:
			cancel()
			wg.Wait()
			t.Fatal(e)
		case <-ticker.C:
			samples = append(samples, h3ResourceSnapshot(start))
		case <-ctx.Done():
			running = false
		}
	}
	wg.Wait()
	cleanupDeadline := time.Now().Add(2 * time.Second)
	for active.Load() != 0 && time.Now().Before(cleanupDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case e := <-errors:
		t.Fatal(e)
	default:
	}
	if time.Since(start) < 300*time.Second || len(samples) < 290 || cycles.Load() < 4 {
		t.Fatal("incomplete observation", time.Since(start), len(samples), cycles.Load())
	}
	// Median baseline seconds 6..10 and median final seconds 291..295. Warmup
	// and cooldown excluded from retention comparison; all samples count for peaks.
	median := func(values []h3ResourceSample) h3ResourceSample {
		rss, heap, fd, g := []uint64{}, []uint64{}, []int{}, []int{}
		for _, s := range values {
			rss = append(rss, s.RSS)
			heap = append(heap, s.Heap)
			fd = append(fd, s.FD)
			g = append(g, s.Goroutines)
		}
		sort.Slice(rss, func(i, j int) bool { return rss[i] < rss[j] })
		sort.Slice(heap, func(i, j int) bool { return heap[i] < heap[j] })
		sort.Ints(fd)
		sort.Ints(g)
		i := len(values) / 2
		return h3ResourceSample{RSS: rss[i], Heap: heap[i], FD: fd[i], Goroutines: g[i]}
	}
	baseline, tail := median(samples[5:10]), median(samples[len(samples)-10:len(samples)-5])
	peak := h3ResourceSample{}
	for _, s := range samples {
		peak.RSS = max(peak.RSS, s.RSS)
		peak.Heap = max(peak.Heap, s.Heap)
		peak.FD = max(peak.FD, s.FD)
		peak.Goroutines = max(peak.Goroutines, s.Goroutines)
	}
	perWorker := make([]uint64, 4)
	for i := range perWorker {
		perWorker[i] = workerCycles[i].Load()
		if perWorker[i] == 0 {
			t.Fatal("worker completed no cycles", i)
		}
	}
	result := map[string]any{"worker_cycles": perWorker, "elapsed_seconds": time.Since(start).Seconds(), "cycles": cycles.Load(), "samples": samples, "baseline": baseline, "tail": tail, "peak": peak, "active_after": active.Load()}
	data, _ := json.MarshalIndent(result, "", "  ")
	if path := os.Getenv("FASTLS_H3_RESOURCE_REPORT"); path != "" {
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("resource seconds=%.3f cycles=%d baseline=%+v tail=%+v peak=%+v active=%d", time.Since(start).Seconds(), cycles.Load(), baseline, tail, peak, active.Load())
	if peak.RSS > 384<<20 || peak.RSS > baseline.RSS+(128<<20) || tail.RSS > baseline.RSS+(64<<20) || tail.Heap > baseline.Heap+(32<<20) || peak.FD > baseline.FD+32 || tail.FD > baseline.FD+16 || peak.Goroutines > baseline.Goroutines+128 || tail.Goroutines > baseline.Goroutines+32 || active.Load() != 0 {
		t.Fatal("frozen resource budget exceeded")
	}
}
