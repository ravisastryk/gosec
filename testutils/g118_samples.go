package testutils

import "github.com/securego/gosec/v2"

// SampleCodeG118 - Context propagation failures that may leak goroutines/resources
var SampleCodeG118 = []CodeSample{
	// Vulnerable: goroutine uses context.Background while request context exists
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = ctx
	go func() {
		child, _ := context.WithTimeout(context.Background(), time.Second)
		_ = child
	}()
}
`}, 2, gosec.NewConfig()},

	// Vulnerable: cancel function from context.WithTimeout is never called
	{[]string{`
package main

import (
	"context"
	"time"
)

func work(ctx context.Context) {
	child, _ := context.WithTimeout(ctx, time.Second)
	_ = child
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: loop with blocking call and no ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"time"
)

func run(ctx context.Context) {
	for {
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: complex infinite multi-block loop without ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"time"
)

func complexInfinite(ctx context.Context, ch <-chan int) {
	_ = ctx
	for {
		select {
		case <-ch:
			time.Sleep(time.Millisecond)
		default:
			time.Sleep(time.Millisecond)
		}
	}
}
`}, 1, gosec.NewConfig()},

	// Safe: goroutine propagates request context and checks cancellation
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	go func(ctx2 context.Context) {
		for {
			select {
			case <-ctx2.Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}(ctx)
}
`}, 0, gosec.NewConfig()},

	// Safe: cancel is always called
	{[]string{`
package main

import (
	"context"
	"time"
)

func work(ctx context.Context) {
	child, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_ = child
}
`}, 0, gosec.NewConfig()},

	// Safe: cancel is forwarded then deferred (regression for SSA store/load flow)
	{[]string{`
package main

import "context"

func forwarded(ctx context.Context) {
	child, cancel := context.WithCancel(ctx)
	_ = child
	cancelCopy := cancel
	defer cancelCopy()
}
`}, 0, gosec.NewConfig()},

	// Safe: loop has explicit ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"time"
)

func run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
`}, 0, gosec.NewConfig()},

	// Safe: bounded loop with blocking call (finite by condition)
	{[]string{`
package main

import (
	"context"
	"time"
)

func bounded(ctx context.Context) {
	_ = ctx
	for i := 0; i < 3; i++ {
		time.Sleep(time.Millisecond)
	}
}
`}, 0, gosec.NewConfig()},

	// Safe: complex loop with explicit non-context exit path
	{[]string{`
package main

import (
	"context"
	"time"
)

func worker(ctx context.Context, max int) {
	_ = ctx
	i := 0
	for {
		if i >= max {
			break
		}
		time.Sleep(time.Millisecond)
		i++
	}
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: context.WithCancel variant (not just WithTimeout)
	{[]string{`
package main

import "context"

func work(ctx context.Context) {
	child, _ := context.WithCancel(ctx)
	_ = child
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: context.WithDeadline variant
	{[]string{`
package main

import (
	"context"
	"time"
)

func work(ctx context.Context) {
	child, _ := context.WithDeadline(ctx, time.Now().Add(time.Second))
	_ = child
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: goroutine uses context.TODO instead of request context
	{[]string{`
package main

import (
	"context"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_ = ctx
	go func() {
		bg := context.TODO()
		_ = bg
	}()
}
`}, 1, gosec.NewConfig()},

	// Note: nested goroutines are not detected by current implementation
	{[]string{`
package main

import (
	"context"
	"net/http"
)

func handler(r *http.Request) {
	_ = r.Context()
	go func() {
		go func() {
			ctx := context.Background()
			_ = ctx
		}()
	}()
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: function parameter ignored in goroutine
	{[]string{`
package main

import (
	"context"
	"time"
)

func worker(ctx context.Context) {
	_ = ctx
	go func() {
		newCtx := context.Background()
		_, _ = context.WithTimeout(newCtx, time.Second)
	}()
}
`}, 2, gosec.NewConfig()},

	// Note: channel range loops are not detected as blocking by current implementation
	{[]string{`
package main

import "context"

func consume(ctx context.Context, ch <-chan int) {
	_ = ctx
	for val := range ch {
		_ = val
	}
}
`}, 0, gosec.NewConfig()},

	// Note: select loops without ctx.Done are not detected by current implementation
	{[]string{`
package main

import (
	"context"
	"time"
)

func selectLoop(ctx context.Context, ch <-chan int) {
	_ = ctx
	for {
		select {
		case <-ch:
		case <-time.After(time.Second):
		}
	}
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: multiple context creations, one missing cancel
	{[]string{`
package main

import "context"

func multiContext(ctx context.Context) {
	ctx1, cancel1 := context.WithCancel(ctx)
	defer cancel1()
	_ = ctx1

	ctx2, _ := context.WithCancel(ctx)
	_ = ctx2
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: cancel returned to caller (analyzer cannot verify caller will use it)
	{[]string{`
package main

import "context"

func createContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}
`}, 1, gosec.NewConfig()},

	// Note: simple goroutines with Background() not detected when request param unused
	{[]string{`
package main

import (
	"context"
	"net/http"
)

func simpleHandler(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx := context.Background()
		_ = ctx
	}()
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: loop with http.Get blocking call (no ctx.Done guard)
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func pollAPI(ctx context.Context) {
	for {
		resp, _ := http.Get("https://api.example.com")
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: loop with database query (no ctx.Done guard)
	{[]string{`
package main

import (
	"context"
	"database/sql"
	"time"
)

func pollDB(ctx context.Context, db *sql.DB) {
	for {
		db.Query("SELECT 1")
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: loop with os.ReadFile blocking call
	{[]string{`
package main

import (
	"context"
	"os"
	"time"
)

func watchFile(ctx context.Context) {
	for {
		os.ReadFile("config.txt")
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Safe: loop with blocking call AND ctx.Done guard
	{[]string{`
package main

import (
	"context"
	"net/http"
	"time"
)

func safePoller(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			resp, _ := http.Get("https://api.example.com")
			if resp != nil {
				resp.Body.Close()
			}
		}
	}
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: goroutine with TODO instead of passed context
	{[]string{`
package main

import (
	"context"
	"time"
)

func startWorker(ctx context.Context) {
	go func() {
		newCtx, cancel := context.WithTimeout(context.TODO(), time.Second)
		defer cancel()
		_ = newCtx
	}()
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: WithTimeout in loop, cancel never called (reports once per location)
	{[]string{`
package main

import (
	"context"
	"time"
)

func leakyLoop(ctx context.Context) {
	for i := 0; i < 10; i++ {
		child, _ := context.WithTimeout(ctx, time.Second)
		_ = child
	}
}
`}, 1, gosec.NewConfig()},

	// Safe: WithTimeout in loop WITH defer cancel
	{[]string{`
package main

import (
	"context"
	"time"
)

func properLoop(ctx context.Context) {
	for i := 0; i < 10; i++ {
		child, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		_ = child
	}
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: cancel assigned to variable but never called
	{[]string{`
package main

import "context"

func storeCancel(ctx context.Context) {
	_, cancel := context.WithCancel(ctx)
	_ = cancel
}
`}, 1, gosec.NewConfig()},

	// Safe: cancel assigned to interface and called
	{[]string{`
package main

import "context"

func interfaceCancel(ctx context.Context) {
	_, cancel := context.WithCancel(ctx)
	var fn func() = cancel
	defer fn()
}
`}, 0, gosec.NewConfig()},

	// Vulnerable: nested WithCancel calls, inner one not canceled
	{[]string{`
package main

import "context"

func nestedContext(ctx context.Context) {
	ctx1, cancel1 := context.WithCancel(ctx)
	defer cancel1()

	ctx2, _ := context.WithCancel(ctx1)
	_ = ctx2
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: loop with goroutine launch (hasBlocking=true)
	{[]string{`
package main

import (
	"context"
	"time"
)

func spawnWorkers(ctx context.Context) {
	for {
		go func() {
			time.Sleep(time.Millisecond)
		}()
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: loop with defer that has blocking call
	{[]string{`
package main

import (
	"context"
	"os"
	"time"
)

func deferredWrites(ctx context.Context) {
	for {
		defer func() {
			os.WriteFile("log.txt", []byte("data"), 0644)
		}()
		time.Sleep(time.Second)
	}
}
`}, 1, gosec.NewConfig()},

	// Vulnerable: infinite loop with blocking interface method call
	{[]string{`
package main

import (
	"context"
	"io"
	"time"
)

func readLoop(ctx context.Context, r io.Reader) {
	buf := make([]byte, 1024)
	for {
		r.Read(buf)
		time.Sleep(time.Millisecond)
	}
}
`}, 1, gosec.NewConfig()},

	// Safe: loop with http.Client.Do has external exit via error
	{[]string{`
package main

import (
	"context"
	"net/http"
)

func fetchWithBreak(ctx context.Context) error {
	client := &http.Client{}
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest("GET", "https://example.com", nil)
		_, err := client.Do(req)
		if err != nil {
			return err
		}
	}
	return nil
}
`}, 0, gosec.NewConfig()},
}
