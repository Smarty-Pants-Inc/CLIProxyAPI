package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRound1ShutdownDrainsActiveRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	stopped := make(chan struct{})
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.Write([]byte("complete")) })}
	s := &Server{server: hs}
	served := make(chan struct{})
	go func() { defer close(served); hs.Serve(ln) }()
	defer func() { hs.Close(); <-served }()
	response := make(chan string, 1)
	go func() {
		r, e := http.Get("http://" + ln.Addr().String())
		if e != nil {
			response <- e.Error()
			return
		}
		defer r.Body.Close()
		b, e := io.ReadAll(r.Body)
		if e != nil {
			response <- e.Error()
		} else {
			response <- string(b)
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		defer close(stopped)
		if e := s.Stop(ctx); e != nil {
			t.Error(e)
		}
	}()
	// Shutdown closes the listener before draining. Wait for it rather than sleeping.
	for {
		c, e := net.Dial("tcp", ln.Addr().String())
		if e != nil {
			break
		}
		c.Close()
		select {
		case <-stopped:
			goto released
		default:
		}
	}
released:
	close(release)
	if got := <-response; got != "complete" {
		t.Errorf("in-flight response truncated: %q", got)
	}
	<-stopped
}
