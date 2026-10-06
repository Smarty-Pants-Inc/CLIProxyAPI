package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// This test deliberately uses only the pre-existing Load/Save API so the identical
// test can run on the old implementation. The process publishes while all local
// writers hold stale snapshots, then those writers race to publish their edits.
func TestConcurrentConfigPublicationCAS(t *testing.T) {
	if os.Getenv("CPA_CONFIG_PUBLICATION_CHILD") == "1" {
		path := os.Getenv("CPA_CONFIG_PUBLICATION_PATH")
		publishConfigMarker(t, path, "process", nil, nil)
		fmt.Println("CPA_WRITER_READY")
		var signal string
		if _, err := fmt.Fscan(os.Stdin, &signal); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			publishConfigMarker(t, path, "process-"+strconv.Itoa(i), nil, nil)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("api-keys: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const workers = 12
	loaded := make(chan struct{}, workers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			publishConfigMarker(t, path, "goroutine-"+strconv.Itoa(i), loaded, start)
		}(i)
	}
	for i := 0; i < workers; i++ {
		<-loaded
	}
	child := exec.Command(os.Args[0], "-test.run=^TestConcurrentConfigPublicationCAS$", "-test.v")
	child.Env = append(os.Environ(), "CPA_CONFIG_PUBLICATION_CHILD=1", "CPA_CONFIG_PUBLICATION_PATH="+path)
	var stderr bytes.Buffer
	child.Stderr = &stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		close(start)
		wg.Wait()
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		close(start)
		wg.Wait()
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		close(start)
		wg.Wait()
		t.Fatal(err)
	}
	reader := bufio.NewReader(stdout)
	for {
		line, errRead := reader.ReadString('\n')
		if strings.TrimSpace(line) == "CPA_WRITER_READY" {
			break
		}
		if errRead != nil {
			close(start)
			_ = stdin.Close()
			_ = child.Wait()
			wg.Wait()
			t.Fatalf("process did not become ready: %v: %s", errRead, stderr.String())
		}
	}
	close(start)
	_, errSignal := fmt.Fprintln(stdin, "go")
	_ = stdin.Close()
	output, errOutput := io.ReadAll(reader)
	errChild := child.Wait()
	wg.Wait()
	if errSignal != nil || errOutput != nil || errChild != nil {
		t.Errorf("separate writer failed: signal=%v output=%v process=%v\n%s\n%s", errSignal, errOutput, errChild, output, stderr.String())
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.APIKeys) != workers+5 {
		t.Fatalf("lost writes: got %d want %d (%v)", len(cfg.APIKeys), workers+5, cfg.APIKeys)
	}
	seen := make(map[string]bool)
	for _, marker := range cfg.APIKeys {
		seen[marker] = true
	}
	for i := 0; i < workers; i++ {
		if !seen["goroutine-"+strconv.Itoa(i)] {
			t.Errorf("missing goroutine marker %d: %v", i, cfg.APIKeys)
		}
	}
	if !seen["process"] {
		t.Errorf("missing process marker: %v", cfg.APIKeys)
	}
	for i := 0; i < 4; i++ {
		if !seen["process-"+strconv.Itoa(i)] {
			t.Errorf("missing concurrent process marker %d: %v", i, cfg.APIKeys)
		}
	}
}

func publishConfigMarker(t *testing.T, path, marker string, loaded chan<- struct{}, start <-chan struct{}) {
	t.Helper()
	cfg, err := LoadConfig(path)
	if loaded != nil {
		loaded <- struct{}{}
		<-start
	}
	if err != nil {
		t.Error(err)
		return
	}
	for attempt := 0; attempt < 100; attempt++ {
		cfg.APIKeys = append(cfg.APIKeys, marker)
		if err = SaveConfigPreserveComments(path, cfg); err == nil {
			return
		}
		// Compare the public error text to keep the regression probe runnable on
		// the old tree, where ErrConfigConflict does not exist yet.
		if err.Error() != "config changed since it was read" {
			t.Error(err)
			return
		}
		cfg, err = LoadConfig(path)
		if err != nil {
			t.Error(err)
			return
		}
	}
	t.Errorf("could not publish %q after retries", marker)
}
