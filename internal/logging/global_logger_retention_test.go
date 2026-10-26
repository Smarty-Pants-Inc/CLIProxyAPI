package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

// Keep: data safety; verify the application actually enables bounded retention.
func TestConfigureLogOutputBoundedRetention(t *testing.T) {
	t.Setenv("WRITABLE_PATH", t.TempDir())
	originalOutput := log.StandardLogger().Out
	defer func() { closeLogOutputs(); log.SetOutput(originalOutput) }()
	if err := ConfigureLogOutput(&config.Config{LoggingToFile: true}); err != nil {
		t.Fatal(err)
	}
	if logWriter.MaxSize != 10 || logWriter.MaxBackups != 19 || logWriter.MaxAge != 7 || !logWriter.Compress {
		t.Fatalf("retention = size:%d backups:%d age:%d compress:%t; want 10 MiB, 19 backups, 7 days, gzip", logWriter.MaxSize, logWriter.MaxBackups, logWriter.MaxAge, logWriter.Compress)
	}
	dir := filepath.Dir(logWriter.Filename)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()
	if err = watcher.Add(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	oldName := "main-" + now.Add(-8*24*time.Hour).Format("2006-01-02T15-04-05.000") + ".log"
	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("main-%s.log", now.Add(-time.Duration(i+1)*time.Minute).Format("2006-01-02T15-04-05.000"))
		if i == 0 {
			name = oldName
		}
		if err = os.WriteFile(filepath.Join(dir, name), []byte("synthetic diagnostic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = logWriter.Write([]byte("synthetic current\n")); err != nil {
		t.Fatal(err)
	}
	if err = logWriter.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Lumberjack's mill is asynchronous: filesystem events drive this bounded wait.
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		entries, errRead := os.ReadDir(dir)
		if errRead != nil {
			t.Fatal(errRead)
		}
		backups, raw, old := 0, 0, false
		for _, entry := range entries {
			name := entry.Name()
			if strings.HasPrefix(name, "main-") {
				backups++
				if !strings.HasSuffix(name, ".gz") {
					raw++
				}
				if name == oldName || name == oldName+".gz" {
					old = true
				}
			}
		}
		if backups == 19 && raw == 0 && !old {
			break
		}
		select {
		case _, ok := <-watcher.Events:
			if !ok {
				t.Fatal("filesystem watcher closed")
			}
		case errWatch := <-watcher.Errors:
			t.Fatal(errWatch)
		case <-deadline.C:
			t.Fatalf("retention did not settle: backups=%d raw=%d old=%t", backups, raw, old)
		}
	}
}
