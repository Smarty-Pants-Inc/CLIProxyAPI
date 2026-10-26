package management

import (
	"compress/gzip"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Keep: PR #178's real compression/management-reader contract, including cursors
// issued before rotation and cursors pointing inside a compressed backup.
func TestGetLogsLumberjackCompressedRotation(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, defaultLogFileName)
	writer := &lumberjack.Logger{Filename: mainPath, MaxSize: 10, Compress: true}
	defer func() { _ = writer.Close() }()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = watcher.Close() }()
	if err = watcher.Add(dir); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"2026-10-01 10:00:01 first " + strings.Repeat("synthetic ", 40),
		"2026-10-01 10:00:02 second " + strings.Repeat("synthetic ", 40),
		"2026-10-01 10:00:03 third " + strings.Repeat("synthetic ", 40),
		"2026-10-01 10:00:04 fourth " + strings.Repeat("synthetic ", 40),
		"2026-10-01 10:00:05 active",
	}
	write := func(data string) {
		t.Helper()
		if _, err := io.WriteString(writer, data); err != nil {
			t.Fatal(err)
		}
	}
	h := newLogsTestHandler(dir, true)
	write(strings.Join(lines[:2], "\n") + "\n")
	initial := performGetLogs(t, h, "/v0/management/logs?limit=1")
	write(strings.Join(lines[2:4], "\n") + "\n")
	if err = writer.Rotate(); err != nil {
		t.Fatal(err)
	}
	// Lumberjack removes the original backup only after closing the gzip output.
	// Observe that completion event instead of sleeping or polling for a .gz name.
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
waitCompression:
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				t.Fatal("watcher closed before compression completed")
			}
			if event.Op&fsnotify.Remove != 0 && event.Name != mainPath && strings.HasSuffix(event.Name, ".log") {
				break waitCompression
			}
		case err := <-watcher.Errors:
			t.Fatal(err)
		case <-timer.C:
			t.Fatal("lumberjack did not finish compression")
		}
	}
	gzPaths, err := filepath.Glob(filepath.Join(dir, "main-*.log.gz"))
	if err != nil || len(gzPaths) != 1 {
		t.Fatalf("compressed backups = %v, %v", gzPaths, err)
	}
	write(lines[4] + "\n")
	assertLines := func(got logsAPIResponse, want []string) {
		t.Helper()
		if !reflect.DeepEqual(got.Lines, want) || got.CursorReset {
			t.Fatalf("response = %+v, want lines %q without reset", got, want)
		}
	}
	tail := performGetLogs(t, h, "/v0/management/logs?limit=3")
	assertLines(tail, lines[2:])
	if tail.LineCount != 3 {
		t.Fatalf("tail count = %d", tail.LineCount)
	}
	cursor := initial.NextCursor
	for _, want := range lines[2:] {
		response := performGetLogs(t, h, "/v0/management/logs?limit=1&cursor="+url.QueryEscape(cursor))
		assertLines(response, []string{want})
		cursor = response.NextCursor
	}
	full := performGetLogs(t, h, "/v0/management/logs")
	assertLines(full, lines)
	if full.LineCount != len(lines) {
		t.Fatalf("full count = %d", full.LineCount)
	}
	// Exercise a latest-file cursor that itself belongs to gzip (no active log).
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(mainPath); err != nil {
		t.Fatal(err)
	}
	backupTail := performGetLogs(t, h, "/v0/management/logs?limit=2")
	assertLines(backupTail, lines[2:4])
	decoded, err := decodeLogCursor(backupTail.NextCursor)
	if err != nil || !strings.HasSuffix(decoded.File, ".gz") {
		t.Fatalf("gzip cursor = %+v, %v", decoded, err)
	}
	assertLines(performGetLogs(t, h, "/v0/management/logs?cursor="+url.QueryEscape(backupTail.NextCursor)), []string{})
}

// Keep: data safety at the compressed file boundary; reuse the exact complete
// line and fingerprint logic used for ordinary files, including CRLF/partials.
func TestCompressedLogReadParity(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "main-2026-10-01T10-00-00.log")
	compressed := plain + ".gz"
	data := "2026-10-01 10:00:01 one\r\n\ntwo\npartial"
	if err := os.WriteFile(plain, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(compressed)
	if err != nil {
		t.Fatal(err)
	}
	zr := gzip.NewWriter(file)
	if _, err := io.WriteString(zr, data); err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, 1, 2, 3} {
		a, err := readTailLogLines(plain, limit)
		if err != nil {
			t.Fatal(err)
		}
		b, err := readTailLogLines(compressed, limit)
		if err != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("limit %d: plain %+v gzip %+v, %v", limit, a, b, err)
		}
	}
	raw, err := newLogCursor(plain, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := decodeLogCursor(raw)
	if err != nil {
		t.Fatal(err)
	}
	// A partially written gzip sibling must not be read or duplicate the raw log.
	if err := os.WriteFile(compressed, []byte("in-progress gzip"), 0600); err != nil {
		t.Fatal(err)
	}
	full := performGetLogs(t, newLogsTestHandler(dir, true), "/v0/management/logs")
	if !reflect.DeepEqual(full.Lines, []string{"2026-10-01 10:00:01 one", "", "two", "partial"}) {
		t.Fatalf("compression in progress lines = %q", full.Lines)
	}
	// Restore the completed gzip before checking a cursor issued for its raw name.
	file, err = os.Create(compressed)
	if err != nil {
		t.Fatal(err)
	}
	zr = gzip.NewWriter(file)
	if _, err := io.WriteString(zr, data); err != nil {
		t.Fatal(err)
	}
	if err := zr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	index, found, err := locateLogCursorFile([]string{compressed}, cursor)
	if err != nil || !found || index != 0 {
		t.Fatalf("cursor after asynchronous compression = %d, %t, %v", index, found, err)
	}
}
