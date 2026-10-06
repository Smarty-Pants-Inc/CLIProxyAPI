package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type round4PanicParser struct{ panicOnce bool }

func (p *round4PanicParser) ParseAuth(_ context.Context, req pluginapi.AuthParseRequest) (*coreauth.Auth, bool, error) {
	if p.panicOnce {
		p.panicOnce = false
		panic("injected one-shot auth parser panic")
	}
	return &coreauth.Auth{ID: "round4-auth", Provider: "round4", FileName: "fixture.json"}, true, nil
}
func TestRound4ParserPanicDoesNotPoisonRescan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	authPath := filepath.Join(dir, "fixture.json")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("auth-dir: %q\noauth-excluded-models: {codex: [new]}\n", dir)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authPath, []byte(`{"type":"round4"}`), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(path, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Stop(); err != nil {
			t.Error(err)
		}
	}()
	w.SetPluginAuthParser(&round4PanicParser{panicOnce: true})
	w.lastAuthHashes = map[string]string{"previous": "retained"}
	previousYAML := []byte(fmt.Sprintf("auth-dir: %q\noauth-excluded-models: {codex: [old]}\n", filepath.Join(dir, "previous-auth")))
	w.config, err = config.ParseConfigBytes(previousYAML)
	if err != nil {
		t.Fatal(err)
	}
	w.oldConfigYaml = previousYAML
	w.currentAuths = map[string]*coreauth.Auth{"previous": {ID: "previous", Provider: "codex"}}
	if w.reloadConfig() {
		t.Fatal("panicking rescan reported applied")
	}
	if w.currentAuths["previous"] == nil {
		t.Error("failed parser rescan prematurely filtered current auth candidates")
	}
	if !w.authRescanMu.TryLock() {
		t.Fatal("parser panic permanently retained authRescanMu")
	}
	w.authRescanMu.Unlock()
	if w.lastAuthHashes["previous"] != "retained" || w.lastConfigHash != "" {
		t.Fatal("failed scan committed partial bookkeeping")
	}
	if !w.reloadConfig() {
		t.Fatal("rescan after panic did not complete")
	}
	norm := w.normalizeAuthPath(authPath)
	if _, ok := w.lastAuthHashes[norm]; !ok {
		t.Fatal("retry did not commit auth hash")
	}
	if err := os.Remove(authPath); err != nil {
		t.Fatal(err)
	}
	w.removeClient(authPath)
	if _, ok := w.lastAuthHashes[norm]; ok {
		t.Fatal("incremental removal left revoked file in cache")
	}
	if !w.reloadConfig() {
		t.Fatal("post-removal rescan failed")
	}
	if len(w.lastAuthHashes) != 0 || len(w.fileAuthsByPath) != 0 {
		t.Fatal("post-removal state incoherent")
	}
}
