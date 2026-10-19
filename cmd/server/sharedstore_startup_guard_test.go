package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	postgresStoreDisabledMessage = "postgres token store disabled in this build: shared-store refresh persistence can resurrect deleted credentials (smarty-dev#13064)"
	objectStoreDisabledMessage   = "object token store disabled in this build: shared-store refresh persistence can resurrect deleted credentials (smarty-dev#13064)"
)

func TestValidateSharedTokenStoreStartupReturnsTypedError(t *testing.T) {
	for _, backend := range []struct {
		name     string
		git      bool
		postgres bool
		object   bool
		message  string
	}{
		{name: "postgres", postgres: true, message: postgresStoreDisabledMessage},
		{name: "object", object: true, message: objectStoreDisabledMessage},
		{name: "postgres before object", postgres: true, object: true, message: postgresStoreDisabledMessage},
		{name: "postgres before git", postgres: true, git: true, message: postgresStoreDisabledMessage},
		{name: "object before git", object: true, git: true, message: objectStoreDisabledMessage},
		{name: "postgres before both", postgres: true, object: true, git: true, message: postgresStoreDisabledMessage},
	} {
		t.Run(backend.name, func(t *testing.T) {
			errStartup := validateTokenStoreStartup(backend.git, backend.postgres, backend.object)
			var disabled *sharedTokenStoreDisabledError
			if !errors.As(errStartup, &disabled) || errStartup.Error() != backend.message {
				t.Fatalf("shared-store startup error = %T %v, want typed disabled error: %s", errStartup, errStartup, backend.message)
			}
		})
	}
}

func TestServerSharedStoreStartupGuard(t *testing.T) {
	for _, backend := range []struct {
		name      string
		selector  string
		value     string
		localPath string
		workspace string
		message   string
	}{
		{
			name: "postgres", selector: "PGSTORE_DSN", value: "startup-test-invalid-dsn",
			localPath: "PGSTORE_LOCAL_PATH", workspace: "pgstore", message: postgresStoreDisabledMessage,
		},
		{
			name: "object", selector: "OBJECTSTORE_ENDPOINT", value: "http://127.0.0.1:1",
			localPath: "OBJECTSTORE_LOCAL_PATH", workspace: "objectstore", message: objectStoreDisabledMessage,
		},
	} {
		t.Run(backend.name, func(t *testing.T) {
			for _, source := range []string{"uppercase env", "lowercase env", "dotenv"} {
				t.Run(source, func(t *testing.T) {
					root := t.TempDir()
					authDir, storeRoot := filepath.Join(root, "auths"), filepath.Join(root, "remote-workspace")
					writeStartupTestConfig(t, root, authDir, 8317)
					command := startupTestCommand(t, root)
					selector, localPath := backend.selector, backend.localPath
					switch source {
					case "lowercase env":
						selector, localPath = strings.ToLower(selector), strings.ToLower(localPath)
					case "dotenv":
						data := fmt.Sprintf("%s=%s\n%s=%s\n", selector, backend.value, localPath, storeRoot)
						if errWrite := os.WriteFile(filepath.Join(root, ".env"), []byte(data), 0o600); errWrite != nil {
							t.Fatal(errWrite)
						}
					}
					if source != "dotenv" {
						command.Env = append(command.Env, selector+"="+backend.value, localPath+"="+storeRoot)
					}
					output, errRun := command.CombinedOutput()
					var exitErr *exec.ExitError
					if !errors.As(errRun, &exitErr) || exitErr.ExitCode() != 1 {
						t.Fatalf("%s-configured startup error = %v, want exit 1; output:\n%s", backend.name, errRun, output)
					}
					if !bytes.Contains(output, []byte(backend.message)) {
						t.Fatalf("missing shared-store startup error: %s", output)
					}
					if bytes.Contains(output, []byte("API server started successfully")) {
						t.Fatalf("server started with %s store configured: %s", backend.name, output)
					}
					for _, path := range []string{authDir, storeRoot, filepath.Join(root, backend.workspace)} {
						if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
							t.Errorf("startup touched store path %s: %v", path, errStat)
						}
					}
				})
			}
		})
	}
}
