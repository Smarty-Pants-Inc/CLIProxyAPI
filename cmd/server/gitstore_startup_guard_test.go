package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const gitStoreDisabledMessage = "git token store disabled in this build: recovery can bypass the Codex credential lock (smarty-dev#12467)"

type startupOfflineTransport struct{}

func (startupOfflineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("external network disabled in startup test")
}

func TestServerGitStoreStartupGuard(t *testing.T) {
	if os.Getenv("CPA_STARTUP_TEST_HELPER") == "1" {
		// Run the real entry point in a fresh process, without inherited test flags
		// or any external updater traffic. The normal password keep-alive shutdown
		// bounds a successful server run without sending a process signal.
		http.DefaultTransport = startupOfflineTransport{}
		flag.CommandLine = flag.NewFlagSet("server", flag.ExitOnError)
		os.Args = []string{"server", "--config", "config.yaml", "--local-model", "--password", "startup-test-password"}
		main()
		return
	}

	for _, source := range []string{"uppercase env", "lowercase env", "dotenv"} {
		t.Run(source, func(t *testing.T) {
			root := t.TempDir()
			authDir, gitRoot := filepath.Join(root, "auths"), filepath.Join(root, "git-workspace")
			writeStartupTestConfig(t, root, authDir, 8317)
			command := startupTestCommand(t, root)
			remote := filepath.Join(root, "missing-remote.git")
			switch source {
			case "uppercase env":
				command.Env = append(command.Env, "GITSTORE_GIT_URL="+remote, "GITSTORE_LOCAL_PATH="+gitRoot)
			case "lowercase env":
				command.Env = append(command.Env, "gitstore_git_url="+remote, "gitstore_local_path="+gitRoot)
			case "dotenv":
				data := fmt.Sprintf("GITSTORE_GIT_URL=%s\nGITSTORE_LOCAL_PATH=%s\n", remote, gitRoot)
				if errWrite := os.WriteFile(filepath.Join(root, ".env"), []byte(data), 0o600); errWrite != nil {
					t.Fatal(errWrite)
				}
			}
			output, errRun := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(errRun, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("git-configured startup error = %v, want exit 1; output:\n%s", errRun, output)
			}
			if !bytes.Contains(output, []byte(gitStoreDisabledMessage)) {
				t.Fatalf("missing typed startup error: %s", output)
			}
			if bytes.Contains(output, []byte("API server started successfully")) {
				t.Fatalf("server started with git store configured: %s", output)
			}
			for _, path := range []string{authDir, gitRoot} {
				if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
					t.Errorf("startup touched store path %s: %v", path, errStat)
				}
			}
		})
	}

	t.Run("default file store serves HTTP", func(t *testing.T) {
		root := t.TempDir()
		listener, errListen := net.Listen("tcp", "127.0.0.1:0")
		if errListen != nil {
			t.Fatal(errListen)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if errClose := listener.Close(); errClose != nil {
			t.Fatal(errClose)
		}
		authDir := filepath.Join(root, "auths")
		writeStartupTestConfig(t, root, authDir, port)
		command := startupTestCommand(t, root)
		stdout, errPipe := command.StdoutPipe()
		if errPipe != nil {
			t.Fatal(errPipe)
		}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if errStart := command.Start(); errStart != nil {
			t.Fatal(errStart)
		}
		var output strings.Builder
		scanner := bufio.NewScanner(stdout)
		var probeErr error
		probed := false
		for scanner.Scan() {
			line := scanner.Text()
			output.WriteString(line + "\n")
			// The listener banner precedes the initial watcher/config reload.
			// Probe only after the file store and watcher have finished startup.
			if !probed && strings.Contains(line, "file watcher started for config and auth directory changes") {
				probed = true
				response, errGet := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
				if errGet != nil {
					probeErr = errGet
					continue
				}
				body, errRead := io.ReadAll(response.Body)
				errClose := response.Body.Close()
				if response.StatusCode != http.StatusOK || errRead != nil || errClose != nil || !bytes.Contains(body, []byte("CLI Proxy API Server")) {
					probeErr = fmt.Errorf("HTTP probe status=%d body=%s read=%v close=%v", response.StatusCode, body, errRead, errClose)
				}
			}
		}
		errScan, errWait := scanner.Err(), command.Wait()
		if errScan != nil || errWait != nil || !probed || probeErr != nil {
			t.Fatalf("default file startup: scan=%v wait=%v probed=%v probe=%v\n%s\n%s", errScan, errWait, probed, probeErr, output.String(), stderr.String())
		}
		if strings.Contains(output.String()+stderr.String(), gitStoreDisabledMessage) {
			t.Fatal("default file store was blocked by git guard")
		}
		if info, errStat := os.Stat(authDir); errStat != nil || !info.IsDir() {
			t.Fatalf("default file store auth directory: %v", errStat)
		}
	})
}

func TestValidateTokenStoreStartupReturnsTypedError(t *testing.T) {
	errStartup := validateTokenStoreStartup(true, false, false)
	var disabled *gitTokenStoreDisabledError
	if !errors.As(errStartup, &disabled) || errStartup.Error() != gitStoreDisabledMessage {
		t.Fatalf("git startup error = %T %v, want typed disabled error", errStartup, errStartup)
	}
	if errOther := validateTokenStoreStartup(false, false, false); errOther != nil {
		t.Fatalf("non-git backend rejected: %v", errOther)
	}
}

func writeStartupTestConfig(t *testing.T, root, authDir string, port int) {
	t.Helper()
	data := fmt.Sprintf("host: 127.0.0.1\nport: %d\nauth-dir: %q\napi-keys: [startup-test-key]\nremote-management:\n  disable-control-panel: true\n  disable-auto-update-panel: true\n", port, authDir)
	if errWrite := os.WriteFile(filepath.Join(root, "config.yaml"), []byte(data), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
}

func startupTestCommand(t *testing.T, root string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestServerGitStoreStartupGuard$")
	command.Dir = root
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "GITSTORE_") || strings.HasPrefix(upper, "PGSTORE_") || strings.HasPrefix(upper, "OBJECTSTORE_") || upper == "HOME_JWT" || upper == "DEPLOY" || upper == "CPA_STARTUP_TEST_HELPER" {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "CPA_STARTUP_TEST_HELPER=1")
	return command
}
