package management

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestSetSourceAuthFileDisabledDoesNotRecreateDeletedSource(t *testing.T) {
	t.Run("external deletion after read wins", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source.json")
		if errWrite := os.WriteFile(path, []byte(`{"type":"plugin-test","access_token":"token"}`), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		read, resume := make(chan struct{}), make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(resume) }) }
		defer release()
		done := make(chan error, 1)
		go func() {
			done <- setSourceAuthFileDisabledWithReader(path, true, func(path string) ([]byte, error) {
				data, errRead := os.ReadFile(path)
				close(read)
				<-resume
				return data, errRead
			})
		}()
		<-read
		// An uncooperative external actor can unlink even while the source
		// lock is held. The pre-write existence fence must still reject it.
		if errRemove := os.Remove(path); errRemove != nil {
			t.Fatal(errRemove)
		}
		release()
		if errUpdate := <-done; !os.IsNotExist(errUpdate) {
			t.Fatalf("source status update error = %v, want missing source", errUpdate)
		}
		if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
			t.Fatalf("source status update recreated revoked credential: %v", errStat)
		}
	})

	t.Run("normal source update shares credential lock", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source.json")
		if errWrite := os.WriteFile(path, []byte(`{"type":"plugin-test","access_token":"token"}`), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		locked, unlock := make(chan struct{}), make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(unlock) }) }
		defer release()
		lockDone := make(chan error, 1)
		go func() {
			lockDone <- codex.WithFileLock(path, func() error {
				close(locked)
				<-unlock
				return nil
			})
		}()
		<-locked
		updateDone := make(chan error, 1)
		go func() { updateDone <- setSourceAuthFileDisabled(path, true) }()
		select {
		case errUpdate := <-updateDone:
			release()
			<-lockDone
			t.Fatalf("source status update bypassed credential lock: %v", errUpdate)
		case <-time.After(100 * time.Millisecond): // Bounded lock-wait observation, not a TTL assertion.
		}
		release()
		if errLock := <-lockDone; errLock != nil {
			t.Fatal(errLock)
		}
		if errUpdate := <-updateDone; errUpdate != nil {
			t.Fatal(errUpdate)
		}
	})
}
