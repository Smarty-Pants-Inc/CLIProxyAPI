package tui

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// openBrowser opens the specified URL in the user's default browser.
func openBrowser(target string) error {
	parsed, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("unsafe browser URL: %w", err)
	}
	if err = validateHTTPDestination(parsed); err != nil {
		return fmt.Errorf("unsafe browser URL: %w", err)
	}
	url := parsed.String()
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
