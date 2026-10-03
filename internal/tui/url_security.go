package tui

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateHTTPDestination runs before credentials or OS handlers see a destination.
func validateHTTPDestination(u *url.URL) error {
	if u == nil || !u.IsAbs() || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("expected an absolute HTTP(S) URL with a host and no userinfo or fragment")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("HTTPS is required for remote destinations")
}

func validateManagementRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many management redirects")
	}
	if err := validateHTTPDestination(req.URL); err != nil {
		return err
	}
	if len(via) > 0 {
		previous := via[len(via)-1].URL
		if strings.EqualFold(previous.Scheme, "https") && !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("management HTTPS downgrade rejected")
		}
		if !strings.EqualFold(via[0].URL.Host, req.URL.Host) {
			return fmt.Errorf("cross-origin management redirect rejected")
		}
	}
	return nil
}
