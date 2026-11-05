// Package ctsurl checks a CTS base URL that replaces a workspace region's.
package ctsurl

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// Override returns u with a trailing slash, matching auth.CRN.CTSURL, after
// checking that it is an absolute HTTPS URL without credentials, query or
// fragment. HTTP is accepted only for a loopback host, such as a local fake.
func Override(u *url.URL) (string, error) {
	loopback := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback()
	if (u.Scheme != "https" && (u.Scheme != "http" || !loopback)) || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("CTS URL must be an HTTPS URL, or HTTP to a loopback host, without credentials, query or fragment")
	}

	override := *u
	if !strings.HasSuffix(override.Path, "/") {
		override.Path += "/"
	}

	return override.String(), nil
}
