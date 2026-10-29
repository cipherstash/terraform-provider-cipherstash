// Package useragent identifies provider builds to CipherStash.
package useragent

import "runtime/debug"

// Value is "terraform-provider-cipherstash/" followed by the first 12
// characters of the build's VCS revision, or
// "terraform-provider-cipherstash/devel" when the binary has none, such as in
// tests.
var Value = "terraform-provider-cipherstash/" + revision()

func revision() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && len(setting.Value) >= 12 {
				return setting.Value[:12]
			}
		}
	}

	return "devel"
}
