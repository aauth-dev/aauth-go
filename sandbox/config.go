// Package sandbox runs every AAuth role from aauth-go together for
// development: an agent provider, a person server, an access server and
// two demo resources, on real HTTPS origins under a development
// certificate authority, with consent pages, a message trace, and a
// signing helper for HTTP clients that cannot sign (Postman, curl).
//
// The sandbox is a development tool. Its keys, certificate authority and
// automatic consent are for local use only.
package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Role names.
const (
	RoleAP       = "ap"
	RolePS       = "ps"
	RoleAS       = "as"
	RoleResource = "resource"
	RoleDocs     = "docs"
)

// Roles lists the roles in display order.
var Roles = []string{RoleAP, RolePS, RoleAS, RoleResource, RoleDocs}

// Consent modes.
const (
	// ConsentAuto approves every interaction as soon as it is created.
	ConsentAuto = "auto"
	// ConsentManual waits for a person at the interaction page, or for
	// a headless approval at /sandbox/approve.
	ConsentManual = "manual"
)

// DefaultDomain is the parent domain of the default role host names. The
// .test top-level domain is reserved for testing (RFC 6761).
const DefaultDomain = "aauth.test"

// DefaultPerson is the person every approval acts for.
const DefaultPerson = "alice"

// Config configures a Sandbox. Zero values take defaults.
type Config struct {
	// StateDir holds the certificate authority and role keys (default
	// ~/.aauth-sandbox).
	StateDir string
	// Domain is the parent domain of the role host names (default
	// aauth.test); role hosts are <role>.<Domain> unless Hosts sets one.
	Domain string
	// Hosts overrides a role's host name.
	Hosts map[string]string
	// Remote maps a role to an external implementation's https origin;
	// the sandbox does not serve that role and calls the URL instead.
	Remote map[string]string
	// Consent is ConsentAuto (default) or ConsentManual.
	Consent string
	// Person is the person approvals act for (default alice).
	Person string
	// TraceSize bounds the trace (default 2000 exchanges).
	TraceSize int
}

func (c Config) withDefaults(home string) (Config, error) {
	if c.StateDir == "" {
		c.StateDir = filepath.Join(home, ".aauth-sandbox")
	}
	if c.Domain == "" {
		c.Domain = DefaultDomain
	}
	if c.Consent == "" {
		c.Consent = ConsentAuto
	}
	if c.Consent != ConsentAuto && c.Consent != ConsentManual {
		return c, fmt.Errorf("sandbox: consent must be %q or %q, not %q", ConsentAuto, ConsentManual, c.Consent)
	}
	if c.Person == "" {
		c.Person = DefaultPerson
	}
	if c.TraceSize <= 0 {
		c.TraceSize = 2000
	}
	hosts := make(map[string]string, len(Roles))
	for _, r := range Roles {
		hosts[r] = r + "." + c.Domain
	}
	for r, h := range c.Hosts {
		if !knownRole(r) {
			return c, fmt.Errorf("sandbox: unknown role %q", r)
		}
		hosts[r] = strings.ToLower(h)
	}
	c.Hosts = hosts
	for r, u := range c.Remote {
		if !knownRole(r) {
			return c, fmt.Errorf("sandbox: unknown role %q", r)
		}
		if !strings.HasPrefix(u, "https://") {
			return c, fmt.Errorf("sandbox: remote %s must be an https origin, not %q", r, u)
		}
	}
	if len(c.Remote) == len(Roles) {
		return c, errors.New("sandbox: every role is remote; nothing to serve")
	}
	return c, nil
}

func knownRole(r string) bool {
	for _, k := range Roles {
		if k == r {
			return true
		}
	}
	return false
}

// URL returns a role's origin: the remote URL, or https://<host>.
func (c Config) URL(role string) string {
	if u, ok := c.Remote[role]; ok {
		return strings.TrimSuffix(u, "/")
	}
	return "https://" + c.Hosts[role]
}

// Local reports whether the sandbox serves role.
func (c Config) Local(role string) bool {
	_, remote := c.Remote[role]
	return !remote
}

// LocalHosts returns the host names of the roles the sandbox serves, in
// role order.
func (c Config) LocalHosts() []string {
	var hosts []string
	for _, r := range Roles {
		if c.Local(r) {
			hosts = append(hosts, c.Hosts[r])
		}
	}
	return hosts
}

// HostsLine returns the /etc/hosts line that points the local role names
// at this machine.
func (c Config) HostsLine() string {
	return "127.0.0.1 " + strings.Join(c.LocalHosts(), " ")
}

// WithDefaults returns cfg with defaults applied and checked, as New
// applies them.
func (c Config) WithDefaults() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil && c.StateDir == "" {
		return c, fmt.Errorf("sandbox: no state directory and no home directory: %w", err)
	}
	return c.withDefaults(home)
}
