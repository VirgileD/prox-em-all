// Package credentials replaces placeholder credentials in the HTTPS requests
// sent to configured servers, so that clients never hold the real secrets.
// It intercepts the TLS connections to these servers with certificates signed
// by a CA the clients trust.
package credentials

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// File is the content of the YAML credentials file.
type File struct {
	// CACertificate and CAKey, in PEM, sign the certificates presented to the
	// clients for the intercepted servers.
	CACertificate string `yaml:"caCertificate"`
	CAKey         string `yaml:"caKey"`

	// Servers are the servers whose requests get their credentials replaced.
	Servers []Server `yaml:"servers"`
}

// Server is a server whose requests get their credentials replaced.
type Server struct {
	// Host is the server name the clients ask for in TLS (SNI), matched exactly.
	Host string `yaml:"host"`

	// Port is the server's TCP port. Default: 443.
	Port uint16 `yaml:"port"`

	Replacements []Replacement `yaml:"replacements"`
}

// Replacement replaces Placeholder by Value wherever it appears in the Header
// of a request.
type Replacement struct {
	Header      string `yaml:"header"`
	Placeholder string `yaml:"placeholder"`
	Value       string `yaml:"value"`
}

// Load reads the credentials file at path and returns the Injector it describes.
func Load(path string) (*Injector, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		slog.Warn("credentials file is readable by other users than its owner", "path", path, "mode", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	injector, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return injector, nil
}

// Parse decodes and validates a YAML credentials file. Unknown settings are
// rejected, so that a typo does not silently leave a credential out.
func Parse(data []byte) (*Injector, error) {
	var file File
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	ca, err := tls.X509KeyPair([]byte(file.CACertificate), []byte(file.CAKey))
	if err != nil {
		return nil, fmt.Errorf("caCertificate and caKey: %w", err)
	}
	if !ca.Leaf.IsCA {
		return nil, errors.New("caCertificate is not a CA certificate")
	}
	servers, err := validateServers(file.Servers)
	if err != nil {
		return nil, err
	}
	return newInjector(ca, servers)
}

// validateServers checks the servers and returns them by address
// ("host:port"), with defaults applied and names normalized.
func validateServers(servers []Server) (map[string]Server, error) {
	byAddress := make(map[string]Server)
	for i, server := range servers {
		server.Host = strings.ToLower(server.Host)
		if server.Host == "" {
			return nil, fmt.Errorf("servers[%d]: host is required", i)
		}
		if server.Port == 0 {
			server.Port = 443
		}
		if len(server.Replacements) == 0 {
			return nil, fmt.Errorf("server %s: replacements are required", server.Host)
		}
		for j, replacement := range server.Replacements {
			if replacement.Header == "" || replacement.Placeholder == "" || replacement.Value == "" {
				return nil, fmt.Errorf("server %s: replacements[%d]: header, placeholder and value are required", server.Host, j)
			}
			server.Replacements[j].Header = http.CanonicalHeaderKey(replacement.Header)
		}
		address := serverAddress(server.Host, server.Port)
		if _, duplicate := byAddress[address]; duplicate {
			return nil, fmt.Errorf("server %s is listed twice", address)
		}
		byAddress[address] = server
	}
	return byAddress, nil
}
