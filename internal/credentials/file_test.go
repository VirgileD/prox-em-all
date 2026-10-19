package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	caCertificate, caKey := newTestCA(t, true)
	_, otherKey := newTestCA(t, true)
	leafCertificate, leafKey := newTestCA(t, false)
	ca := func(certificate, key string) string {
		return "caCertificate: |\n" + indent(certificate) + "caKey: |\n" + indent(key)
	}
	validCA := ca(caCertificate, caKey)
	validServer := `
servers:
  - host: API.Example.com
    replacements:
      - { header: authorization, placeholder: PLACEHOLDER, value: secret }
`
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"valid", validCA + validServer, ""},
		{"no CA", validServer, "caCertificate and caKey"},
		{"key of another CA", ca(caCertificate, otherKey) + validServer, "caCertificate and caKey"},
		{"not a CA", ca(leafCertificate, leafKey) + validServer, "not a CA certificate"},
		{"unknown setting", validCA + "\nserver: []\n", "field server not found"},
		{"no host", validCA + "\nservers: [{replacements: [{header: a, placeholder: b, value: c}]}]\n", "host is required"},
		{"no replacements", validCA + "\nservers: [{host: example.com}]\n", "replacements are required"},
		{"no placeholder", validCA + "\nservers: [{host: example.com, replacements: [{header: a, value: c}]}]\n", "header, placeholder and value are required"},
		{"listed twice", validCA + "\nservers:\n" +
			"  - {host: example.com, port: 443, replacements: [{header: a, placeholder: b, value: c}]}\n" +
			"  - {host: EXAMPLE.com, replacements: [{header: a, placeholder: b, value: c}]}\n",
			"server example.com:443 is listed twice"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			injector, err := Parse([]byte(test.yaml))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("got error %v, want one containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !injector.Intercepts("api.example.com", 443) {
				t.Error("api.example.com:443 is not intercepted: host not lowercased, or port not 443 by default")
			}
			if got := injector.servers["api.example.com:443"].Replacements[0].Header; got != "Authorization" {
				t.Errorf("got header %q, want the canonical Authorization", got)
			}
		})
	}
}

// newTestCA returns a PEM certificate, a CA one when isCA is set, and its PEM key.
func newTestCA(t *testing.T, isCA bool) (certificatePEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certificatePEM, keyPEM
}

// indent indents text as a YAML block scalar of a top-level setting.
func indent(text string) string {
	return "  " + strings.ReplaceAll(strings.TrimSuffix(text, "\n"), "\n", "\n  ") + "\n"
}
