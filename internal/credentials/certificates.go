package credentials

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// certificateLifetime is the validity of the certificates presented to the
// clients. They are made again when they expire.
const certificateLifetime = 24 * time.Hour

// certificateMaker makes the certificates presented to the clients, signed by
// the CA, and keeps them until they are about to expire.
type certificateMaker struct {
	ca  tls.Certificate
	key *ecdsa.PrivateKey // shared by all the certificates

	mu           sync.Mutex
	certificates map[string]*tls.Certificate // by host
}

func newCertificateMaker(ca tls.Certificate) (*certificateMaker, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &certificateMaker{ca: ca, key: key, certificates: make(map[string]*tls.Certificate)}, nil
}

// certificate returns a valid certificate for host.
func (m *certificateMaker) certificate(host string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Renew an hour early: a client may check the certificate a little later.
	if certificate, found := m.certificates[host]; found && time.Now().Add(time.Hour).Before(certificate.Leaf.NotAfter) {
		return certificate, nil
	}
	certificate, err := m.make(host)
	if err != nil {
		return nil, fmt.Errorf("make certificate for %s: %w", host, err)
	}
	m.certificates[host] = certificate
	return certificate, nil
}

func (m *certificateMaker) make(host string) (*tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour), // tolerates clients whose clock is a little late
		NotAfter:     now.Add(certificateLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if template.NotAfter.After(m.ca.Leaf.NotAfter) {
		template.NotAfter = m.ca.Leaf.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.ca.Leaf, &m.key.PublicKey, m.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: m.key, Leaf: leaf}, nil
}
