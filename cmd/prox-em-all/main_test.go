package main

import (
	"os"
	"strings"
	"testing"

	"github.com/VirgileD/prox-em-all/internal/config"
	"github.com/VirgileD/prox-em-all/internal/credentials"
	"github.com/VirgileD/prox-em-all/internal/rules"
)

func TestExampleConfigIsValid(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Compile(cfg.Rules); err != nil {
		t.Fatal(err)
	}
}

// The example holds no real CA: parsing must get past the settings, then fail on the CA.
func TestExampleCredentialsHaveKnownSettings(t *testing.T) {
	data, err := os.ReadFile("../../credentials.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = credentials.Parse(data)
	if err == nil || !strings.HasPrefix(err.Error(), "caCertificate and caKey:") {
		t.Fatalf("got error %v, want only the example CA rejected", err)
	}
}
