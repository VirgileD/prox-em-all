package main

import (
	"testing"

	"github.com/VirgileD/prox-em-all/internal/config"
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
