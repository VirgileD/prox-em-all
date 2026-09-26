// Copyright (C) 2013 Ryan A. Chapman. All rights reserved.
// Use of this source code is governed by the BSD-style license in the LICENSE file.
// prox-em-all started as a fork of https://github.com/ryanchapman/go-any-proxy.

// Command prox-em-all transparently forwards the TCP connections of a Linux
// host, or of the hosts routed through it, directly or through upstream HTTP
// and SOCKS5 proxies chosen by destination. See README.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // serves /debug/pprof/ on the debug endpoint
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/VirgileD/prox-em-all/internal/config"
	"github.com/VirgileD/prox-em-all/internal/dnsproxy"
	"github.com/VirgileD/prox-em-all/internal/hostcache"
	"github.com/VirgileD/prox-em-all/internal/netfilter"
	"github.com/VirgileD/prox-em-all/internal/rules"
	"github.com/VirgileD/prox-em-all/internal/tcpproxy"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("c", "/etc/prox-em-all/config.yaml", "path of the configuration `file`")
	cleanup := flag.Bool("cleanup", false, "remove the iptables rules left by a previous run, then exit")
	showVersion := flag.Bool("version", false, "print the version, then exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-c file] [-cleanup] [-version]\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Transparently forwards TCP connections through upstream proxies, using iptables.")
		fmt.Fprintln(flag.CommandLine.Output(), "Needs root privileges, or the CAP_NET_ADMIN capability.")
		fmt.Fprintln(flag.CommandLine.Output())
		flag.PrintDefaults()
	}
	flag.Parse()

	var err error
	switch {
	case *showVersion:
		fmt.Printf("prox-em-all %s (%s)\n", version, runtime.Version())
	case *cleanup:
		err = netfilter.Remove()
	default:
		err = run(*configPath)
	}
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

// run runs the proxy until it receives SIGINT or SIGTERM.
func run(configPath string) error {
	// Catch the signals first, and until run returns: a signal must never
	// kill the process while iptables rules are being installed or removed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel})))
	slog.Info("starting prox-em-all", "version", version, "config", configPath)

	routingRules, err := rules.Compile(cfg.Rules)
	if err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	hostnames := hostcache.New(65536)
	dialer := netfilter.Dialer(cfg.IPTableMark)

	// The TCP and DNS proxies share the listen endpoint.
	tcpListener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(cfg.ListenEndpoint))
	if err != nil {
		return err
	}
	defer tcpListener.Close()
	udpConn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(cfg.ListenEndpoint))
	if err != nil {
		return err
	}
	defer udpConn.Close()

	tcpProxy := &tcpproxy.Server{
		Rules:               routingRules,
		Hostnames:           hostnames,
		Dialer:              dialer,
		OriginalDestination: netfilter.OriginalDestination,
		RelayRedirects:      cfg.RelayingRedirectResponse,
	}
	dnsProxy := &dnsproxy.Server{
		Hostnames: hostnames,
		Dialer:    dialer,
		OriginalDestination: func(client netip.AddrPort) (netip.AddrPort, error) {
			return netfilter.OriginalDNSServer(client, cfg.ListenEndpoint.Port())
		},
	}
	stopped := make(chan error, 2)
	go func() { stopped <- tcpProxy.Serve(tcpListener) }()
	go func() { stopped <- dnsProxy.Serve(udpConn) }()

	if cfg.DebugEndpoint != "" {
		go func() {
			slog.Error("debug endpoint stopped", "error", http.ListenAndServe(cfg.DebugEndpoint, nil))
		}()
	}

	// Redirect traffic only now that the proxies are ready, and stop
	// redirecting it before they stop (deferred calls run in reverse order).
	localNetworks, err := netfilter.LocalNetworks()
	if err != nil {
		return err
	}
	redirect := netfilter.Redirect{
		ListenPort:  cfg.ListenEndpoint.Port(),
		ProxyPorts:  cfg.ProxyPorts,
		Mark:        cfg.IPTableMark,
		NoRedirect:  append(cfg.NoProxyList, localNetworks...),
		Routed:      cfg.ListenEndpoint.Addr().IsUnspecified(),
		WSLMirrored: cfg.WSLMirroredNetworking,
	}
	if err := netfilter.Install(redirect); err != nil {
		return fmt.Errorf("install iptables rules: %w", err)
	}
	defer removeIPTablesRules()
	slog.Info("installed iptables rules", "listen", cfg.ListenEndpoint, "ports", redirect.ProxyPorts,
		"noRedirect", redirect.NoRedirect, "routed", redirect.Routed, "wslMirrored", redirect.WSLMirrored, "rules", len(routingRules))

	select {
	case <-ctx.Done():
		slog.Info("stopping")
		return nil
	case err := <-stopped:
		return err
	}
}

func removeIPTablesRules() {
	if err := netfilter.Remove(); err != nil {
		slog.Error("cannot remove iptables rules, run prox-em-all -cleanup", "error", err)
		return
	}
	slog.Info("removed iptables rules")
}
