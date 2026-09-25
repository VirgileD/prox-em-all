# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

`prox-em-all` (repository `github.com/VirgileD/prox-em-all`) is a Linux transparent proxy:
iptables REDIRECT rules send TCP connections (configured ports) and DNS queries (UDP 53) to it; it
forwards each connection directly or through HTTP CONNECT / SOCKS5 upstream proxies chosen by
ordered rules (IP, CIDR, hostname regexp). Hostnames come from the DNS answers it forwards.
README.md documents behaviour and configuration; keep it in sync with the code.

The owner's priority: **code that is simple to read and maintain**. Prefer plain, explicit code over
clever or generic solutions, even if slightly slower. Standard library first; avoid new dependencies.

## Commands

Go is **not installed locally**; run Go commands in a container (repo mounted, current user):

```sh
docker run --rm -v "$PWD":/src -w /src --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOFLAGS=-buildvcs=false \
  golang:1.27 make lint test build
```

- `make test`: unit tests with the race detector. Single test: `go test -run TestHTTPProxy ./internal/tcpproxy/`
- `make lint`: gofmt check, go vet, staticcheck, govulncheck (pinned versions in the Makefile)
- `make integration-test` (runs on the host, needs Docker Compose): end-to-end test in
  `test/integration/`, with real iptables inside containers on an isolated network. Run it after
  any change to `internal/netfilter`, `internal/tcpproxy`, `internal/dnsproxy` or `cmd/`. It never
  touches host iptables. `VERBOSE=1` prints logs.
- `make image`: Docker image `prox-em-all`, version from `git describe`.

Never run the binary directly on the host outside a container: it rewrites the host's iptables.

## Layout

- `cmd/prox-em-all/main.go`: flags (`-c`, `-cleanup`, `-version`), wiring, shutdown order
  (signals caught first; listeners up → install rules; on SIGINT/SIGTERM remove rules → close
  listeners). `listenEndpoint` 127.0.0.1 = this host's traffic only, 0.0.0.0 = routed traffic too.
- `internal/config`: JSON config with defaults and validation (`encoding/json`, unknown fields rejected).
- `internal/rules`: compiles config rules; `Match` returns the first matching rule (nil = direct).
  Hostname regexps are anchored and case-insensitive.
- `internal/tcpproxy`: accepts redirected connections, dials direct or through proxies
  (`upstream.go`: hand-written HTTP CONNECT and SOCKS5 handshakes over `*net.TCPConn`), `pipe`
  copies with TCP half-close. expvar counters `connections`.
- `internal/dnsproxy`: UDP forwarder (at most 100 queries at once); replies from the redirected
  address (IP_PKTINFO via `x/net/ipv4`); parses A answers with `x/net/dns/dnsmessage` into the host
  cache, ignoring names with characters other than `[A-Za-z0-9._-]`. expvar counters `dns`.
- `internal/hostcache`: bounded IP → hostname map with TTL.
- `internal/netfilter`: iptables rules in `PROX_EM_ALL_*` chains (installed idempotently, removable
  without the config; `iptables_test.go` lists them), `Dialer` setting SO_MARK, original destination
  via SO_ORIGINAL_DST (TCP) and conntrack over netlink (DNS), local networks from interface addresses.
  The filter OUTPUT REJECT rules stop the proxy from connecting to its own listen port (loops).
  `loopback.go`: optional `ip rule`s (`wslMirroredNetworking`) keeping traffic to 127.0.0.1:listenPort
  on Linux under WSL2 mirrored networking, which otherwise routes 127.0.0.1 through Windows.

## Conventions

- Components are structs with exported fields, wired in `main`; no package-level mutable state
  except expvar counters. Functions that need root (iptables, conntrack, SO_MARK) are injected as
  fields so tests can replace them.
- Logging: `log/slog` with lowercase messages and key/value attributes; per-connection success at
  debug, failures at warn. Never log proxy passwords: use `url.Redacted()`.
- Tests: standard `testing` only (no assertion library), table-driven where natural, local fake
  servers instead of network access.
- IPv4 only. Dependencies: go-iptables, netlink (conntrack), x/net (dnsmessage, ipv4), x/sys.
- Security-sensitive: hostnames from DNS are untrusted input (see README "Security considerations").
- Commit messages: conventional prefix (`feat:`, `fix:`, `refactor:`, `test:`, `build:`, `docs:`)
  and a body explaining why.
