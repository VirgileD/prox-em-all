# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project

`prox-em-all` (repository `github.com/VirgileD/prox-em-all`) is a Linux transparent proxy:
iptables REDIRECT rules send TCP connections (configured ports) and DNS queries (UDP 53) to it; it
forwards each connection directly or through HTTP CONNECT / SOCKS5 upstream proxies chosen by
ordered rules (IP, CIDR, hostname regexp). Hostnames come from the DNS answers it forwards.
Optionally, for configured HTTPS servers, it intercepts TLS and replaces placeholder credentials in
request headers with real ones from a systemd-encrypted credentials file.
README.md documents behaviour and configuration; keep it in sync with the code.

## Code principles

The owner's priority is **code that is simple to read and maintain**. Simple beats smart.

- Prefer plain, explicit code over clever or generic solutions, even if slightly slower or a little
  repetitive. No abstraction until there is a real second use for it.
- Do **not** follow the "accept interfaces everywhere" Go habit: use concrete types. Introduce an
  interface only when there is a real need for several implementations. For tests, replace
  root-only functions through struct fields (see Conventions) rather than interfaces.
- Names carry the meaning: choose precise, descriptive names for packages, types, functions,
  variables and constants so that the code reads without comments. Rename rather than explain a
  bad name with a comment.
- Comments where they are needed, not more: explain *why* (a non-obvious decision, a kernel or
  protocol quirk, a security reason), not *what* the code already says. Exported identifiers get a
  short doc comment.
- Small functions with one job, early returns, errors wrapped with context (`fmt.Errorf("...: %w", err)`).
- Standard library first; avoid new dependencies.
- Keep changes focused: no unrelated refactoring or reformatting in a change.

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
  any change to `internal/netfilter`, `internal/tcpproxy`, `internal/dnsproxy`, `internal/credentials`
  or `cmd/`. Its test certificates in `test/integration/tls/` are fixtures, not secrets. It never
  touches host iptables. `VERBOSE=1` prints logs.
- `make image`: Docker image `prox-em-all`, version from `git describe`.
- CI (`.github/workflows/ci.yml`) runs lint, test, build and the integration test on every push.

## Layout

- `cmd/prox-em-all/main.go`: flags (`-c`, `-cleanup`, `-version`), wiring, shutdown order
  (signals caught first; listeners up → install rules; on SIGINT/SIGTERM remove rules → close
  listeners). `listenEndpoint` 127.0.0.1 = this host's traffic only, 0.0.0.0 = routed traffic too.
- `internal/config`: YAML config with defaults and validation (`go.yaml.in/yaml/v3`, unknown fields
  rejected). `config.example.yaml` comments every setting; `main_test.go` checks it is valid.
- `internal/rules`: compiles config rules; `Match` returns the first matching rule (nil = direct).
  Hostname regexps are anchored and case-insensitive.
- `internal/tcpproxy`: accepts redirected connections, dials direct or through proxies
  (`upstream.go`: hand-written HTTP CONNECT and SOCKS5 handshakes over `*net.TCPConn`), `pipe`
  copies with TCP half-close. expvar counters `connections`.
- `internal/dnsproxy`: UDP forwarder (at most 100 queries at once); replies from the redirected
  address (IP_PKTINFO via `x/net/ipv4`); parses A answers with `x/net/dns/dnsmessage` into the host
  cache, ignoring names with characters other than `[A-Za-z0-9._-]`. expvar counters `dns`.
- `internal/credentials`: credential injection, active when `$CREDENTIALS_DIRECTORY/credentials`
  exists (systemd `LoadCredentialEncrypted=`). Reads the SNI from the ClientHello (`ReadClientHello`,
  bytes replayed), verifies the server's certificate, presents one minted from the CA in the file,
  then forwards HTTP/1.1 requests one at a time, replacing placeholders in configured headers only.
  expvar counters `credentials`. `credentials.example.yaml` is checked by `main_test.go`.
- `internal/hostcache`: bounded IP → hostname map with TTL.
- `internal/netfilter`: iptables rules in `PROX_EM_ALL_*` chains (installed idempotently, removable
  without the config; `iptables_test.go` lists them), `Dialer` setting SO_MARK, original destination
  via SO_ORIGINAL_DST (TCP) and conntrack over netlink (DNS), local networks from interface addresses.
  `Redirect.Interfaces` (config `redirectInterfaces`) limits nat PREROUTING to some interfaces
  (`-i` on each rule), e.g. Docker bridges. The filter INPUT rules accept DNAT'd traffic to the listen
  port and drop the rest; the filter OUTPUT REJECT rules stop the proxy from connecting to its own
  listen port (loops).
  `loopback.go`: optional `ip rule`s (`wslMirroredNetworking`) keeping traffic to 127.0.0.1:listenPort
  on Linux under WSL2 mirrored networking, which otherwise routes 127.0.0.1 through Windows.

## Conventions

- Components are structs with exported fields, wired in `main`; no package-level mutable state
  except expvar counters. Functions that need root (iptables, conntrack, SO_MARK) are injected as
  fields so tests can replace them.
- Logging: `log/slog` with lowercase messages and key/value attributes; per-connection success at
  debug, failures at warn. Never log proxy passwords (use `url.Redacted()`) nor credential values.
- Tests: standard `testing` only (no assertion library), table-driven where natural, local fake
  servers instead of network access.
- IPv4 only. Dependencies: go-iptables, netlink (conntrack, ip rules), x/net (dnsmessage, ipv4), x/sys,
  go.yaml.in/yaml/v3.
- Security-sensitive: hostnames from DNS are untrusted input (see README "Security considerations").
- Commit messages: conventional prefix (`feat:`, `fix:`, `refactor:`, `test:`, `build:`, `docs:`)
  and a body explaining why.

## Safety rules — read before acting

- **Never run the binary directly on the host** outside a container: it rewrites the host's
  iptables. Use the integration test or a container to exercise it.
- **Secrets:** never print, log or commit secret values (proxy credentials included).
- **Destructive operations** (deleting branches, tags, releases, images, rewriting history) need an
  explicit go-ahead each time; a previous approval does not carry over.
- **No force-push** to shared branches (`main`).
- **Admin / bypass merges (`gh pr merge --admin`) need an explicit go-ahead for each PR**, given
  after its checks are green. Never merge several PRs in a single command or loop.
