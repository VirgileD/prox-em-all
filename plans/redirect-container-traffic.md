# Plan: redirect the traffic of containers (`redirectInterfaces`)

Status: implemented on branch `feat/redirect-interfaces` (2026-10-24). Rule layout chosen: `-i` on
every PREROUTING rule, no extra chain, so `remove` is unchanged.

## Problem

Connections and DNS queries made from inside a container on a Docker bridge network (`docker0`,
or `br-<id>` for compose and user-defined networks) are not proxied with the default configuration.

## Why

A bridged container has its own network namespace. Its packets leave through a veth pair, enter
the host on the bridge interface and traverse the host's netfilter as **routed** traffic: they hit
`nat PREROUTING`, never `nat OUTPUT`.

In `internal/netfilter/iptables.go`:

- `nat OUTPUT` (always installed) covers the host's own processes, which includes
  `--network host` containers and rootless Docker/Podman (slirp4netns/pasta open host sockets).
- `nat PREROUTING` is installed only when `Redirect.Routed` is true, and `main.go` sets `Routed`
  only when `listenEndpoint` is `0.0.0.0`.

The two are tied on purpose: `REDIRECT` in PREROUTING rewrites the destination to the **primary
address of the incoming interface** (e.g. `172.17.0.1` on `docker0`), not to 127.0.0.1, so a
listener bound to 127.0.0.1 would never receive the connection. The original go-any-proxy
"worked" with containers because it was usually run listening on all addresses (`-l :3140`) with
PREROUTING rules added by hand.

## Why the workaround is not enough

`listenEndpoint: 0.0.0.0:3129` already redirects container traffic. The rest of the code handles it
(filter INPUT accepts DNAT'd traffic, SO_ORIGINAL_DST and conntrack see container flows since they
live in the host namespace, the DNS proxy answers from the redirected address via IP_PKTINFO).
But it has two drawbacks:

1. **Too broad**: PREROUTING redirects traffic arriving on *every* interface (`eth0`, VPN, Wi-Fi),
   so the host proxies anything routed through it, not only its containers.
2. **Exposed listener**: port 3129 accepts connections from the LAN (and from Windows/LAN under
   WSL2 mirrored networking). A direct connection only ends in the filter OUTPUT REJECT rule (its
   original destination is the listen port itself), but the port answers and the DNS proxy
   receives datagrams from anyone.

## Design

### Configuration

New optional setting in `internal/config`:

```yaml
# Interfaces whose incoming traffic is redirected, such as the bridges of Docker containers.
# "+" at the end matches any interface starting with the name (iptables wildcard), so that bridges
# created later are covered too. Needs listenEndpoint 0.0.0.0:<port>: the traffic is redirected to
# the address of the interface it arrives on. Default: [] (with 0.0.0.0: all interfaces)
redirectInterfaces: [docker0, br-+]
```

Semantics, in a single table:

| listenEndpoint | redirectInterfaces | PREROUTING redirection          |
|----------------|--------------------|---------------------------------|
| 127.0.0.1      | empty              | none (unchanged)                |
| 127.0.0.1      | non-empty          | config error                    |
| 0.0.0.0        | empty              | all interfaces (unchanged)      |
| 0.0.0.0        | non-empty          | the listed interfaces only      |

Existing configurations keep their behaviour.

Validation (`config.validate`):

- `redirectInterfaces` non-empty requires an unspecified listen address. Error message explains:
  `redirectInterfaces needs listenEndpoint "0.0.0.0:<port>": redirected traffic arrives on the
  interface's address`.
- Each name: 1–15 characters (IFNAMSIZ-1), characters `[A-Za-z0-9._-]` plus an optional trailing
  `+`. This rejects anything that iptables would parse as an option (names come from the config
  file, which is trusted, but a typo such as a space should be reported clearly).

`Config` field: `RedirectInterfaces []string \`yaml:"redirectInterfaces"\``.

### netfilter

`Redirect` gets a field:

```go
// Interfaces restricts the redirection of routed traffic to the traffic
// arriving on these interfaces ("+" suffix: any name with that prefix).
// Empty: all interfaces.
Interfaces []string
```

`main.go` passes `cfg.RedirectInterfaces`; `Routed` stays `cfg.ListenEndpoint.Addr().IsUnspecified()`.

`rules("nat", "PREROUTING")`, when `Interfaces` is non-empty, jumps per interface to the same
redirect rules rather than duplicating them. Keep it explicit with a second proxy-owned chain:

```
-A PROX_EM_ALL_PREROUTING -i docker0 -j PROX_EM_ALL_REDIRECT
-A PROX_EM_ALL_PREROUTING -i br-+    -j PROX_EM_ALL_REDIRECT
-A PROX_EM_ALL_REDIRECT -p udp --dport 53 -j REDIRECT --to-ports 3129
-A PROX_EM_ALL_REDIRECT -d 172.16.0.0/12 -j RETURN
...
-A PROX_EM_ALL_REDIRECT -p tcp -m multiport --dports 80,443 -j REDIRECT --to-ports 3129
```

Alternative considered: prefix every redirect rule with `-i <iface>` (N × M rules). Simpler code
but the rule list grows quickly and `iptables-save` is harder to read. **Decision: decide during
implementation by which reads simpler in `iptables.go`.** The extra chain requires the install and
remove code to handle a chain that is not hooked to a built-in chain: `install` creates it before
`PROX_EM_ALL_PREROUTING` jumps to it, `remove` must flush the jumping chain before deleting it
(iptables refuses to delete a referenced chain). If that makes `remove` noticeably more complex,
prefer the `-i` prefix on every rule — simple beats smart.

### Hardening the listener (applies to every 0.0.0.0 configuration)

In `PROX_EM_ALL_INPUT`, after the two ACCEPT rules, drop what reaches the listen port without
having been redirected:

```
-A PROX_EM_ALL_INPUT -p tcp --dport 3129 -m conntrack --ctstate DNAT -j ACCEPT
-A PROX_EM_ALL_INPUT -p udp --dport 3129 -m conntrack --ctstate DNAT -j ACCEPT
-A PROX_EM_ALL_INPUT -p tcp --dport 3129 -j DROP
-A PROX_EM_ALL_INPUT -p udp --dport 3129 -j DROP
```

Every legitimate packet is DNAT'd (REDIRECT from OUTPUT or PREROUTING), so nothing legitimate is
lost; local processes connecting straight to 127.0.0.1:3129 are dropped too, which is fine. Keep
the filter OUTPUT REJECT rules: they still stop the proxy from looping on its own connections if
the INPUT rule is ever bypassed (and REJECT gives a fast failure where DROP would hang).

Note: with this rule, the integration check "traffic sent straight to the listen port does not
loop" passes because of the DROP rather than the OUTPUT REJECT. Keep the check; add a separate
check that the REJECT rules alone prevent the loop only if it is cheap to do (e.g. by removing the
DROP rules with `iptables -D` in that scenario) — otherwise accept the overlap.

`-cleanup` needs no change: the rules live in the existing `PROX_EM_ALL_*` chains.

### Logging

The "installed iptables rules" log line gains `"interfaces", redirect.Interfaces`.

## Tests

Unit (`internal/netfilter/iptables_test.go`):

- `TestRedirectRules`: add the two DROP rules to the expected `filter INPUT` rules.
- New `TestRoutedTrafficIsRedirectedFromListedInterfacesOnly`: `Interfaces: [docker0, br-+]` →
  expected PREROUTING (and `PROX_EM_ALL_REDIRECT` if chosen) rules.
- If an extra chain is added, extend the test listing the chains, so `remove` is known to cover it.

Unit (`internal/config`):

- table cases: interfaces with 127.0.0.1 rejected; invalid names (`""`, too long, `eth 0`, `-j`,
  `a+b`) rejected; `docker0`, `br-+`, `veth.1` accepted.
- `main_test.go` keeps checking that `config.example.yaml` is valid (the example adds a commented
  `redirectInterfaces` line).

Integration (`test/integration/`), run after the change as CLAUDE.md requires:

- Scenario "listed interface": config with `redirectInterfaces: [eth0]` (the client's traffic
  arrives on the proxy container's eth0) → the client's routes behave as with 0.0.0.0 today.
- Scenario "unlisted interface": `redirectInterfaces: [docker+]` (no such interface in the
  container) → client traffic is not redirected (same expectation as the existing
  "local mode: routed traffic is not redirected" check: web2 sees 10.213.0.3).
- Scenario "listener not reachable directly": from the client, `nc -z -w 2 10.213.0.2 3129` fails
  and a UDP datagram to 10.213.0.2:3129 gets no answer.
- Build the scenario configs with `sed`/`echo >>` from `config.yaml`, like the existing local and
  WSL scenarios.

## Documentation

- README: new section "Containers" (or extend "As a gateway"): why bridged containers need
  PREROUTING, the `redirectInterfaces` setting, the table above, the DNS caveats below; settings
  table row; mention of the INPUT DROP rules in the description of the installed rules.
- `config.example.yaml`: commented setting.
- CLAUDE.md "Layout": one line on `redirectInterfaces` and the INPUT drop rules.

## Caveats to document

- **Docker Desktop**: containers run in a separate VM; their traffic never crosses the host's
  netfilter and cannot be redirected. Only Docker Engine installed in the same host/WSL distro works.
- **DNS on the default bridge** (`docker0`): containers copy the host's resolv.conf; when it points
  to a loopback resolver (systemd-resolved 127.0.0.53), Docker substitutes 8.8.8.8/8.8.4.4. The
  queries are redirected and fill the hostname cache, but are still forwarded to 8.8.8.8, often
  blocked on corporate networks. Fix: `"dns": [...]` in `/etc/docker/daemon.json`.
- **DNS on user-defined networks / compose**: Docker's embedded DNS (127.0.0.11) forwards external
  queries from the container's namespace, so they cross PREROUTING and hostname rules work.
- **Docker's own nat rules**: Docker's `DOCKER` chain in nat PREROUTING only matches
  `--dst-type LOCAL` (published ports); our jump is inserted first and traffic to local addresses
  returns before the TCP redirect, so they do not conflict. Docker re-adds its rules on restart
  with `-A`/`-I` into its own chains; our jump stays first. With Docker's nftables firewall backend
  (`"firewall-backend": "nftables"`), its rules live in a separate nft table at the same dstnat
  hook: check the ordering before claiming support.
- **WSL2 mirrored networking**: container traffic is redirected to the bridge address, not
  127.0.0.1, so the loopback routing rules are not involved; but a 0.0.0.0 listener is reachable
  from Windows, which the INPUT DROP rules address.
- **Kubernetes / other CNIs**: same mechanism with their interface names (`cni0`, `cali+`,
  `flannel.1`, `veth+`).

## Steps

1. `internal/config`: field, validation, tests; `config.example.yaml`.
2. `internal/netfilter`: `Redirect.Interfaces`, PREROUTING rules, INPUT DROP rules, tests.
3. `cmd/prox-em-all/main.go`: wiring and log attribute.
4. Integration scenarios in `test/integration/run.sh`.
5. README and CLAUDE.md.
6. `make lint test build` in the Go container, then `make integration-test`.
7. Commits: `feat: redirect only the traffic of listed interfaces` and
   `fix: drop traffic reaching the listen port without being redirected` (separate: the hardening
   changes behaviour on its own and is worth its own explanation).
