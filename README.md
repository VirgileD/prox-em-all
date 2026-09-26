# prox-em-all

A transparent proxy for Linux. It captures the outgoing TCP connections of a host (or of the hosts
routed through it) with iptables, and forwards each one **directly** or through **upstream HTTP or
SOCKS5 proxies**, chosen by destination IP address, network or hostname.

Applications need no proxy settings. This is handy in corporate networks where different
destinations are reachable through different proxies, and for tools that ignore `HTTP_PROXY`.

prox-em-all is based on [go-any-proxy](https://github.com/ryanchapman/go-any-proxy) by Ryan A. Chapman,
through the [fork by Feng Zhou](https://github.com/feng-zh/go-any-proxy). See [Credits](#credits).

## How it works

```
 application ──TCP 93.184.215.14:443──► iptables REDIRECT ──► prox-em-all ──► direct
             ──DNS query (UDP 53)─────► iptables REDIRECT ──►      │        ──► HTTP proxy (CONNECT)
                                                                   │        ──► SOCKS5 proxy
                                                  learns 93.184.215.14 = www.example.com
```

1. At startup, prox-em-all adds iptables rules redirecting TCP connections to the configured ports
   (80 and 443 by default), and DNS queries (UDP port 53), to its listen port. Connections to
   networks of the host's own interfaces are never redirected.
2. It forwards each DNS query to the server it was meant for and reads the answer, to remember
   which hostname each IP address was resolved from.
3. For each redirected connection, it finds the original destination and its hostname, and applies
   the first matching rule: connect directly, or through the rule's proxies, tried in order.
   HTTP proxies receive a `CONNECT hostname:port` request, so their own policies still apply.
4. On exit, the iptables rules are removed.

Its own connections carry a firewall mark (`ipTableMark`) so that they are not redirected again.

## Requirements

- Linux with iptables (the Docker image uses its `nf_tables` backend, the default of current
  distributions)
- root, or the `CAP_NET_ADMIN` capability
- IPv4: IPv6 traffic is not redirected

## Getting started

Write a configuration file, starting from [`config.example.yaml`](config.example.yaml), which
comments every setting and shows the various kinds of rules:

```sh
cp config.example.yaml config.yaml
$EDITOR config.yaml
```

### With Docker

```sh
make image    # or: docker build -t prox-em-all .
docker run -d --name prox-em-all --network host --cap-add NET_ADMIN \
    -v "$PWD/config.yaml:/etc/prox-em-all/config.yaml:ro" prox-em-all
```

`--network host` is required: the rules must be installed in the host's network namespace.
Stop the container with `docker stop` so that the rules are removed.

### From source

With Go 1.27 or later:

```sh
make build    # builds ./prox-em-all
sudo ./prox-em-all -c config.yaml
```

```
Usage: prox-em-all [-c file] [-cleanup] [-version]
  -c file     path of the configuration file (default "/etc/prox-em-all/config.yaml")
  -cleanup    remove the iptables rules left by a previous run, then exit
  -version    print the version, then exit
```

## Configuration

A YAML file. All settings are optional; unknown settings are rejected.
[`config.example.yaml`](config.example.yaml) shows and comments each of them. Configuration files
written in JSON for earlier versions are still read: JSON is valid YAML.

| Setting | Default | Description |
|---|---|---|
| `listenEndpoint` | `127.0.0.1:3129` | Address and port the proxy listens on, for TCP and DNS: `127.0.0.1` to proxy the traffic of this host only, `0.0.0.0` to also proxy [routed traffic](#as-a-gateway). |
| `proxyPorts` | `[80, 443]` | TCP destination ports to redirect, at most 15. |
| `ipTableMark` | `5` | Firewall mark of the proxy's own packets. Change it if another tool on the host uses mark 5. |
| `noProxyList` | `[]` | Networks (CIDR, such as `192.168.0.0/16`) to which TCP connections are never redirected. The networks of the host's interfaces, loopback included, are added automatically. DNS queries are redirected whatever their destination. |
| `relayingRedirectResponse` | `true` | When an HTTP proxy answers `CONNECT` with a redirection (3xx), such as a login page, send it to the client instead of trying the next proxy. |
| `logLevel` | `info` | `debug`, `info`, `warn` or `error`. Each connection is logged at `debug` level. |
| `debugEndpoint` | `""` | Address serving [debug information](#monitoring) over HTTP, such as `127.0.0.1:6060`. Disabled when empty. |
| `wslMirroredNetworking` | `false` | Set it on WSL2 with `networkingMode=mirrored`, see [below](#on-wsl2-with-mirrored-networking). |
| `rules` | `[]` | Routing rules, see below. |

### Rules

```yaml
rules:
  - name: internal services, direct
    destinations: [10.1.2.3, 10.20.0.0/16, '.*\.internal\.example\.com']
    proxies: []
  - name: everything else
    destinations: [0.0.0.0/0]
    proxies: [http://user:password@proxy.example.com:3128, socks5://10.0.0.1:1080]
```

- Rules are checked **in order**, and the first one matching the destination applies.
  Destinations matching no rule are connected to **directly**.
- `destinations` holds IP addresses, CIDR networks, and **regular expressions** matched against the
  **whole** hostname, ignoring case: `.*\.example\.com` matches `www.example.com` but neither
  `example.com` nor `www.example.com.evil.net`. Write them between single quotes, where YAML keeps
  backslashes as they are.
- `proxies` are URLs, `http://` (the default when no scheme is given) or `socks5://`, optionally with
  credentials (percent-encode special characters of passwords, such as `%40` for `@`).
  They are tried in order until one accepts the connection; if all fail, the client
  connection is closed. An empty list means a direct connection.

Hostnames are only known for addresses the proxy has seen in a DNS answer since it started. Clients
using DNS over HTTPS or TLS, DNS over TCP, or addresses resolved before the proxy started, only match
IP and CIDR destinations. End your rules with a `0.0.0.0/0` rule to decide what happens then.

> [!NOTE]
> Connections to port 80 are also forwarded with `CONNECT`. Some proxies only allow `CONNECT` to
> port 443 by default, such as Squid with its `SSL_ports` list.

## Operations

### Stopping and cleaning up

On `SIGINT` or `SIGTERM`, prox-em-all removes its iptables rules and exits. If it was killed or
crashed instead, the rules stay and redirect traffic to a port nobody listens on. They are replaced
at the next start, or can be removed with:

```sh
sudo prox-em-all -cleanup
```

All the rules live in chains named `PROX_EM_ALL_*` (`sudo iptables-save | grep PROX_EM_ALL`), plus the
[WSL2 routing rules](#on-wsl2-with-mirrored-networking) (`ip rule`) when enabled.

### As a gateway

To also proxy the traffic of hosts using this host as their gateway, enable IP forwarding
(`sysctl -w net.ipv4.ip_forward=1`) and set `listenEndpoint` to `"0.0.0.0:3129"`: routed
connections are redirected to the address of the interface they arrive on. With `127.0.0.1`,
routed traffic, such as the traffic of Docker containers on bridge networks, is left untouched.

### On WSL2 with mirrored networking

In mirrored networking mode, WSL2 shares `localhost` with Windows: its routing rules send TCP and
UDP traffic to `127.0.0.1` through Windows. The traffic that iptables redirects to prox-em-all, which
goes to `127.0.0.1`, would come back from Windows as a new connection whose original destination is
lost: DNS queries and connections then hang. Set `wslMirroredNetworking: true` to add two routing
rules, removed on exit like the iptables rules, that keep the traffic to the listen port on Linux:

```
0:	from all to 127.0.0.1 ipproto tcp dport 3129 lookup local
0:	from all to 127.0.0.1 ipproto udp dport 3129 lookup local
```

Other traffic to `127.0.0.1`, such as an upstream proxy running on Windows, still reaches Windows.

### Monitoring

When `debugEndpoint` is set, it serves:

- `/debug/vars`: counters of `connections` (`direct`, `proxied`, `redirected`, `failed`,
  `accept_errors`) and of `dns` queries (`answered`, `failed`, `dropped` when more than 100 are
  pending, `read_errors`)
- `/debug/pprof/`: Go profiles and goroutine dumps

Keep it bound to a local address.

### Security considerations

- **Hostnames come from the clients' DNS traffic.** A client querying a DNS server it controls can
  associate any IP address with any hostname, for every client of the proxy. It can then reach that
  address through the rule of that hostname, and change the hostname sent to upstream proxies for
  other clients' connections to that address. Do not use hostname rules as a security boundary, and
  only proxy the traffic of trusted hosts.
- **As a gateway, redirected connections bypass the forwarding firewall.** They are accepted by the
  host's `INPUT` chain and opened again by the proxy itself, so `FORWARD` rules do not apply to them.
  Restrict which hosts may use the gateway.
- **The configuration file holds proxy passwords**: make it readable by root only.
- **The debug endpoint** exposes profiles and internal state: keep it on a local address.

## Development

```sh
make test               # unit tests
make lint               # gofmt, go vet, staticcheck, govulncheck
make integration-test   # end-to-end test with Docker, see below
make help               # all targets
```

The code is small and split by responsibility:

| Package | Role |
|---|---|
| [`cmd/prox-em-all`](cmd/prox-em-all) | Command line, wiring and shutdown |
| [`internal/config`](internal/config) | Loading and validating the configuration |
| [`internal/rules`](internal/rules) | Choosing the route of a destination |
| [`internal/tcpproxy`](internal/tcpproxy) | Forwarding TCP connections, directly or through HTTP and SOCKS5 proxies |
| [`internal/dnsproxy`](internal/dnsproxy) | Forwarding DNS queries and learning hostnames |
| [`internal/hostcache`](internal/hostcache) | IP address to hostname cache |
| [`internal/netfilter`](internal/netfilter) | iptables rules, firewall mark, original destinations |

The [integration test](test/integration/run.sh) starts prox-em-all in a container on an isolated
Docker network, with tinyproxy, Dante, dnsmasq and web servers. It checks the routes taken by
connections from the proxy's container and from a container using it as gateway, and the cleanup of
the iptables rules. It does not modify the host's iptables.

## Credits

prox-em-all started from [go-any-proxy](https://github.com/ryanchapman/go-any-proxy), written by
Ryan A. Chapman and described in his post
[Transparently proxying HTTP and HTTPS connections](http://blog.rchapman.org/post/47406142744/transparently-proxying-http-and-https-connections),
and from its [fork by Feng Zhou](https://github.com/feng-zh/go-any-proxy), which added the DNS
proxy, routing rules and SOCKS5 support.

Distributed under the BSD-style license in [LICENSE](LICENSE).
