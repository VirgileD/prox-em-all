#!/bin/sh
# End-to-end test: runs prox-em-all with real iptables inside a container
# on an isolated docker network, and checks each destination takes the configured route.
#
# Usage: test/integration/run.sh   (needs docker with compose; does not touch host iptables)
#        VERBOSE=1 test/integration/run.sh   also prints the logs when all checks pass
set -eu
cd "$(dirname "$0")"

compose() { docker compose "$@"; }
in_proxy() { compose exec -T proxy sh -c "$1"; }

failures=0
pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; failures=$((failures + 1)); }
check() { # check NAME COMMAND: passes when COMMAND succeeds in the proxy container
    if in_proxy "$2"; then pass "$1"; else fail "$1"; fi
}

cleanup() {
    if [ "$failures" -ne 0 ] || [ -n "${VERBOSE:-}" ]; then
        echo "--- prox-em-all log"; in_proxy 'cat /tmp/proxy.log' || true
        echo "--- iptables"; in_proxy 'iptables-save' || true
        echo "--- services log"; compose logs --no-color | grep -v '^proxy' || true
    fi
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# start_proxy [CONFIG [ENVIRONMENT]] waits until prox-em-all has installed its iptables rules.
# ENVIRONMENT holds variable assignments, such as "CREDENTIALS_DIRECTORY=/test/credentials".
start_proxy() {
    installs=$(in_proxy 'grep -ci "installed iptables rules" /tmp/proxy.log || true')
    compose exec -T --detach proxy sh -c "${2:-} prox-em-all -c ${1:-/test/config.yaml} >> /tmp/proxy.log 2>&1"
    for _ in $(seq 50); do
        [ "$(in_proxy 'grep -ci "installed iptables rules" /tmp/proxy.log || true')" -gt "$installs" ] && return
        sleep 0.2
    done
    fail "prox-em-all started and installed its iptables rules"
    exit 1
}

# stop_proxy sends SIGNAL to prox-em-all and waits for it to exit.
stop_proxy() {
    in_proxy "pkill -$1 prox-em-all"
    for _ in $(seq 50); do
        in_proxy 'pgrep prox-em-all >/dev/null' || return 0
        sleep 0.2
    done
    fail "prox-em-all stopped on SIG$1"
}

# expect_route NAME FROM_SERVICE URL BODY WEB_SERVICE EXPECTED_CLIENT_IP
# Fetches URL from FROM_SERVICE and checks the web server saw the request coming from
# EXPECTED_CLIENT_IP: the proxy container itself when direct, else the upstream proxy.
expect_route() {
    body=$(compose exec -T "$2" wget -q -T 5 -O- "$3" 2>&1) || true
    if [ "$body" != "$4" ]; then
        fail "$1: expected body '$4', got '$body'"
        return
    fi
    if compose logs --no-color "$5" | tail -n 1 | grep -qF "ffff:$6]"; then
        pass "$1"
    else
        fail "$1: the last request $5 received did not come from $6"
    fi
}

# expect_https NAME URL CA BODY
# Fetches URL from the client container with the placeholder token, trusting only the
# certificates signed by CA (a file of tls/), and checks the body of the answer.
expect_https() {
    body=$(compose exec -T client curl -sS --max-time 5 --cacert "/test/tls/$3" \
        -H 'Authorization: Bearer PLACEHOLDER_TOKEN' "$2" 2>&1) || true
    if [ "$body" = "$4" ]; then pass "$1"; else fail "$1: expected '$4', got '$body'"; fi
}

compose up --detach --build --wait >/dev/null
in_proxy 'ip route add 10.99.0.0/24 dev eth0'
in_proxy 'echo "nameserver 10.213.0.30" > /etc/resolv.conf'
in_proxy ': > /tmp/proxy.log'

# Hostname rules only match addresses learnt from DNS answers since the proxy
# started, so each hostname check below runs first after a (re)start.

start_proxy
# Connections routed through the proxy host, DNS queries included.
expect_route "routed: hostname rule via HTTP proxy" client http://web1.test/ web1 web1 10.213.0.20
expect_route "routed: IP rule goes direct from the proxy" client http://10.99.0.11/ web2 web2 10.213.0.2
expect_https "without credentials: HTTPS is not intercepted" https://secure.test/ server-ca.crt denied
# Connections opened on the proxy host itself.
expect_route "IP rule goes direct" proxy http://10.99.0.11/ web2 web2 10.213.0.2
expect_route "CIDR rule via SOCKS5 proxy" proxy http://10.99.0.12/ web3 web3 10.213.0.21
# Traffic sent straight to the listen port must not make the proxy connect to itself, again and again.
# Each round of such a loop opens a new socket.
in_proxy 'wget -q -T 3 -O- http://127.0.0.1:3129/ >/dev/null 2>&1; echo x | nc -u -w 1 127.0.0.1 3129; sleep 1'
check "traffic sent straight to the listen port does not loop" \
    'fds=$(ls /proc/$(pgrep prox-em-all)/fd | wc -l); echo "prox-em-all has $fds open files"; [ "$fds" -lt 30 ]'
# Listening on 0.0.0.0 must not expose the proxy: traffic sent straight to the listen port from
# the network is dropped, before the proxy sees it.
compose exec -T client sh -c 'wget -q -T 2 -O- http://10.213.0.2:3129/ >/dev/null 2>&1; echo x | nc -u -w 1 10.213.0.2 3129' || true
check "traffic sent straight to the listen port from the network is dropped" \
    'iptables -t filter -L PROX_EM_ALL_INPUT -v -n -x | awk "/DROP/ && \$1 > 0 { n++ } END { exit n != 2 }"'
check "debug endpoint serves connection stats" \
    'wget -q -T 5 -O- http://127.0.0.1:6060/debug/vars | grep -q "\"connections\""'

stop_proxy KILL
start_proxy
check "restart after a crash replaces leftover rules instead of duplicating them" \
    '[ "$(iptables-save -t nat | grep -c "^-A OUTPUT -j PROX_EM_ALL_OUTPUT")" = 1 ]'
expect_route "hostname rule via HTTP proxy" proxy http://web1.test/ web1 web1 10.213.0.20

stop_proxy TERM
check "iptables rules removed on exit" '! iptables-save | grep -Eq "PROX_EM_ALL|REDIRECT|--mark"'

start_proxy
stop_proxy KILL
check "-cleanup removes the rules left by a crash" \
    'prox-em-all -cleanup && ! iptables-save | grep -Eq "PROX_EM_ALL|REDIRECT|--mark"'

# Credentials, as systemd provides them, for secure.test only. other.test has the same address.
# The proxy trusts the HTTPS server's CA, the client trusts the interception CA for secure.test.
start_proxy /test/config.yaml "CREDENTIALS_DIRECTORY=/test/credentials SSL_CERT_FILE=/test/tls/server-ca.crt"
expect_https "credentials: placeholder replaced, through an HTTP proxy" https://secure.test/ interception-ca.crt authorized
check "credentials: the intercepted connection followed its rule" \
    'grep "intercepted connection" /tmp/proxy.log | grep -q "rule=secure-http"'
expect_https "credentials: other server on the same address is not intercepted" https://other.test/ server-ca.crt denied
check "credentials: debug endpoint counts replacements" \
    'wget -q -T 5 -O- http://127.0.0.1:6060/debug/vars | grep -q "\"credentials\": {\"intercepted\": 1, \"replaced\": 1}"'
stop_proxy TERM

# Listening on 127.0.0.1, only the traffic of the proxy host is redirected. The listen port is
# also the port of the HTTP upstream proxy, which the proxy must still be able to reach.
in_proxy "sed 's/0.0.0.0:3129/127.0.0.1:8888/' /test/config.yaml > /tmp/local.yaml"
start_proxy /tmp/local.yaml
expect_route "local mode: hostname rule via a proxy using the listen port number" proxy http://web1.test/ web1 web1 10.213.0.20
expect_route "local mode: routed traffic is not redirected" client http://10.99.0.11/ web2 web2 10.213.0.3
stop_proxy TERM

# redirectInterfaces limits the redirection of routed traffic to the listed interfaces. The
# client's traffic arrives on the proxy container's eth0.
in_proxy "echo 'redirectInterfaces: [eth0]' | cat /test/config.yaml - > /tmp/eth0.yaml"
start_proxy /tmp/eth0.yaml
expect_route "listed interface: routed hostname rule via HTTP proxy" client http://web1.test/ web1 web1 10.213.0.20
stop_proxy TERM
in_proxy "echo 'redirectInterfaces: [docker+]' | cat /test/config.yaml - > /tmp/docker.yaml"
start_proxy /tmp/docker.yaml
expect_route "unlisted interface: routed traffic is not redirected" client http://10.99.0.11/ web2 web2 10.213.0.3
expect_route "unlisted interface: local traffic is still redirected" proxy http://web1.test/ web1 web1 10.213.0.20
stop_proxy TERM

# WSL2's mirrored networking mode routes TCP and UDP to 127.0.0.1 through Windows, with rules
# placed before the "local" table's. Simulate it by sending 127.0.0.1 nowhere.
in_proxy 'ip rule add pref 2 lookup local && ip rule del pref 0 lookup local'
in_proxy 'ip route add blackhole 127.0.0.1/32 table 127 && ip rule add pref 1 lookup 127'
in_proxy "sed 's/0.0.0.0:3129/127.0.0.1:3129/' /test/config.yaml > /tmp/wsl.yaml && echo 'wslMirroredNetworking: true' >> /tmp/wsl.yaml"
start_proxy /tmp/wsl.yaml
expect_route "WSL mirrored mode: hostname rule via HTTP proxy" proxy http://web1.test/ web1 web1 10.213.0.20
stop_proxy TERM
check "WSL mirrored mode: routing rules removed on exit" '! ip rule | grep -q "to 127.0.0.1"'
start_proxy /tmp/wsl.yaml
stop_proxy KILL
check "WSL mirrored mode: -cleanup removes the routing rules left by a crash" \
    'prox-em-all -cleanup && ! ip rule | grep -q "to 127.0.0.1"'

[ "$failures" -eq 0 ] && echo "All integration checks passed."
exit "$failures"
