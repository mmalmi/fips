package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func routingFixture(t *testing.T, rules, routes string) func() string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("ROUTING_TEST_DIR", dir)
	t.Setenv("ROUTING_TEST_FAIL", "")
	t.Setenv("ROUTING_TEST_NFT_FAIL", "")
	files := map[string]string{
		"rules": rules, "routes": routes,
		"ip": `#!/bin/sh
printf 'ip %s\n' "$*" >> "$ROUTING_TEST_DIR/log"
[ "$*" != "$ROUTING_TEST_FAIL" ] || exit 1
case "$*" in
  '-4 rule list') cat "$ROUTING_TEST_DIR/rules";;
  '-4 -N route show table all') cat "$ROUTING_TEST_DIR/routes";;
esac
`,
		"nft": `#!/bin/sh
printf 'nft %s\n' "$*" >> "$ROUTING_TEST_DIR/log"
cat >> "$ROUTING_TEST_DIR/log"
[ -z "$ROUTING_TEST_NFT_FAIL" ]
`,
	}
	for name, data := range files {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(data), 0700); e != nil {
			t.Fatal(e)
		}
	}
	return func() string {
		data, e := os.ReadFile(filepath.Join(dir, "log"))
		if e != nil {
			t.Fatal(e)
		}
		return string(data)
	}
}

const rulesFixture = `0: from all lookup local
19971: from all iif br-freedom lookup 19971
19972: from all iif br-freedom unreachable
19973: from all fwmark 0x4e13 lookup 19973
19974: from all fwmark 0x4e13 unreachable
32766: from all lookup main
`

func TestCleanupClosesAdmissionAndOnlyRemovesOwnedRouting(t *testing.T) {
	log := routingFixture(t, rulesFixture, `default dev wg-guest table 19971 proto 199
default via 192.0.2.1 dev eth0 table 19973 proto static
192.0.2.0/24 dev eth0 table 19971 proto kernel
default dev unrelated table 19975 proto 199
`)
	if e := cleanupRouting(context.Background()); e != nil {
		t.Fatal(e)
	}
	output := log()
	last := -1
	for _, command := range []string{
		"flush set inet fw4 freedom_uplink\n",
		"rule del pref 19971 iif br-freedom lookup 19971\n",
		"rule del pref 19973 fwmark 0x4e13 lookup 19973\n",
		"route del table 19971 default proto 199\n",
		"rule del pref 19972 iif br-freedom unreachable\n",
		"rule del pref 19974 fwmark 0x4e13 unreachable\n",
	} {
		index := strings.Index(output, command)
		if index <= last {
			t.Fatalf("missing or out-of-order %q in %s", command, output)
		}
		last = index
	}
	if strings.Count(output, "route del") != 1 || strings.Contains(output, "route flush") {
		t.Fatal("cleanup changed unowned routes", output)
	}
}

func TestRoutingConflictAndCleanupFailuresStayClosed(t *testing.T) {
	t.Run("duplicate priority", func(t *testing.T) {
		log := routingFixture(t, rulesFixture+"19971: from all lookup main\n", "")
		if e := ensureRule(context.Background(), "19971", "iif br-freedom", "lookup 19971"); e == nil {
			t.Fatal("conflicting duplicate priority accepted")
		}
		if e := cleanupRouting(context.Background()); e == nil || strings.Contains(log(), "rule del") {
			t.Fatal("cleanup removed conflicting rules", e, log())
		}
	})
	t.Run("firewall unavailable", func(t *testing.T) {
		log := routingFixture(t, rulesFixture, "")
		t.Setenv("ROUTING_TEST_NFT_FAIL", "1")
		if e := cleanupRouting(context.Background()); e == nil || strings.Contains(log(), "ip ") {
			t.Fatal("cleanup touched routing with admission still open", e, log())
		}
	})
	t.Run("lookup removal fails", func(t *testing.T) {
		log := routingFixture(t, rulesFixture, "")
		t.Setenv("ROUTING_TEST_FAIL", "-4 rule del pref 19971 iif br-freedom lookup 19971")
		if e := cleanupRouting(context.Background()); e == nil || strings.Contains(log(), "del pref 19972") || strings.Contains(log(), "del pref 19974") {
			t.Fatal("cleanup removed terminal rules after failure", e, log())
		}
	})
	t.Run("already clean", func(t *testing.T) {
		log := routingFixture(t, "0: from all lookup local\n", "")
		if e := cleanupRouting(context.Background()); e != nil || strings.Contains(log(), " del ") {
			t.Fatal("cleanup was not idempotent", e, log())
		}
	})
}

func TestDefaultRouteRequiresOwnership(t *testing.T) {
	for _, tc := range []struct {
		name, routes string
		wantError    bool
	}{
		{"empty table", "", false},
		{"owned", "default dev old table 19971 proto 199\n", false},
		{"legacy untagged", "default dev old table 19971\n", true},
		{"operator route", "192.0.2.0/24 dev eth0 table 19971 proto 2\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := routingFixture(t, "", tc.routes)
			e := defaultRoute(context.Background(), routeTable, Profile{Device: "wg-guest"})
			if (e != nil) != tc.wantError {
				t.Fatal("ownership decision", e)
			}
			mutated := strings.Contains(log(), "route replace table 19971 default proto 199 dev wg-guest")
			if mutated == tc.wantError {
				t.Fatal("unowned state changed or owned route not installed", log())
			}
		})
	}
}
