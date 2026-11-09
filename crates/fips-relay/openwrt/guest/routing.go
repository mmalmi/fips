package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const guestBridge = "br-freedom"
const routeTable = "19971"
const probeMark = 0x4e13
const routeProtocol = "199"

var guestRules = [][3]string{{"19972", "iif " + guestBridge, "unreachable"}, {"19974", "fwmark 0x4e13", "unreachable"}, {"19971", "iif " + guestBridge, "lookup " + routeTable}, {"19973", "fwmark 0x4e13", "lookup 19973"}}

func nft(ctx context.Context, script string) error {
	_, e := cmd(ctx, script, "nft", "-f", "-")
	return e
}
func clearUplink(ctx context.Context) error { return nft(ctx, "flush set inet fw4 freedom_uplink\n") }
func ip(ctx context.Context, args ...string) error {
	_, e := cmd(ctx, "", append([]string{"ip", "-4"}, args...)...)
	return e
}
func defaultRoute(ctx context.Context, table string, p Profile) error {
	routes, e := tableRoutes(ctx, table)
	if e != nil {
		return e
	}
	for _, route := range routes {
		if !ownedRoute(route) {
			return fmt.Errorf("routing table %s contains an unowned route", table)
		}
	}
	a := []string{"route", "replace", "table", table, "default", "proto", routeProtocol}
	if p.Gateway != "" {
		a = append(a, "via", p.Gateway, "onlink")
	}
	return ip(ctx, append(a, "dev", p.Device)...)
}

func routeField(fields []string, name string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == name {
			return fields[i+1]
		}
	}
	return ""
}
func ownedRoute(fields []string) bool {
	return len(fields) > 0 && fields[0] == "default" && routeField(fields, "proto") == routeProtocol
}
func tableRoutes(ctx context.Context, table string) ([][]string, error) {
	// Listing all tables also succeeds when our table has not been created.
	// Numeric output makes ownership independent of local protocol aliases.
	out, e := cmd(ctx, "", "ip", "-4", "-N", "route", "show", "table", "all")
	if e != nil {
		return nil, e
	}
	var routes [][]string
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if routeField(fields, "table") == table {
			routes = append(routes, fields)
		}
	}
	return routes, nil
}

func matchingRules(out, pref, selector, target string) (int, error) {
	count := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != pref+":" {
			continue
		}
		if strings.Join(f[1:], " ") != "from all "+selector+" "+target {
			return 0, fmt.Errorf("policy priority %s is already in use", pref)
		}
		count++
	}
	return count, nil
}

// Refuse conflicting policy rules. Both lookups terminate even if their device disappears.
func ensureRule(ctx context.Context, pref, selector, target string) error {
	out, e := cmd(ctx, "", "ip", "-4", "rule", "list")
	if e != nil {
		return e
	}
	count, e := matchingRules(string(out), pref, selector, target)
	if e != nil || count > 0 {
		return e
	}
	a := []string{"rule", "add", "pref", pref}
	a = append(a, strings.Fields(selector+" "+target)...)
	return ip(ctx, a...)
}
func setupRules(ctx context.Context) error {
	for _, r := range guestRules {
		if e := ensureRule(ctx, r[0], r[1], r[2]); e != nil {
			return e
		}
	}
	return nil
}

func cleanupRouting(ctx context.Context) error {
	// Close admission before touching lookup or terminal rules. On any error,
	// keep the remaining terminal rules to prevent fallthrough to local WAN.
	if e := clearUplink(ctx); e != nil {
		return fmt.Errorf("close guest forwarding: %w", e)
	}
	out, e := cmd(ctx, "", "ip", "-4", "rule", "list")
	if e != nil {
		return e
	}
	counts := make([]int, len(guestRules))
	for i, r := range guestRules {
		counts[i], e = matchingRules(string(out), r[0], r[1], r[2])
		if e != nil {
			return e
		}
	}
	removeRule := func(i int) error {
		r := guestRules[i]
		args := append([]string{"rule", "del", "pref", r[0]}, strings.Fields(r[1]+" "+r[2])...)
		for n := 0; n < counts[i]; n++ {
			if e := ip(ctx, args...); e != nil {
				return e
			}
		}
		return nil
	}
	for _, i := range []int{2, 3} {
		if e := removeRule(i); e != nil {
			return e
		}
	}
	for _, table := range []string{routeTable, "19973"} {
		routes, e := tableRoutes(ctx, table)
		if e != nil {
			return e
		}
		for _, route := range routes {
			if ownedRoute(route) {
				args := []string{"route", "del", "table", table, "default", "proto", routeProtocol}
				if metric := routeField(route, "metric"); metric != "" {
					args = append(args, "metric", metric)
				}
				if e := ip(ctx, args...); e != nil {
					return e
				}
			}
		}
	}
	for _, i := range []int{0, 1} {
		if e := removeRule(i); e != nil {
			return e
		}
	}
	return nil
}
func setUplink(ctx context.Context, p Profile) error {
	if e := defaultRoute(ctx, routeTable, p); e != nil {
		return e
	}
	return nft(ctx, fmt.Sprintf("flush set inet fw4 freedom_uplink\nadd element inet fw4 freedom_uplink { %q }\n", p.Device))
}
func clientMAC(ip string) (string, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return "", err
	}
	for _, row := range strings.Split(string(data), "\n") {
		f := strings.Fields(row)
		if len(f) != 6 || f[0] != ip || f[5] != guestBridge || f[2] != "0x2" {
			continue
		}
		mac, e := net.ParseMAC(f[3])
		if e == nil && len(mac) == 6 && mac[0]&1 == 0 {
			return mac.String(), nil
		}
	}
	return "", fmt.Errorf("client is not on guest Wi-Fi")
}
func clientSets(passes map[string]Order, now int64) string {
	var b strings.Builder
	b.WriteString("flush set inet fw4 freedom_clients\nflush set inet fw4 freedom_returns\n")
	ips := map[string]int64{}
	tuples := map[string]int64{}
	for _, o := range passes {
		if o.Until <= now || net.ParseIP(o.IP).To4() == nil {
			continue
		}
		mac, e := net.ParseMAC(o.MAC)
		if e != nil {
			continue
		}
		k := mac.String() + " . " + o.IP
		if o.Until > tuples[k] {
			tuples[k] = o.Until
		}
		if o.Until > ips[o.IP] {
			ips[o.IP] = o.Until
		}
	}
	for k, u := range tuples {
		fmt.Fprintf(&b, "add element inet fw4 freedom_clients { %s timeout %ss }\n", k, strconv.FormatInt(u-now, 10))
	}
	for k, u := range ips {
		fmt.Fprintf(&b, "add element inet fw4 freedom_returns { %s timeout %ss }\n", k, strconv.FormatInt(u-now, 10))
	}
	return b.String()
}
