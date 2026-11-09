package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const guestBridge = "br-freedom"
const routeTable = "19971"
const probeMark = 0x4e13

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
	a := []string{"route", "replace", "table", table, "default"}
	if p.Gateway != "" {
		a = append(a, "via", p.Gateway, "onlink")
	}
	return ip(ctx, append(a, "dev", p.Device)...)
}

// Refuse conflicting policy rules. Both lookups terminate even if their device disappears.
func ensureRule(ctx context.Context, pref, selector, target string) error {
	out, e := cmd(ctx, "", "ip", "-4", "rule", "list")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != pref+":" {
			continue
		}
		expected := "from all " + selector + " " + target
		if strings.Join(f[1:], " ") == expected {
			return nil
		}
		return fmt.Errorf("policy priority %s is already in use", pref)
	}
	a := []string{"rule", "add", "pref", pref}
	a = append(a, strings.Fields(selector+" "+target)...)
	return ip(ctx, a...)
}
func setupRules(ctx context.Context) error {
	for _, r := range [][3]string{{"19972", "iif " + guestBridge, "unreachable"}, {"19974", "fwmark 0x4e13", "unreachable"}, {"19971", "iif " + guestBridge, "lookup " + routeTable}, {"19973", "fwmark 0x4e13", "lookup 19973"}} {
		if e := ensureRule(ctx, r[0], r[1], r[2]); e != nil {
			return e
		}
	}
	return nil
}
func ready(ctx context.Context, c Config, p Profile) bool {
	if c.Mode != "direct" {
		// Each paid profile terminates at a guarded Nostr VPN buyer namespace.
		peers, err := cmd(ctx, "", "wg", "show", p.Device, "peers")
		if err != nil || len(bytes.TrimSpace(peers)) == 0 {
			return false
		}
	}
	if defaultRoute(ctx, "19973", p) != nil {
		return false
	}
	d := net.Dialer{Timeout: 3 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) { err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, probeMark) }); e != nil {
			return e
		}
		return err
	}}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, "tcp4", addr) }, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodHead, c.Probe, nil)
	if e != nil {
		return false
	}
	res, e := client.Do(req)
	if e != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 400
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
