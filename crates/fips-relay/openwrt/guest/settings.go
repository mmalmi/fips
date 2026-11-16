package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Profile struct{ Name, Device, Gateway string }
type Config struct {
	Mode, Address, State, Wallet, Mint, NVPNConfig, TLSName, Cert, Key, Probe string
	Price, Minutes                                                            int
	Profiles                                                                  []Profile
}

var nameRE = regexp.MustCompile("^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}$")

func cmd(ctx context.Context, input string, args ...string) ([]byte, error) {
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	c.Stdin = strings.NewReader(input)
	return c.Output()
}
func readConfig() (Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	data, err := cmd(ctx, "", "ubus", "call", "uci", "get", `{"config":"freedom_guest"}`)
	if err != nil {
		return Config{}, err
	}
	var u struct{ Values map[string]map[string]any }
	if err = json.Unmarshal(data, &u); err != nil {
		return Config{}, err
	}
	return parseConfig(u.Values)
}
func parseConfig(sections map[string]map[string]any) (Config, error) {
	val := func(section, key string) string { s, _ := sections[section][key].(string); return s }
	get := func(k string) string { return val("main", k) }
	c := Config{Mode: get("mode"), Address: get("address"), State: get("state"), Wallet: get("wallet"), Mint: get("mint"), NVPNConfig: get("nvpn_config"), TLSName: get("tls_name"), Cert: get("tls_cert"), Key: get("tls_key"), Probe: get("probe_url")}
	if c.Mode == "off" {
		return c, nil
	}
	c.Price, _ = strconv.Atoi(get("price_sat"))
	c.Minutes, _ = strconv.Atoi(get("minutes"))
	if c.Price < 1 || c.Price > 1000000 || c.Minutes < 1 || c.Minutes > 1440 || net.ParseIP(c.Address).To4() == nil || !filepath.IsAbs(c.State) || !filepath.IsAbs(c.Wallet) || !filepath.IsAbs(c.NVPNConfig) {
		return c, errors.New("invalid hotspot settings")
	}
	mint, e := url.Parse(c.Mint)
	if e != nil || mint.Host == "" || mint.User != nil || mint.RawQuery != "" || mint.Fragment != "" || (mint.Scheme != "https" && !(mint.Scheme == "http" && net.ParseIP(mint.Hostname()).IsLoopback())) {
		return c, errors.New("mint must use HTTPS or local loopback")
	}
	if c.TLSName == "" || !filepath.IsAbs(c.Cert) || !filepath.IsAbs(c.Key) || strings.ContainsAny(c.TLSName, "/ :?#@") {
		return c, errors.New("incomplete portal TLS settings")
	}
	if c.Probe == "" {
		c.Probe = "https://example.com/"
	}
	probe, e := url.Parse(c.Probe)
	if e != nil || probe.Scheme != "https" || probe.Host == "" || probe.User != nil {
		return c, errors.New("invalid HTTPS probe")
	}
	var names []string
	switch c.Mode {
	case "direct", "automatic":
		names = []string{c.Mode}
	case "selected":
		switch list := sections["main"]["provider"].(type) {
		case []any:
			for _, entry := range list {
				s, _ := entry.(string)
				names = append(names, s)
			}
		case string:
			names = []string{list}
		}
	default:
		return c, errors.New("unknown internet source")
	}
	if len(names) == 0 || len(names) > 8 {
		return c, errors.New("choose one to eight providers")
	}
	seen := map[string]bool{}
	for _, name := range names {
		if !nameRE.MatchString(name) || (c.Mode == "selected" && (name == "direct" || name == "automatic")) || val(name, ".type") != "uplink" {
			return c, fmt.Errorf("invalid uplink %q", name)
		}
		p := Profile{name, val(name, "device"), val(name, "gateway")}
		if !nameRE.MatchString(p.Device) || p.Device == "lo" || p.Device == "br-freedom" || seen[p.Device] || (p.Gateway != "" && net.ParseIP(p.Gateway).To4() == nil) {
			return c, errors.New("invalid uplink device or gateway")
		}
		if c.Mode != "direct" && (p.Gateway != "" || p.Device == val("direct", "device")) {
			return c, errors.New("paid exits require distinct point-to-point devices")
		}
		seen[p.Device] = true
		c.Profiles = append(c.Profiles, p)
	}
	return c, nil
}
