package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFeeAdjustedCashuAndProofReplay(t *testing.T) {
	const mint = "https://mint.example"
	const id = "009a1f293253e41e"
	token := func(memo string, reverse bool) string {
		proofs := []map[string]any{{"id": id, "amount": 8, "secret": "one"}, {"id": id, "amount": 4, "secret": "two"}, {"id": id, "amount": 1, "secret": "three"}}
		if reverse {
			proofs[0], proofs[1] = proofs[1], proofs[0]
		}
		b, _ := json.Marshal(map[string]any{"token": []map[string]any{{"mint": mint, "proofs": proofs}}, "memo": memo})
		return "cashuA" + base64.RawURLEncoding.EncodeToString(b)
	}
	a := token("first", false)
	b := token("different", true)
	sets := []keyset{{id, "sat", 400}}
	x, net, e := proofKeys(a, mint, 10, sets)
	if e != nil || net != 11 {
		t.Fatal(net, e)
	}
	y, _, e := proofKeys(b, mint, 10, sets)
	if e != nil || strings.Join(x, ".") != strings.Join(y, ".") {
		t.Fatal("proof identity changed with serialization")
	}
	for _, price := range []int{9, 12} {
		if _, _, e := proofKeys(a, mint, price, sets); e == nil {
			t.Fatal("unexpected price accepted", price)
		}
	}
	if _, _, e := proofKeys(a, "https://different", 10, sets); e == nil {
		t.Fatal("unexpected mint")
	}
	if _, _, e := proofKeys(a, mint, 10, nil); e == nil {
		t.Fatal("unknown keyset accepted")
	}
}
func TestOnlyBoundSettledInvoiceOpensPass(t *testing.T) {
	q := map[string]string{"quote": "q", "request": "lnbc-bind", "state": "UNPAID"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/mint/quote/bolt11/q" {
			t.Error(r.URL.Path)
		}
		json.NewEncoder(w).Encode(q)
	}))
	defer server.Close()
	o := Order{Mint: server.URL, Quote: Quote{ID: "q", Invoice: "lnbc-bind"}}
	check := func(want bool) {
		t.Helper()
		got, _ := paidInvoice(context.Background(), o)
		if got != want {
			t.Fatal("paid", got, "want", want)
		}
	}
	check(false)
	q["state"] = "PAID"
	check(true)
	q["state"] = "ISSUED"
	check(true)
	q["request"] = "different"
	check(false)
}
func TestDurableGrantsStackAndDoNotRestartOnRetry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	if e := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\ncat >/dev/null\n"), 0700); e != nil {
		t.Fatal(e)
	}
	c := Config{State: filepath.Join(dir, "passes.json")}
	p, e := openPortal(c)
	if e != nil {
		t.Fatal(e)
	}
	o := Order{IP: "192.0.2.2", MAC: "02:00:00:00:00:01", Minutes: 2}
	if e = p.unlock(context.Background(), "first", o); e != nil {
		t.Fatal(e)
	}
	until := p.orders["first"].Until
	p, e = openPortal(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.unlock(context.Background(), "first", p.orders["first"]); e != nil || p.orders["first"].Until != until {
		t.Fatal("retry changed expiry")
	}
	if e = p.unlock(context.Background(), "second", o); e != nil || p.orders["second"].Until != until+120 {
		t.Fatal("passes do not stack")
	}
	if strings.Contains(clientSets(p.orders, time.Now().Add(time.Hour).Unix()), "add element") {
		t.Fatal("expired pass survived")
	}
}
func TestSelectedProfilesCannotFallBackToDirect(t *testing.T) {
	sections := map[string]map[string]any{"main": {"mode": "selected", "address": "192.0.2.1", "price_sat": "10", "minutes": "20", "wallet": "/bin/nvpn", "nvpn_config": "/etc/merchant.toml", "state": "/tmp/test", "mint": "https://mint.example", "tls_name": "guest.example", "tls_cert": "/etc/cert", "tls_key": "/etc/key", "provider": []any{"b", "a"}}, "a": {".type": "uplink", "device": "wg-a"}, "b": {".type": "uplink", "device": "wg-b"}, "direct": {".type": "uplink", "device": "eth0"}}
	c, e := parseConfig(sections)
	if e != nil || len(c.Profiles) != 2 || c.Profiles[0].Name != "b" {
		t.Fatal("operator order lost", e)
	}
	for _, bad := range [][]any{{"direct"}, {"missing"}, {"a", "a"}, {}} {
		sections["main"]["provider"] = bad
		if _, e = parseConfig(sections); e == nil {
			t.Fatal("unsafe selection", bad)
		}
	}
}
