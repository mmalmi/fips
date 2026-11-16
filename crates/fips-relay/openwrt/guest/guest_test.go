package main

import (
	"bytes"
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

func TestSurplusCashuGrantsSecondsAndKeepsOriginalTerms(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	if e := os.WriteFile(filepath.Join(dir, "nft"), []byte("#!/bin/sh\ncat >/dev/null\n"), 0700); e != nil {
		t.Fatal(e)
	}
	p, e := openPortal(Config{State: filepath.Join(dir, "passes.json")})
	if e != nil {
		t.Fatal(e)
	}
	anchor := time.Now().Unix() + 100
	p.orders["previous"] = Order{MAC: "02:00:00:00:00:01", Until: anchor}
	o := Order{IP: "192.0.2.2", MAC: "02:00:00:00:00:01", Method: "cashu", Price: 10, Minutes: 1, NetSat: 11}
	if e := p.unlock(context.Background(), "cashu", o); e != nil {
		t.Fatal(e)
	}
	if got := p.orders["cashu"]; got.Until != anchor+66 || got.Minutes != 1 {
		t.Fatalf("surplus time or original terms lost: %+v", got)
	}
	p, e = openPortal(p.c)
	if e != nil {
		t.Fatal(e)
	}
	if e := p.unlock(context.Background(), "cashu", p.orders["cashu"]); e != nil || p.orders["cashu"].Until != anchor+66 {
		t.Fatal("restart/retry changed the granted time", e)
	}
	o.Price, o.NetSat = 100, 101
	if e := p.unlock(context.Background(), "fractional", o); e != nil || p.orders["fractional"].Until != anchor+66+61 {
		t.Fatal("a fractional surplus second was lost", e)
	}
}

func TestCashuReplacementPreservesOriginalClaimsAndRecovery(t *testing.T) {
	c := Config{State: filepath.Join(t.TempDir(), "passes.json"), Mint: "https://mint.example", Price: 10, Minutes: 1}
	p, e := openPortal(c)
	if e != nil {
		t.Fatal(e)
	}
	p.active = "test"
	o := Order{IP: "192.0.2.2", MAC: "02:00:00:00:00:01", Mint: c.Mint, Method: "cashu", Price: 10, Minutes: 1, NetSat: 11, Proofs: []string{"claimed-proof"}, Created: time.Now().Unix()}
	if e := p.save("original", o); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	if _, e := p.checkout(ctx, "original", o.IP, "02:00:00:00:00:02", "replace-cashu", "", true); e == nil {
		t.Fatal("another device replaced this payment")
	}
	if _, e := p.checkout(ctx, "original", o.IP, o.MAC, "replace-cashu", "", false); e == nil {
		t.Fatal("insecure replacement accepted")
	}
	id, e := p.checkout(ctx, "original", o.IP, o.MAC, "replace-cashu", "", true)
	if e != nil || id == "original" || id == "" {
		t.Fatal("could not use a separate token", id, e)
	}
	if got := p.orders["original"]; len(got.Proofs) != 1 || got.Proofs[0] != "claimed-proof" || got.NetSat != 11 || got.Until != 0 {
		t.Fatal("replacement changed the original payment", got)
	}
	if retry, e := p.checkout(ctx, "original", o.IP, o.MAC, "replace-cashu", "", true); e != nil || retry != id || len(p.orders) != 2 {
		t.Fatal("replacement retry created another order", retry, e)
	}
	if current, e := p.checkout(ctx, "", o.IP, o.MAC, "start-cashu", "", true); e != nil || current != id {
		t.Fatal("checkout returned to the trapped order", current, e)
	}
}

func TestSeparatePaymentKeepsReplayClaimsAndRecoversAmbiguousReceipt(t *testing.T) {
	const keysetID = "009a1f293253e41e"
	mint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/keysets" {
			t.Error(r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{"keysets": []keyset{{keysetID, "sat", 0}}})
	}))
	defer mint.Close()
	token := func(secret string) string {
		proofs := []map[string]any{}
		for i, amount := range []int{8, 2, 1} {
			proofs = append(proofs, map[string]any{"id": keysetID, "amount": amount, "secret": secret + strings.Repeat("x", i)})
		}
		data, _ := json.Marshal(map[string]any{"token": []map[string]any{{"mint": mint.URL, "proofs": proofs}}})
		return "cashuA" + base64.RawURLEncoding.EncodeToString(data)
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	writeExecutable := func(name, body string) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0700); e != nil {
			t.Fatal(e)
		}
	}
	writeExecutable("nft", "cat >/dev/null\n")
	writeExecutable("wallet", "exit 1\n")
	c := Config{State: filepath.Join(dir, "passes.json"), Wallet: filepath.Join(dir, "wallet"), Mint: mint.URL, Price: 10, Minutes: 1}
	p, e := openPortal(c)
	if e != nil {
		t.Fatal(e)
	}
	p.active = "test"
	const ip, mac = "192.0.2.2", "02:00:00:00:00:01"
	ctx := context.Background()
	original, e := p.checkout(ctx, "", ip, mac, "start-cashu", "", true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := p.checkout(ctx, original, ip, mac, "redeem", token("original"), true); e == nil {
		t.Fatal("unconfirmed receipt granted access")
	}
	replacement, e := p.checkout(ctx, original, ip, mac, "replace-cashu", "", true)
	if e != nil {
		t.Fatal(e)
	}
	p, e = openPortal(c)
	if e != nil || p.orders[replacement].Replaces != original {
		t.Fatal("restart lost the recovery link", e)
	}
	p.active = "test"
	if _, e := p.checkout(ctx, replacement, ip, mac, "redeem", token("original"), true); e == nil || !strings.Contains(e.Error(), "already belongs") {
		t.Fatal("replaced proof claims no longer prevent replay", e)
	}
	receipt, _ := json.Marshal(map[string]any{"received": map[string]any{"mint_url": mint.URL, "unit": "sat", "amount_sat": 11}})
	writeExecutable("wallet", "cat >/dev/null\nprintf '%s\\n' '"+string(receipt)+"'\n")
	if _, e := p.checkout(ctx, replacement, ip, mac, "redeem", token("different"), true); e != nil {
		t.Fatal("separate valid token could not pay", e)
	}
	until := p.orders[replacement].Until
	if _, e := p.checkout(ctx, original, ip, mac, "recover", "", true); e != nil || p.orders[original].Until != until+66 {
		t.Fatal("original receipt recovery did not stack its full credit", e)
	}
	if _, e := p.checkout(ctx, original, ip, mac, "recover", "", true); e != nil || p.orders[original].Until != until+66 {
		t.Fatal("receipt retry granted time twice", e)
	}
}

func TestPaymentRecoveryPages(t *testing.T) {
	for _, tc := range []struct {
		name, replaces string
		pending        bool
	}{
		{"pending", "", true},
		{"separate", "original", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			e := page.Execute(&out, map[string]any{"Up": true, "Secure": true, "Cashu": true, "Price": 10, "Minutes": 1, "ID": "checkout", "Mint": "https://mint.example", "PendingCashu": tc.pending, "Replaces": tc.replaces, "Error": "Payment unconfirmed; retain your original token."})
			if e != nil {
				t.Fatal(e)
			}
			html := out.String()
			if strings.Contains(html, `value="replace-cashu"`) != tc.pending || strings.Contains(html, `href="/?id=original"`) != (tc.replaces != "") || !strings.Contains(html, `role="alert"`) {
				t.Fatal("recovery actions or original payment link missing")
			}
			if dir := os.Getenv("FREEDOM_TEST_OUTPUT"); dir != "" {
				if e := os.WriteFile(filepath.Join(dir, tc.name+".html"), out.Bytes(), 0600); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
