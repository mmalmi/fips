package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Index each proof, regardless of token encoding, memo, order or grouping.
// The wallet is the authority on the signature, spend state and credited amount.
type keyset struct {
	ID   string `json:"id"`
	Unit string `json:"unit"`
	Fee  uint64 `json:"input_fee_ppk"`
}

func mintKeysets(ctx context.Context, mint string) ([]keyset, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(mint, "/")+"/v1/keysets", nil)
	if e != nil {
		return nil, e
	}
	client := http.Client{Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	var r struct{ Keysets []keyset }
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&r) != nil || len(r.Keysets) == 0 {
		return nil, errors.New("mint fee schedule unavailable")
	}
	return r.Keysets, nil
}
func proofKeys(token, mint string, price int, sets []keyset) ([]string, int, error) {
	bad := errors.New("use an exact-price sat token from the accepted mint")
	if len(token) < 8 || len(token) > 32768 {
		return nil, 0, bad
	}
	raw, e := base64.RawURLEncoding.DecodeString(strings.TrimRight(token[6:], "="))
	if e != nil {
		return nil, 0, bad
	}
	keys := []string{}
	sum, feePPK := uint64(0), uint64(0)
	seen := map[string]bool{}
	add := func(secret string, amount uint64, id string) bool {
		if secret == "" || len(secret) > 4096 || amount == 0 || amount > uint64(price)*2+128 || len(keys) >= 128 {
			return false
		}
		var matches int
		for _, k := range sets {
			if k.Unit == "sat" && len(id) >= 16 && strings.HasPrefix(k.ID, id) {
				if k.Fee > 1000000 {
					return false
				}
				feePPK += k.Fee
				matches++
			}
		}
		if matches != 1 {
			return false
		}
		sum += amount
		hash := sha256.Sum256([]byte("Secp256k1_HashToCurve_Cashu_" + secret))
		key := hex.EncodeToString(hash[:])
		if seen[key] {
			return false
		}
		seen[key] = true
		keys = append(keys, key)
		return true
	}
	switch token[:6] {
	case "cashuA":
		var t struct {
			Unit  string
			Token []struct {
				Mint   string
				Proofs []struct {
					Amount uint64
					ID     string
					Secret string
				}
			}
		}
		if json.Unmarshal(raw, &t) != nil || (t.Unit != "" && t.Unit != "sat") || len(t.Token) != 1 || t.Token[0].Mint != mint {
			return nil, 0, bad
		}
		for _, p := range t.Token[0].Proofs {
			if !add(p.Secret, p.Amount, p.ID) {
				return nil, 0, bad
			}
		}
	case "cashuB":
		type proof struct {
			Amount uint64 `cbor:"a"`
			Secret string `cbor:"s"`
		}
		var t struct {
			Mint   string `cbor:"m"`
			Unit   string `cbor:"u"`
			Groups []struct {
				ID     []byte  `cbor:"i"`
				Proofs []proof `cbor:"p"`
			} `cbor:"t"`
		}
		dec, _ := (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxArrayElements: 256, MaxMapPairs: 128, MaxNestedLevels: 12, IndefLength: cbor.IndefLengthForbidden}).DecMode()
		if dec.Unmarshal(raw, &t) != nil || t.Mint != mint || t.Unit != "sat" {
			return nil, 0, bad
		}
		for _, g := range t.Groups {
			for _, p := range g.Proofs {
				if !add(p.Secret, p.Amount, hex.EncodeToString(g.ID)) {
					return nil, 0, bad
				}
			}
		}
	default:
		return nil, 0, bad
	}
	fee := (feePPK + 999) / 1000
	if sum < fee+uint64(price) || sum > fee+uint64(price)+1 {
		return nil, 0, bad
	}
	sort.Strings(keys)
	return keys, int(sum - fee), nil
}

// wallet is an operator-owned executable. A remote wallet adapter receives a
// fixed operation and data on stdin. Never forward guest-supplied CLI arguments.
func wallet(ctx context.Context, c Config, action string, args []string, input string, result any) error {
	argv := []string{c.Wallet, "paid-exit", "wallet", "--config", c.NVPNConfig, "--json", action}
	argv = append(argv, args...)
	data, e := cmd(ctx, input, argv...)
	if e != nil {
		return errors.New("merchant wallet unavailable")
	}
	if len(data) > 8<<20 {
		return errors.New("wallet response too large")
	}
	return json.Unmarshal(data, result)
}

type Quote struct {
	ID      string `json:"quote_id"`
	Invoice string `json:"payment_request"`
	Mint    string `json:"mint_url"`
	Amount  int    `json:"amount_sat"`
	Expiry  int64  `json:"expiry_unix"`
}

func invoice(ctx context.Context, c Config) (Quote, error) {
	var r struct{ Quote Quote }
	e := wallet(ctx, c, "topup", []string{fmt.Sprint(c.Price), "--mint", c.Mint}, "", &r)
	if e != nil || r.Quote.ID == "" || len(r.Quote.ID) > 256 || r.Quote.Invoice == "" || r.Quote.Mint != c.Mint || r.Quote.Amount != c.Price || r.Quote.Expiry <= time.Now().Unix() {
		return Quote{}, errors.New("could not create a payable invoice")
	}
	return r.Quote, nil
}
func paidInvoice(ctx context.Context, o Order) (bool, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(o.Mint, "/")+"/v1/mint/quote/bolt11/"+url.PathEscape(o.Quote.ID), nil)
	if e != nil {
		return false, e
	}
	client := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(req)
	if e != nil {
		return false, e
	}
	defer res.Body.Close()
	var q struct{ Quote, Request, State string }
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 16384)).Decode(&q) != nil || q.Quote != o.Quote.ID || q.Request != o.Quote.Invoice {
		return false, errors.New("mint did not confirm this invoice")
	}
	return q.State == "PAID" || q.State == "ISSUED", nil
}
func receive(ctx context.Context, c Config, id string, keys []string, token string) error {
	var r struct {
		Received struct {
			Mint   string `json:"mint_url"`
			Unit   string
			Amount int `json:"amount_sat"`
		}
	}
	request, e := json.Marshal(map[string]any{"order": id, "seeds": keys, "mint": c.Mint, "amount": c.Price, "token": token})
	if e != nil {
		return e
	}
	if e := wallet(ctx, c, "freedom-receive", nil, string(request), &r); e != nil {
		return e
	}
	if r.Received.Mint != c.Mint || r.Received.Unit != "sat" || r.Received.Amount != c.Price {
		return errors.New("wallet receipt does not cover this pass")
	}
	return nil
}
