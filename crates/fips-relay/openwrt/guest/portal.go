package main

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

type Order struct {
	IP, MAC, Mint, Method  string
	Price, Minutes, NetSat int
	Created, Until         int64
	Quote                  Quote
	Proofs                 []string
}
type Portal struct {
	c      Config
	mu     sync.Mutex
	orders map[string]Order
	active string
}

func openPortal(c Config) (*Portal, error) {
	p := &Portal{c: c, orders: map[string]Order{}}
	data, e := os.ReadFile(c.State)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if e == nil {
		if len(data) > 32<<20 {
			return nil, errors.New("payment store full")
		}
		if e = json.Unmarshal(data, &p.orders); e != nil || p.orders == nil {
			return nil, errors.New("invalid saved payments")
		}
	}
	return p, nil
}
func (p *Portal) save(id string, o Order) error {
	// Caller holds the lock. Publish before granting network access.
	was, exists := p.orders[id]
	p.orders[id] = o
	ok := false
	defer func() {
		if !ok {
			if exists {
				p.orders[id] = was
			} else {
				delete(p.orders, id)
			}
		}
	}()
	dir := filepath.Dir(p.c.State)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".passes-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = json.NewEncoder(f).Encode(p.orders); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = os.Rename(f.Name(), p.c.State); e != nil {
		return e
	}
	ok = true
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (p *Portal) syncClients(ctx context.Context) error {
	return nft(ctx, clientSets(p.orders, time.Now().Unix()))
}
func (p *Portal) unlock(ctx context.Context, id string, o Order) error {
	if o.Until == 0 {
		start := time.Now().Unix()
		for _, pass := range p.orders {
			if pass.MAC == o.MAC && pass.Until > start {
				start = pass.Until
			}
		}
		o.Until = start + int64(o.Minutes)*60
		if e := p.save(id, o); e != nil {
			return e
		}
	}
	return p.syncClients(ctx)
}
func (p *Portal) checkout(ctx context.Context, id, ip, mac, action, token string, tls bool) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active == "" {
		return "", errors.New("the internet connection is unavailable")
	}
	if action == "start-lightning" || action == "start-cashu" {
		if action == "start-cashu" && !tls {
			return "", errors.New("open the secure checkout to pay with a token")
		}
		method := strings.TrimPrefix(action, "start-")
		for k, o := range p.orders {
			if o.MAC == mac && o.IP == ip && (o.Until > time.Now().Unix() || (o.Until == 0 && o.Method == method && o.Mint == p.c.Mint && o.Price == p.c.Price && (len(o.Proofs) > 0 || o.Created > time.Now().Unix()-600) && (o.Method != "lightning" || o.Quote.Expiry > time.Now().Unix()))) {
				return k, nil
			}
		}
		if len(p.orders) >= 8192 {
			return "", errors.New("payment store is full")
		}
		var key [20]byte
		if _, e := rand.Read(key[:]); e != nil {
			return "", e
		}
		id = hex.EncodeToString(key[:])
		o := Order{IP: ip, MAC: mac, Mint: p.c.Mint, Method: method, Price: p.c.Price, Minutes: p.c.Minutes, Created: time.Now().Unix()}
		if method == "lightning" {
			q, e := invoice(ctx, p.c)
			if e != nil {
				return "", e
			}
			o.Quote = q
		}
		return id, p.save(id, o)
	}
	o, exists := p.orders[id]
	if !exists || o.MAC != mac || o.IP != ip {
		return "", errors.New("pass not found for this device")
	}
	if o.Until != 0 {
		if o.Until <= time.Now().Unix() {
			return "", errors.New("this pass has expired")
		}
		return id, p.syncClients(ctx)
	}
	switch action {
	case "recover":
		if !tls || o.Method != "cashu" || len(o.Proofs) == 0 || o.NetSat <= 0 {
			return "", errors.New("no pending Cashu payment")
		}
		cfg := p.c
		cfg.Price = o.NetSat
		cfg.Mint = o.Mint
		if e := receive(ctx, cfg, id, o.Proofs, ""); e != nil {
			return "", errors.New("no completed wallet receipt yet; retain your original token")
		}
		o.Minutes = o.Minutes * o.NetSat / o.Price
	case "check":
		if o.Method != "lightning" {
			return "", errors.New("this pass uses Cashu")
		}
		paid, e := paidInvoice(ctx, o)
		if e != nil {
			return "", e
		}
		if !paid {
			return id, nil
		}
	case "redeem":
		if !tls || o.Method != "cashu" {
			return "", errors.New("a secure Cashu checkout is required")
		}
		sets, e := mintKeysets(ctx, o.Mint)
		if e != nil {
			return "", errors.New("mint fee schedule unavailable")
		}
		keys, netValue, e := proofKeys(token, o.Mint, o.Price, sets)
		if e != nil {
			return "", e
		}
		if len(o.Proofs) > 0 && !slices.Equal(keys, o.Proofs) {
			return "", errors.New("retry with the original token")
		}
		for other, v := range p.orders {
			if other != id && v.Mint == o.Mint && len(v.Proofs) > 0 {
				for _, key := range keys {
					if _, found := slices.BinarySearch(v.Proofs, key); found {
						return "", errors.New("token already belongs to another pass")
					}
				}
			}
		}
		if len(o.Proofs) == 0 {
			o.Proofs = keys
			o.NetSat = netValue
			if e = p.save(id, o); e != nil {
				return "", e
			}
		}
		cfg := p.c
		cfg.Price = netValue
		cfg.Mint = o.Mint
		if e = receive(ctx, cfg, id, keys, token); e != nil {
			return "", errors.New("payment unconfirmed; retain the original token and retry")
		}
		o.Minutes = o.Minutes * netValue / o.Price
	default:
		return "", errors.New("unknown checkout action")
	}
	return id, p.unlock(ctx, id, o)
}

//go:embed portal.html
var portalHTML string
var page = template.Must(template.New("portal").Parse(portalHTML))

func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	host := net.JoinHostPort(p.c.Address, "2080")
	scheme := "http"
	secure := r.TLS != nil
	tlsURL := ""
	if p.c.TLSName != "" {
		tlsURL = "https://" + net.JoinHostPort(p.c.TLSName, "2443") + "/"
	}
	if secure {
		host = net.JoinHostPort(p.c.TLSName, "2443")
		scheme = "https"
	}
	if r.Host != host || r.URL.Path != "/" {
		if r.Method == "GET" || r.Method == "HEAD" {
			http.Redirect(w, r, scheme+"://"+host+"/", 302)
		} else {
			http.Error(w, "Use the Freedom checkout", 400)
		}
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	mac, e := clientMAC(ip)
	if e != nil {
		http.Error(w, "Join Freedom Wi-Fi to use this page", 403)
		return
	}
	id := r.URL.Query().Get("id")
	if r.Method == "POST" {
		if !secure {
			http.Error(w, "Open the secure checkout", 403)
			return
		}
		if r.Header.Get("Origin") != scheme+"://"+host {
			http.Error(w, "Reopen the checkout", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64000)
		if r.ParseForm() != nil {
			http.Error(w, "Invalid payment request", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		id, e = p.checkout(ctx, r.PostForm.Get("id"), ip, mac, r.PostForm.Get("action"), strings.TrimSpace(r.PostForm.Get("token")), secure)
		if e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		http.Redirect(w, r, "/?id="+url.QueryEscape(id), 303)
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	p.mu.Lock()
	// DHCP can renew to a different address. Only the station currently
	// observed on the isolated bridge can move its own unexpired pass.
	for key, pass := range p.orders {
		if pass.MAC == mac && pass.IP != ip && pass.Until > time.Now().Unix() {
			pass.IP = ip
			if err := p.save(key, pass); err != nil {
				p.mu.Unlock()
				http.Error(w, "Could not restore pass", 503)
				return
			}
			if err := p.syncClients(r.Context()); err != nil {
				p.mu.Unlock()
				http.Error(w, "Could not restore access", 503)
				return
			}
		}
	}
	o := p.orders[id]
	up := p.active != ""
	if o.IP != ip || o.MAC != mac {
		o = Order{}
		id = ""
	}
	if id == "" {
		for _, v := range p.orders {
			if v.IP == ip && v.MAC == mac && v.Until > time.Now().Unix() {
				o = v
				break
			}
		}
	}
	p.mu.Unlock()
	price, minutes := p.c.Price, p.c.Minutes
	if o.Price > 0 {
		price = o.Price
		minutes = o.Minutes
	}
	link := template.URL("")
	if strings.HasPrefix(strings.ToLower(o.Quote.Invoice), "ln") {
		link = template.URL("lightning:" + o.Quote.Invoice)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, map[string]any{"Up": up, "Active": o.Until > time.Now().Unix(), "End": time.Unix(o.Until, 0).UTC().Format("15:04"), "Price": price, "Minutes": minutes, "ID": id, "Mint": o.Mint, "Cashu": o.Method == "cashu", "PendingCashu": len(o.Proofs) > 0, "Invoice": o.Quote.Invoice, "Link": link, "Secure": secure, "TLSURL": tlsURL})
}
