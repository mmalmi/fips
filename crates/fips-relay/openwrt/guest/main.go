package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (p *Portal) reconcile(ctx context.Context) {
	name := ""
	var selected Profile
	for _, candidate := range p.c.Profiles {
		if ready(ctx, p.c, candidate) {
			name = candidate.Name
			selected = candidate
			break
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if name == "" {
		_ = clearUplink(ctx)
	} else if setUplink(ctx, selected) != nil || p.syncClients(ctx) != nil {
		_ = clearUplink(ctx)
		name = ""
	}
	if name != p.active {
		log.Printf("guest internet source changed to %q", name)
	}
	p.active = name
	if name == "" {
		os.Remove("/var/run/freedom-guest.uplink")
	} else {
		_ = os.WriteFile("/var/run/freedom-guest.uplink", []byte(name+"\n"), 0644)
	}
}
func run() error {
	c, e := readConfig()
	if e != nil {
		return e
	}
	if c.Mode == "off" {
		return nil
	}
	// One writer per hotspot, including manual starts and overlapping procd retries.
	f, e := os.OpenFile("/var/run/freedom-guest.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("hotspot is already running")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if e = clearUplink(ctx); e != nil {
		return errors.New("install the Freedom firewall includes first")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = clearUplink(cleanup)
		os.Remove("/var/run/freedom-guest.uplink")
	}()
	if e = setupRules(ctx); e != nil {
		return fmt.Errorf("guest routing: %w", e)
	}
	p, e := openPortal(c)
	if e != nil {
		return e
	}
	server := func(port string) *http.Server {
		return &http.Server{Addr: net.JoinHostPort(c.Address, port), Handler: p, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	}
	errs := make(chan error, 2)
	httpd := server("2080")
	defer httpd.Close()
	if c.Cert != "" {
		tlsd := server("2443")
		defer tlsd.Close()
		go func() { errs <- tlsd.ListenAndServeTLS(c.Cert, c.Key) }()
	}
	go func() { errs <- httpd.ListenAndServe() }()
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		p.reconcile(ctx)
		select {
		case <-ctx.Done():
			return nil
		case e = <-errs:
			return e
		case <-tick.C:
		}
	}
}
func main() {
	if len(os.Args) != 1 {
		log.Fatal("unexpected arguments")
	}
	if e := run(); e != nil {
		log.Fatal(e)
	}
}
