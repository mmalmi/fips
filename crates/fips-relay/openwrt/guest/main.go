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
func withHotspotLock(wait bool, action func() error) error {
	// One writer per hotspot, including manual starts and overlapping procd retries.
	f, e := os.OpenFile("/var/run/freedom-guest.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if !wait || !errors.Is(e, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			return fmt.Errorf("hotspot is already running or locked: %w", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return action()
}
func cleanup() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := cleanupRouting(ctx)
	if e == nil {
		os.Remove("/var/run/freedom-guest.uplink")
	}
	return e
}
func run() (err error) {
	c, e := readConfig()
	if e != nil {
		return e
	}
	if c.Mode == "off" {
		return cleanup()
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if e = clearUplink(ctx); e != nil {
		return errors.New("install the Freedom firewall includes first")
	}
	defer func() {
		err = errors.Join(err, cleanup())
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
	var e error
	switch {
	case len(os.Args) == 1:
		e = withHotspotLock(false, run)
	case len(os.Args) == 2 && os.Args[1] == "--cleanup":
		e = withHotspotLock(true, cleanup)
	default:
		log.Fatal("unexpected arguments")
	}
	if e != nil {
		log.Fatal(e)
	}
}
