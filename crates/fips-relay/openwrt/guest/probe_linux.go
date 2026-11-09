package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"syscall"
	"time"
)

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
