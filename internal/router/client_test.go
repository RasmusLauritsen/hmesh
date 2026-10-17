package router

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHuaweiJavaScriptFixture(t *testing.T) {
	salt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	first := strings.Repeat("ab", 32)
	final := first + strings.Repeat("cd", 32)
	proof, server, auth, err := derive("test-password-not-a-secret", salt, 1000, first, final)
	if err != nil {
		t.Fatal(err)
	}
	// Captured from the router-served CryptoJS implementation with public fake inputs.
	if hex.EncodeToString(proof) != "c1daf607086590326ab83269758703d7f89587019320b4d848226083d8e28638" {
		t.Fatal("proof differs from vendor JS")
	}
	if hex.EncodeToString(mac(auth, server)) != "c62f0b60a9a809f63c6caf086800d923195d68e3dadeab0f590c482b19d0d8f9" {
		t.Fatal("server proof differs")
	}
	pub, _ := hex.DecodeString("a1b2c3d4")
	if hex.EncodeToString(mac(server, pub)) != "11c28c41671a287104233d2767a9f3170a26f0b142dfcbc7cfdfcc02d69c5f46" {
		t.Fatal("public key proof differs")
	}
}

func TestLoginCookieAndSignatures(t *testing.T) {
	for _, bad := range []string{"", "nonce", "server", "rsa", "challenge"} {
		t.Run(bad, func(t *testing.T) {
			var first, final string
			posts := 0
			salt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/html/index.html":
					if r.Method != "GET" {
						t.Error("page method")
					}
					w.Write([]byte(`<meta name="csrf_param" content="p1"/><meta name="csrf_token" content="t1"/>`))
				case "/api/system/user_login_nonce":
					posts++
					var body struct {
						Data map[string]string
						CSRF map[string]string
					}
					json.NewDecoder(r.Body).Decode(&body)
					if body.CSRF["csrf_token"] != "t1" || body.Data["username"] != "admin" {
						t.Error("challenge envelope")
					}
					first = body.Data["firstnonce"]
					final = first + strings.Repeat("cd", 32)
					if bad == "nonce" {
						final = "unrelated"
					}
					code := 0
					if bad == "challenge" {
						code = 1
					}
					json.NewEncoder(w).Encode(map[string]any{"err": code, "salt": hex.EncodeToString(salt), "iterations": 1000, "servernonce": final, "csrf_param": "p2", "csrf_token": "t2"})
				case "/api/system/user_login_proof":
					posts++
					var body struct {
						Data map[string]string
						CSRF map[string]string
					}
					json.NewDecoder(r.Body).Decode(&body)
					proof, server, auth, _ := derive("fake-password", salt, 1000, first, final)
					if body.Data["clientproof"] != hex.EncodeToString(proof) || body.CSRF["csrf_token"] != "t2" {
						t.Error("proof envelope")
					}
					pub, _ := hex.DecodeString("a1b2c3d4")
					sig := mac(auth, server)
					rsaSig := mac(server, pub)
					if bad == "server" {
						sig = make([]byte, 32)
					}
					if bad == "rsa" {
						rsaSig = make([]byte, 32)
					}
					http.SetCookie(w, &http.Cookie{Name: "SessionID_R3", Value: "fake-session", Path: "/", Secure: true})
					json.NewEncoder(w).Encode(map[string]any{"err": 0, "rsan": "a1b2c3d4", "serversignature": hex.EncodeToString(sig), "rsapubkeysignature": hex.EncodeToString(rsaSig)})
				case "/api/system/deviceinfo":
					cookie, err := r.Cookie("SessionID_R3")
					if err != nil || cookie.Value != "fake-session" {
						t.Error("missing cookie")
					}
					json.NewEncoder(w).Encode(map[string]any{"SoftwareVersion": "test"})
				default:
					t.Error("unexpected path")
					http.NotFound(w, r)
				}
			}))
			defer s.Close()
			c, err := New(Options{URL: s.URL, Username: "admin", Insecure: true})
			if err != nil {
				t.Fatal(err)
			}
			err = c.Login(context.Background(), "fake-password")
			if bad == "" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.Get(context.Background(), "status"); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("bad signature/challenge accepted")
			}
			want := 2
			if bad == "nonce" || bad == "challenge" {
				want = 1
			}
			if posts != want {
				t.Fatalf("posts=%d, want %d", posts, want)
			}
		})
	}
}

func TestTransportSecurity(t *testing.T) {
	for _, raw := range []string{"http://192.168.3.1", "https://u:p@router", "https://router/api", "https://router?x=1", "https://router/#x"} {
		if _, err := New(Options{URL: raw}); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	called := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called++; w.Write([]byte(`{}`)) }))
	defer target.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer s.Close()
	c, _ := New(Options{URL: s.URL, Insecure: true})
	if _, err := c.Get(context.Background(), "status"); err == nil {
		t.Fatal("redirect accepted")
	}
	if called != 0 {
		t.Fatal("followed redirect")
	}
	c, _ = New(Options{URL: s.URL})
	if _, err := c.Get(context.Background(), "status"); err == nil {
		t.Fatal("untrusted TLS accepted by default")
	}
}

func TestRedaction(t *testing.T) {
	v := map[string]any{"csrf_token": "secret", "Cookie": "secret", "Password": "secret", "WpaPreSharedKey": "secret", "nested": []any{map[string]any{"pwd": "secret", "IPAddress": "192.0.2.2"}}}
	b, _ := json.Marshal(Redact(v))
	if strings.Contains(string(b), "secret") {
		t.Fatal("secret leaked")
	}
	if !strings.Contains(string(b), "192.0.2.2") {
		t.Fatal("inventory unexpectedly redacted")
	}
}

func TestRedactionNestedCredentialFields(t *testing.T) {
	keys := []string{"PASSWORD", "passwd", "pwd", "WepKey", "WpaPreSharedKey", "Set-Cookie", "CSRF_TOKEN", "SessionID_R3", "session_id", "session-id", "Authorization", "Proxy-Authorization", "access_token", "refreshToken", "ID-TOKEN"}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			inner := map[string]any{key: "sensitive-fixture", "IPAddress": "192.0.2.2", "enabled": true, "count": 2, "optional": nil}
			input := map[string]any{"nested": []any{map[string]any{"deeper": inner}, "ordinary text"}}
			want := map[string]any{"nested": []any{map[string]any{"deeper": map[string]any{"IPAddress": "192.0.2.2", "enabled": true, "count": 2, "optional": nil}}, "ordinary text"}}
			if got := Redact(input); !reflect.DeepEqual(got, want) {
				t.Fatal("credential field retained or ordinary data altered")
			}
			if inner[key] != "sensitive-fixture" {
				t.Fatal("redaction mutated input")
			}
		})
	}
}

type fakeDHCP struct {
	t      *testing.T
	items  []map[string]any
	server map[string]any
	hosts  []any
	posts  int
	mode   string
}

func newDHCP(t *testing.T) (*Client, *fakeDHCP) {
	f := &fakeDHCP{t: t, items: []map[string]any{{"ID": "reservation.1.", "Enable": true, "Chaddr": "02:00:00:00:00:01", "Yiaddr": "192.168.3.10"}},
		server: map[string]any{"ServerEnable": true, "MinIP": "192.168.3.2", "MaxIP": "192.168.3.254"}, hosts: []any{}}
	s := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(s.Close)
	c, err := New(Options{URL: s.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func (f *fakeDHCP) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		f.posts++
		if r.URL.Path != "/api/ntwk/lan_ipaddressreserve" {
			f.t.Error("unexpected write path")
		}
		var body struct {
			Action string
			Data   map[string]any
			CSRF   map[string]string
		}
		d := json.NewDecoder(r.Body)
		d.UseNumber()
		if err := d.Decode(&body); err != nil {
			f.t.Error(err)
		}
		if f.mode == "reject" {
			w.Write([]byte(`{"errcode":9003}`))
			return
		}
		switch body.Action {
		case "create":
			body.Data["ID"] = "reservation.2."
			f.items = append(f.items, body.Data)
		case "update":
			for i, v := range f.items {
				if v["ID"] == body.Data["ID"] {
					f.items[i] = body.Data
				}
			}
		case "delete":
			for i, v := range f.items {
				if v["ID"] == body.Data["ID"] {
					f.items = append(f.items[:i], f.items[i+1:]...)
					break
				}
			}
		default:
			f.t.Error("unexpected action")
		}
		if f.mode == "lost" {
			w.Write([]byte(`invalid-json`))
			return
		}
		if f.mode == "alter-other" {
			f.items[0]["Yiaddr"] = "192.168.3.88"
		}
		w.Write([]byte(`{"errcode":0}`))
		return
	}
	switch r.URL.Path {
	case "/api/ntwk/lan_ipaddressreserve":
		json.NewEncoder(w).Encode(f.items)
	case "/api/ntwk/lan_server":
		json.NewEncoder(w).Encode(f.server)
	case "/api/ntwk/lan_all":
		w.Write([]byte(`[{"IPInterfaceIPAddress":"192.168.3.1","IPInterfaceSubnetMask":"255.255.255.0"}]`))
	case "/api/system/HostInfo":
		json.NewEncoder(w).Encode(f.hosts)
	default:
		f.t.Error("unexpected GET " + r.URL.Path)
		http.NotFound(w, r)
	}
}

func TestDHCPCreateUpdateDelete(t *testing.T) {
	c, f := newDHCP(t)
	ctx := context.Background()
	p, err := c.PlanReservation(ctx, "create", "02-00-00-00-00-02", "192.168.3.20", nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.posts != 0 || !p.DryRun {
		t.Fatal("planning wrote")
	}
	if err = c.ApplyReservation(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !p.Verified || p.DryRun || p.Reservation["ID"] != "reservation.2." {
		t.Fatal("bad create result")
	}
	p, err = c.PlanReservation(ctx, "create", "02:00:00:00:00:02", "192.168.3.20", nil)
	if err != nil || p.Action != "unchanged" {
		t.Fatal("not idempotent", err)
	}
	if err = c.ApplyReservation(ctx, p); err != nil {
		t.Fatal(err)
	}
	if f.posts != 1 {
		t.Fatal("idempotent create posted")
	}
	disabled := false
	p, err = c.PlanReservation(ctx, "update", "02:00:00:00:00:02", "192.168.3.21", &disabled)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ApplyReservation(ctx, p); err != nil {
		t.Fatal(err)
	}
	if p.Reservation["Enable"] != false || p.Reservation["ID"] != "reservation.2." {
		t.Fatal("bad update")
	}
	p, err = c.PlanReservation(ctx, "delete", "02:00:00:00:00:02", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ApplyReservation(ctx, p); err != nil {
		t.Fatal(err)
	}
	if len(f.items) != 1 || f.posts != 3 {
		t.Fatal("bad deletion")
	}
	p, err = c.PlanReservation(ctx, "delete", "02:00:00:00:00:02", "", nil)
	if err != nil || p.Action != "unchanged" {
		t.Fatal("delete absent not idempotent")
	}
}

func TestDHCPValidation(t *testing.T) {
	for _, ip := range []string{"192.168.3.1", "192.168.3.0", "192.168.3.255", "192.168.4.20", "192.168.3.10", "invalid", "::1"} {
		t.Run(ip, func(t *testing.T) {
			c, f := newDHCP(t)
			if _, err := c.PlanReservation(context.Background(), "create", "02:00:00:00:00:02", ip, nil); err == nil {
				t.Fatal("accepted invalid/conflicting IP")
			}
			if f.posts != 0 {
				t.Fatal("posted")
			}
		})
	}
	for _, m := range []string{"bad", "FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", "01:00:00:00:00:01"} {
		if _, err := NormalizeMAC(m); err == nil {
			t.Error("accepted invalid MAC")
		}
	}
	c, f := newDHCP(t)
	f.hosts = []any{map[string]any{"IPAddress": "192.168.3.20", "MACAddress": "02:00:00:00:00:03"}}
	if _, err := c.PlanReservation(context.Background(), "create", "02:00:00:00:00:02", "192.168.3.20", nil); err == nil {
		t.Fatal("host conflict accepted")
	}
}

func TestDHCPSafety(t *testing.T) {
	for _, mode := range []string{"concurrent", "reject", "lost", "alter-other"} {
		t.Run(mode, func(t *testing.T) {
			c, f := newDHCP(t)
			ctx := context.Background()
			p, err := c.PlanReservation(ctx, "create", "02:00:00:00:00:02", "192.168.3.20", nil)
			if err != nil {
				t.Fatal(err)
			}
			f.mode = mode
			if mode == "concurrent" {
				f.items[0]["Enable"] = false
			}
			err = c.ApplyReservation(ctx, p)
			if err == nil {
				t.Fatal("uncertain/conflict not reported")
			}
			want := 1
			if mode == "concurrent" {
				want = 0
			}
			if f.posts != want {
				t.Fatalf("posts=%d", f.posts)
			}
			if mode == "lost" && !p.Verified {
				t.Fatal("lost response readback not verified")
			}
		})
	}
}

func TestNoUnexpectedPayloadMutation(t *testing.T) {
	c, f := newDHCP(t)
	ctx := context.Background()
	p, err := c.PlanReservation(ctx, "update", "02:00:00:00:00:01", "192.168.3.11", nil)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(p.before[0], p.Reservation) {
		t.Fatal("expected edited copy")
	}
	if f.items[0]["Yiaddr"] != "192.168.3.10" || p.before[0]["Yiaddr"] != "192.168.3.10" {
		t.Fatal("planning mutated original")
	}
}

func TestDisableOnlyAllowsConflictingOrOldAddress(t *testing.T) {
	for _, reason := range []string{"host-conflict", "changed-pool", "dhcp-disabled"} {
		t.Run(reason, func(t *testing.T) {
			c, f := newDHCP(t)
			switch reason {
			case "host-conflict":
				f.hosts = []any{map[string]any{"IPAddress": "192.168.3.10", "MACAddress": "02:00:00:00:00:99"}}
			case "changed-pool":
				f.server["MinIP"] = "192.168.3.100"
			case "dhcp-disabled":
				f.server["ServerEnable"] = false
			}
			disabled := false
			p, err := c.PlanReservation(context.Background(), "update", "02:00:00:00:00:01", "", &disabled)
			if err != nil {
				t.Fatal(err)
			}
			if err = c.ApplyReservation(context.Background(), p); err != nil {
				t.Fatal(err)
			}
			if f.posts != 1 || f.items[0]["Enable"] != false {
				t.Fatal("disable failed")
			}
		})
	}
}

func TestUnchangedApplyRechecksState(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			c, f := newDHCP(t)
			m, ip := "02:00:00:00:00:01", "192.168.3.10"
			if operation == "delete" {
				m = "02:00:00:00:00:02"
				ip = ""
			}
			p, err := c.PlanReservation(context.Background(), operation, m, ip, nil)
			if err != nil || p.Action != "unchanged" {
				t.Fatal("expected no-op", err)
			}
			if operation == "create" {
				f.items[0]["Yiaddr"] = "192.168.3.11"
			} else {
				f.items = append(f.items, map[string]any{"ID": "reservation.2.", "Chaddr": m, "Yiaddr": "192.168.3.20", "Enable": true})
			}
			if err = c.ApplyReservation(context.Background(), p); err == nil {
				t.Fatal("stale no-op reported verified")
			}
			if f.posts != 0 || p.Verified {
				t.Fatal("no-op wrote or verified stale state")
			}
		})
	}
}
