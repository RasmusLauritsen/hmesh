package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Exercise Cobra -> stdin credentials -> SCRAM -> HTTP -> mutation -> JSON.
// The server and all credential/network records are fake; no router is contacted.
func TestCLIEndToEnd(t *testing.T) {
	var first, final string
	posts := 0
	logins, logouts := 0, 0
	readFailure, logoutFailure := false, false
	var cancelRead context.CancelFunc
	items := []map[string]any{}
	salt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	hash := func(key, msg []byte) []byte { h := hmac.New(sha256.New, key); h.Write(msg); return h.Sum(nil) }
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/html/index.html":
			w.Write([]byte(`<meta name="csrf_param" content="p1"/><meta name="csrf_token" content="t1"/>`))
		case "/api/system/user_login_nonce":
			var body struct{ Data map[string]string }
			json.NewDecoder(r.Body).Decode(&body)
			first = body.Data["firstnonce"]
			final = first + strings.Repeat("cd", 32)
			json.NewEncoder(w).Encode(map[string]any{"err": 0, "salt": hex.EncodeToString(salt), "iterations": 1000, "servernonce": final, "csrf_param": "p2", "csrf_token": "t2"})
		case "/api/system/user_login_proof":
			logins++
			http.SetCookie(w, &http.Cookie{Name: "SessionID_R3", Value: "fake-session", Path: "/", Secure: true})
			salted, _ := pbkdf2.Key(sha256.New, "fake-password", salt, 1000, 32)
			server := hash([]byte("Server Key"), salted)
			pub, _ := hex.DecodeString("a1b2c3d4")
			json.NewEncoder(w).Encode(map[string]any{"err": 0, "rsan": "a1b2c3d4", "serversignature": hex.EncodeToString(hash([]byte(first+","+final+","+final), server)), "rsapubkeysignature": hex.EncodeToString(hash(server, pub))})
		case "/api/system/deviceinfo":
			if cancelRead != nil {
				cancelRead()
			}
			if readFailure {
				http.Error(w, "fake read failure", http.StatusInternalServerError)
				return
			}
			w.Write([]byte(`{"SoftwareVersion":"test","csrf_token":"never-output"}`))
		case "/api/system/user_logout":
			logouts++
			if r.Method != http.MethodPost {
				t.Error("logout must POST")
			}
			if cookie, err := r.Cookie("SessionID_R3"); err != nil || cookie.Value != "fake-session" {
				t.Error("logout missing session cookie")
			}
			if logoutFailure {
				http.Error(w, "fake logout failure", http.StatusInternalServerError)
				return
			}
			w.Write([]byte(`{"errcode":0}`))
		case "/api/ntwk/lan_server":
			w.Write([]byte(`{"ServerEnable":true,"MinIP":"192.168.3.2","MaxIP":"192.168.3.254"}`))
		case "/api/ntwk/lan_all":
			w.Write([]byte(`[{"IPInterfaceIPAddress":"192.168.3.1","IPInterfaceSubnetMask":"255.255.255.0"}]`))
		case "/api/system/HostInfo":
			w.Write([]byte(`[]`))
		case "/api/ntwk/lan_ipaddressreserve":
			if r.Method == "GET" {
				json.NewEncoder(w).Encode(items)
				return
			}
			posts++
			var body struct {
				Action string
				Data   map[string]any
				CSRF   map[string]string
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.CSRF["csrf_token"] != "t2" {
				t.Error("stale CSRF")
			}
			switch body.Action {
			case "create":
				body.Data["ID"] = "reservation.1."
				items = append(items, body.Data)
			case "update":
				if len(items) != 1 || body.Data["ID"] != "reservation.1." {
					t.Error("update ID")
				}
				items[0] = body.Data
			case "delete":
				items = []map[string]any{}
			default:
				t.Error("bad action")
			}
			w.Write([]byte(`{"errcode":0}`))
		default:
			t.Error("unexpected path " + r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	configFile := filepath.Join(t.TempDir(), "config.json")
	run := func(args ...string) any {
		t.Helper()
		var out, errOut bytes.Buffer
		base := []string{"--config", configFile, "--router", s.URL, "--insecure", "--password-stdin", "--non-interactive", "--output", "json"}
		code := Run(append(base, args...), strings.NewReader("fake-password\n"), &out, &errOut)
		if logins != logouts {
			t.Fatalf("session leaked: %d logins, %d logouts", logins, logouts)
		}
		if code != 0 || errOut.Len() != 0 {
			t.Fatalf("%v: exit=%d err=%s", args, code, errOut.String())
		}
		if strings.Contains(out.String(), "never-output") || strings.Contains(out.String(), "fake-password") {
			t.Fatal("credential output leak")
		}
		var value any
		if json.Unmarshal(out.Bytes(), &value) != nil {
			t.Fatal("invalid success JSON")
		}
		return value
	}
	run("status")
	preview := run("dhcp", "reservations", "create", "--mac", "02:00:00:00:00:42", "--ip", "192.168.3.100", "--dry-run").(map[string]any)
	if preview["dry_run"] != true || posts != 0 {
		t.Fatal("dry-run wrote")
	}
	created := run("dhcp", "reservations", "create", "--mac", "02:00:00:00:00:42", "--ip", "192.168.3.100", "--yes").(map[string]any)
	if created["verified"] != true || posts != 1 {
		t.Fatal("create failed")
	}
	listed := run("dhcp", "reservations", "list").([]any)
	if len(listed) != 1 || listed[0].(map[string]any)["ID"] != "reservation.1." {
		t.Fatal("JSON reservation list changed")
	}
	if shorthand := run("dhcp", "list"); !reflect.DeepEqual(shorthand, listed) {
		t.Fatal("dhcp list JSON differs from reservations list")
	}
	var tableOut, tableErr bytes.Buffer
	tableCode := Run([]string{"--config", configFile, "--router", s.URL, "--insecure", "--password-stdin", "--non-interactive", "dhcp", "reservations", "list"}, strings.NewReader("fake-password\n"), &tableOut, &tableErr)
	if tableCode != 0 || tableErr.Len() != 0 || !strings.Contains(tableOut.String(), "IP ADDRESS") || !strings.Contains(tableOut.String(), "1 reservation\n") || strings.Contains(tableOut.String(), "reservation.1.") {
		t.Fatalf("default reservation list was not a table: exit=%d out=%q err=%q", tableCode, tableOut.String(), tableErr.String())
	}
	var shortOut, shortErr bytes.Buffer
	shortCode := Run([]string{"--config", configFile, "--router", s.URL, "--insecure", "--password-stdin", "--non-interactive", "dhcp", "list"}, strings.NewReader("fake-password\n"), &shortOut, &shortErr)
	if shortCode != 0 || shortErr.Len() != 0 || shortOut.String() != tableOut.String() || posts != 1 {
		t.Fatalf("dhcp list table differs or sent a write: exit=%d out=%q err=%q", shortCode, shortOut.String(), shortErr.String())
	}
	noOp := run("dhcp", "reservations", "create", "--mac", "02:00:00:00:00:42", "--ip", "192.168.3.100", "--yes").(map[string]any)
	if noOp["action"] != "unchanged" || posts != 1 {
		t.Fatal("idempotent create wrote")
	}
	run("dhcp", "reservations", "update", "--mac", "02:00:00:00:00:42", "--enabled=false", "--yes")
	if len(items) != 1 || items[0]["Enable"] != false || posts != 2 {
		t.Fatal("CLI update failed")
	}
	run("dhcp", "reservations", "delete", "--mac", "02:00:00:00:00:42", "--yes")
	if len(items) != 0 || posts != 3 {
		t.Fatal("CLI delete failed")
	}
	// Validation failures after connecting must also release the session without
	// masking the original command error or sending a configuration write.
	var out, errOut bytes.Buffer
	code := Run([]string{"--config", configFile, "--router", s.URL, "--insecure", "--password-stdin", "--non-interactive", "--output", "json", "dhcp", "reservations", "create", "--mac", "invalid", "--ip", "192.168.3.100", "--yes"}, strings.NewReader("fake-password\n"), &out, &errOut)
	if code != 2 || logins != logouts || posts != 3 {
		t.Fatalf("failed command leaked session or changed result: code=%d logins=%d logouts=%d posts=%d", code, logins, logouts, posts)
	}
	for _, failRead := range []bool{false, true} {
		readFailure, logoutFailure = failRead, true
		out.Reset()
		errOut.Reset()
		code := Run([]string{"--config", configFile, "--router", s.URL, "--insecure", "--password-stdin", "--non-interactive", "--output", "json", "status"}, strings.NewReader("fake-password\n"), &out, &errOut)
		wantCode := 0
		if failRead {
			wantCode = 5
		}
		if code != wantCode || logins != logouts || !strings.Contains(errOut.String(), `"session_cleanup"`) {
			t.Fatalf("logout failure masked result or lacked warning: code=%d stderr=%q", code, errOut.String())
		}
		if !failRead && !json.Valid(out.Bytes()) {
			t.Fatal("cleanup warning corrupted command JSON")
		}
	}
	readFailure, logoutFailure = false, false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelRead = cancel
	out.Reset()
	errOut.Reset()
	a := &app{ctx: ctx, in: strings.NewReader("fake-password\n"), out: &out, errOut: &errOut}
	root := a.command()
	root.SetArgs([]string{"--config", configFile, "--router", s.URL, "--insecure", "--password-stdin", "--non-interactive", "--output", "json", "status"})
	_ = root.ExecuteContext(ctx)
	if ctx.Err() == nil || logins != logouts || errOut.Len() != 0 {
		t.Fatalf("cancellation prevented logout: logins=%d logouts=%d stderr=%q", logins, logouts, errOut.String())
	}
}
