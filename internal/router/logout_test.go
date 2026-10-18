package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestLogout(t *testing.T) {
	for _, response := range []string{`{"errcode":0}`, `{"err":0}`, `{"errcode":1}`, `{}`, `not JSON`} {
		t.Run(response, func(t *testing.T) {
			calls := 0
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodPost || r.URL.Path != "/api/system/user_logout" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				cookie, err := r.Cookie("SessionID_R3")
				if err != nil || cookie.Value != "owned-session" {
					t.Error("missing owned session")
				}
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 {
					t.Error("logout must contain only CSRF envelope")
				}
				csrf, _ := body["csrf"].(map[string]any)
				if csrf["csrf_param"] != "latest-param" || csrf["csrf_token"] != "latest-token" {
					t.Error("logout used stale CSRF")
				}
				w.Write([]byte(response))
			}))
			defer s.Close()
			c, err := New(Options{URL: s.URL, Insecure: true})
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(s.URL)
			c.http.Jar.SetCookies(u, []*http.Cookie{{Name: "SessionID_R3", Value: "owned-session", Path: "/", Secure: true}})
			c.csrf = map[string]string{"csrf_param": "latest-param", "csrf_token": "latest-token"}
			c.loggedIn = true
			err = c.Logout(context.Background())
			wantSuccess := response == `{"errcode":0}` || response == `{"err":0}`
			if (err == nil) != wantSuccess {
				t.Fatalf("unexpected logout result: %v", err)
			}
			if c.loggedIn || len(c.csrf) != 0 || len(c.http.Jar.Cookies(u)) != 0 {
				t.Fatal("local session state retained")
			}
			if err := c.Logout(context.Background()); err != nil || calls != 1 {
				t.Fatalf("logout retried: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestLogoutWithoutLogin(t *testing.T) {
	c, err := New(Options{URL: "https://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Logout(context.Background()); err != nil {
		t.Fatalf("unauthenticated client attempted logout: %v", err)
	}
}

func TestLogoutTimeout(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body any
		_ = json.NewDecoder(r.Body).Decode(&body)
		<-r.Context().Done()
	}))
	defer s.Close()
	c, err := New(Options{URL: s.URL, Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	c.loggedIn = true
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Logout(ctx); err == nil {
		t.Fatal("timed-out logout succeeded")
	}
	if c.loggedIn {
		t.Fatal("timed-out logout retained session state")
	}
}
