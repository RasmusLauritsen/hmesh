package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineCommands(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		code     int
		contains string
	}{
		{[]string{"--help"}, 0, "hmesh"},
		{[]string{"--version"}, 0, Version},
		{[]string{"--non-interactive"}, 2, "interactive menu needs a terminal"},
		{[]string{"dhcp", "reservations", "create", "--mac", "02:00:00:00:00:02", "--ip", "192.168.3.20", "--non-interactive"}, 2, "require --yes"},
		{[]string{"--router", "http://router", "status"}, 2, "HTTPS origin"},
		{[]string{"--output", "xml", "status"}, 2, "--output"},
		{[]string{"dhcp", "reservations", "create"}, 2, "required flag"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var out, errOut bytes.Buffer
			args := append([]string{"--config", filepath.Join(t.TempDir(), "config.json")}, tc.args...)
			code := Run(args, strings.NewReader(""), &out, &errOut)
			if code != tc.code || !strings.Contains(out.String()+errOut.String(), tc.contains) {
				t.Fatalf("code=%d output=%q err=%q", code, out.String(), errOut.String())
			}
		})
	}
}

func TestJSONErrorOnStderr(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "--output", "json", "--non-interactive"}, strings.NewReader(""), &out, &errOut)
	var v map[string]any
	if code != 2 || out.Len() != 0 || json.Unmarshal(errOut.Bytes(), &v) != nil || v["error"] == nil {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestConfigDefaultAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmesh", "config.json")
	c, err := loadConfig(path)
	if err != nil || c.Router != "https://192.168.3.1" {
		t.Fatal("wrong factory default", err)
	}
	c.Router = "https://192.168.50.1"
	if err = saveConfig(path, c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "password") {
		t.Fatal("password field persisted")
	}
	loaded, err := loadConfig(path)
	if err != nil || loaded != c {
		t.Fatal("config roundtrip", err)
	}
	if err = os.WriteFile(path, []byte(`{"password":"forbidden"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadConfig(path); err == nil {
		t.Fatal("accepted password in config")
	}
}

func TestPasswordSources(t *testing.T) {
	old := keyringGet
	defer func() { keyringGet = old }()
	keyringGet = func(service, account string) (string, error) { return "keyring-password", nil }
	t.Setenv("HMESH_PASSWORD", "env-password")
	a := &app{in: strings.NewReader("stdin-password\n"), passwordStdin: true, nonInteractive: true}
	if got, err := a.password(); err != nil || got != "stdin-password" {
		t.Fatal("stdin priority", err)
	}
	a.passwordStdin = false
	if got, err := a.password(); err != nil || got != "env-password" {
		t.Fatal("env priority", err)
	}
	t.Setenv("HMESH_PASSWORD", "")
	if _, err := a.password(); err == nil {
		t.Fatal("empty env accepted")
	}
	os.Unsetenv("HMESH_PASSWORD")
	called := false
	keyringGet = func(service, account string) (string, error) {
		called = true
		return "", errors.New("locked provider must not be invoked")
	}
	if _, err := a.password(); err == nil || called {
		t.Fatal("unattended execution invoked keyring")
	}
	keyringGet = func(service, account string) (string, error) { return "", errors.New("keyring unavailable") }
	if _, err := a.password(); err == nil {
		t.Fatal("missing unattended password accepted")
	}
	a.passwordStdin = true
	a.passwordFile = "also-set"
	if _, err := a.password(); err == nil {
		t.Fatal("ambiguous password inputs")
	}
}

func TestBoundedCredentialCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := boundedCredential(ctx, time.Minute, func() (string, error) { close(started); <-release; return "", nil })
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, errCredentialCanceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("credential lookup ignored cancellation")
	}
	close(release)
}

func TestBoundedCredentialTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	_, err := boundedCredential(context.Background(), time.Millisecond, func() (string, error) { <-release; return "", nil })
	if !errors.Is(err, errCredentialCanceled) {
		t.Fatal("unresponsive provider did not time out")
	}
}

func TestUnattendedAuthCommandsDoNotInvokeKeyring(t *testing.T) {
	oldSet, oldDelete := keyringSet, keyringDelete
	defer func() { keyringSet = oldSet; keyringDelete = oldDelete }()
	keyringSet = func(_, _, _ string) error { t.Fatal("unexpected keyring set"); return nil }
	keyringDelete = func(_, _ string) error { t.Fatal("unexpected keyring delete"); return nil }
	for _, verb := range []string{"login", "logout"} {
		var out, errOut bytes.Buffer
		if code := Run([]string{"--config", filepath.Join(t.TempDir(), "config.json"), "--non-interactive", "auth", verb}, strings.NewReader(""), &out, &errOut); code != 3 {
			t.Fatalf("%s: code %d", verb, code)
		}
	}
}

func TestPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("file-password\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &app{passwordFile: path}
	if got, err := a.password(); err != nil || got != "file-password" {
		t.Fatal("file password", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.password(); err == nil {
		t.Fatal("insecure file permissions accepted")
	}
}

func TestPasswordLineValidation(t *testing.T) {
	for _, s := range []string{"", "first\nsecond", strings.Repeat("x", 65537), "bad\x00value"} {
		if _, err := readPassword(strings.NewReader(s)); err == nil {
			t.Fatal("bad password input accepted")
		}
	}
	got, err := readPassword(strings.NewReader(" with spaces \n"))
	if err != nil || got != " with spaces " {
		t.Fatal("trimmed password spaces")
	}
}

func TestConfigFlagOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := saveConfig(path, config{Router: "https://saved", Username: "saved-user"}); err != nil {
		t.Fatal(err)
	}
	a := &app{in: strings.NewReader(""), out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	cmd := a.command()
	cmd.SetArgs([]string{"--config", path, "--router", "https://override", "--username", "new-user", "--non-interactive"})
	_ = cmd.Execute()
	if a.settings.Router != "https://override" || a.settings.Username != "new-user" {
		t.Fatalf("flags not applied: %+v", a.settings)
	}
}
