package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"charm.land/huh/v2"
	"github.com/RasmusLauritsen/hmesh/internal/router"
	"github.com/zalando/go-keyring"
)

const keyringService = "hmesh"

var keyringGet = keyring.Get
var keyringSet = keyring.Set
var keyringDelete = keyring.Delete

var errCredentialCanceled = errors.New("credential provider canceled or timed out")

// OS keyring APIs have no context support. Bound how long the CLI waits; the
// buffered result lets the provider finish without blocking after cancellation.
func boundedCredential(ctx context.Context, timeout time.Duration, fn func() (string, error)) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if ctx.Err() != nil {
		return "", errCredentialCanceled
	}
	type result struct {
		value string
		err   error
	}
	ch := make(chan result, 1)
	go func() { value, err := fn(); ch <- result{value, err} }()
	select {
	case r := <-ch:
		return r.value, r.err
	case <-ctx.Done():
		return "", errCredentialCanceled
	}
}

func (a *app) credentialAccount() string { return a.settings.Router + "|" + a.settings.Username }

func readPassword(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(b) > 65536 {
		return "", router.Fail("auth", "cannot read password or password exceeds 64 KiB")
	}
	s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if s == "" || strings.ContainsAny(s, "\r\n\x00") {
		return "", router.Fail("auth", "password must be one nonempty line")
	}
	return s, nil
}

func (a *app) password() (string, error) {
	count := 0
	if a.passwordStdin {
		count++
	}
	if a.passwordFile != "" {
		count++
	}
	if a.bwsSecret != "" {
		count++
	}
	if count > 1 {
		return "", router.Fail("usage", "choose only one of --password-stdin, --password-file and --bws-secret")
	}
	if a.passwordStdin {
		return readPassword(a.in)
	}
	if a.passwordFile != "" {
		f, err := os.Open(a.passwordFile)
		if err != nil {
			return "", router.Fail("auth", "cannot open password file")
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			return "", router.Fail("auth", "password file must be a regular file")
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
			return "", router.Fail("auth", "password file must not be group/world accessible (use chmod 600)")
		}
		return readPassword(f)
	}
	if a.bwsSecret != "" {
		// BWS is optional; its stderr/stdout are never forwarded to avoid leaking secrets.
		cmd := exec.CommandContext(a.ctx, "bws", "secret", "list")
		b, err := cmd.Output()
		if err != nil {
			return "", router.Fail("auth", "BWS lookup failed; output withheld")
		}
		var items []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if json.Unmarshal(b, &items) != nil {
			return "", router.Fail("auth", "BWS returned invalid JSON")
		}
		found := 0
		value := ""
		for _, s := range items {
			if s.Key == a.bwsSecret {
				found++
				value = s.Value
			}
		}
		if found != 1 || value == "" {
			return "", router.Fail("auth", "expected exactly one nonempty BWS secret matching the supplied key")
		}
		return value, nil
	}
	if s, ok := os.LookupEnv("HMESH_PASSWORD"); ok {
		if s == "" {
			return "", router.Fail("auth", "HMESH_PASSWORD is empty")
		}
		return s, nil
	}
	if !a.canPrompt() {
		return "", router.Fail("auth", "no unattended password source; use --password-stdin, --password-file, HMESH_PASSWORD or --bws-secret (OS keyring lookup is interactive-only)")
	}
	get := keyringGet
	value, err := boundedCredential(a.ctx, a.timeout, func() (string, error) { return get(keyringService, a.credentialAccount()) })
	if err == nil && value != "" {
		return value, nil
	}
	if errors.Is(err, errCredentialCanceled) {
		return "", router.Fail("auth", "OS-keyring lookup canceled or timed out")
	}
	value = ""
	form := huh.NewForm(huh.NewGroup(huh.NewInput().Title("Router password").EchoMode(huh.EchoModePassword).Value(&value)))
	if err := form.WithInput(a.in).WithOutput(a.errOut).Run(); err != nil {
		return "", router.Fail("auth", "password entry canceled")
	}
	if value == "" {
		return "", router.Fail("auth", "password cannot be empty")
	}
	return value, nil
}
