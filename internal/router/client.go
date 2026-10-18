// Package router implements the firmware-specific Huawei Mesh 3 protocol.
package router

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string        { return e.Message }
func Fail(kind, message string) error { return &Error{Kind: kind, Message: message} }

type Options struct {
	URL, Username, CAFile string
	Insecure              bool
	Timeout               time.Duration
}

type Client struct {
	base     string
	username string
	http     *http.Client
	csrf     map[string]string
	loggedIn bool
}

// NormalizeURL excludes credentials, query strings and paths from credential keys.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", Fail("usage", "router URL must be an HTTPS origin without credentials, path, query or fragment")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

func New(o Options) (*Client, error) {
	base, err := NormalizeURL(o.URL)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: o.Insecure} // Explicit opt-in for local self-signed certificates.
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, Fail("usage", "cannot read CA certificate file")
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, Fail("usage", "CA file contains no valid certificates")
		}
		config.RootCAs = pool
	}
	jar, _ := cookiejar.New(nil)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = config
	if o.Timeout <= 0 {
		o.Timeout = 20 * time.Second
	}
	return &Client{base: base, username: o.Username, csrf: map[string]string{}, http: &http.Client{
		Transport: transport, Jar: jar, Timeout: o.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func (c *Client) request(ctx context.Context, method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, Fail("api", "cannot encode request")
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return nil, Fail("usage", "invalid request URL")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("_ResponseFormat", "JSON")
	req.Header.Set("Referer", c.base+"/html/index.html")
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, Fail("connection", "router request failed (check connectivity, TLS trust and timeout); no request was retried")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, Fail("api", fmt.Sprintf("router returned HTTP %d", resp.StatusCode))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20+1))
	if err != nil || len(b) > 8<<20 {
		return nil, Fail("api", "cannot read router response or response exceeds 8 MiB")
	}
	return b, nil
}

func (c *Client) json(ctx context.Context, method, path string, body any) (any, error) {
	b, err := c.request(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return nil, Fail("api", "router returned invalid JSON; session may have expired")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, Fail("api", "router returned trailing data")
	}
	if m, ok := v.(map[string]any); ok {
		p, pok := m["csrf_param"].(string)
		t, tok := m["csrf_token"].(string)
		if pok && tok {
			c.csrf = map[string]string{"csrf_param": p, "csrf_token": t}
		}
		for _, key := range []string{"err", "errcode"} {
			if code, exists := m[key]; exists && fmt.Sprint(code) != "0" {
				return nil, Fail("api", "router rejected request ("+key+"="+safeCode(code)+")")
			}
		}
	}
	return v, nil
}

func safeCode(v any) string {
	n, err := intValue(v)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprint(n)
}
func intValue(v any) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, fmt.Errorf("not a number")
	}
	i, err := n.Int64()
	return int(i), err
}
func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, Fail("api", "expected a JSON object from router")
	}
	return m, nil
}
func text(m map[string]any, k string) string { v, _ := m[k].(string); return v }
func mac(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)
	return h.Sum(nil)
}

var meta = regexp.MustCompile(`<meta\s+name="(csrf_param|csrf_token)"\s+content="([^"]+)"`)

func (c *Client) Login(ctx context.Context, password string) error {
	b, err := c.request(ctx, "GET", "/html/index.html", nil)
	if err != nil {
		return err
	}
	c.csrf = map[string]string{}
	for _, m := range meta.FindAllSubmatch(b, -1) {
		c.csrf[string(m[1])] = string(m[2])
	}
	if c.csrf["csrf_param"] == "" || c.csrf["csrf_token"] == "" {
		return Fail("auth", "login page lacks CSRF tokens")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return Fail("auth", "cannot generate login nonce")
	}
	first := hex.EncodeToString(nonce)
	v, err := c.json(ctx, "POST", "/api/system/user_login_nonce", map[string]any{"data": map[string]string{"username": c.username, "firstnonce": first}, "csrf": c.csrf})
	if err != nil {
		return Fail("auth", "login challenge failed; no retries attempted")
	}
	m, err := object(v)
	if err != nil {
		return err
	}
	if fmt.Sprint(m["err"]) != "0" {
		return Fail("auth", "login challenge missing success code")
	}
	final := text(m, "servernonce")
	salt, err := hex.DecodeString(text(m, "salt"))
	iterations, ierr := intValue(m["iterations"])
	if err != nil || len(salt) == 0 || ierr != nil || iterations < 1 || iterations > 1000000 || !strings.HasPrefix(final, first) || len(final) <= len(first) {
		return Fail("auth", "invalid SCRAM challenge")
	}
	proof, serverKey, auth, err := derive(password, salt, iterations, first, final)
	if err != nil {
		return err
	}
	v, err = c.json(ctx, "POST", "/api/system/user_login_proof", map[string]any{"data": map[string]string{"clientproof": hex.EncodeToString(proof), "finalnonce": final}, "csrf": c.csrf})
	// Even a malformed response can have allocated a session via Set-Cookie.
	u, _ := url.Parse(c.base)
	for _, cookie := range c.http.Jar.Cookies(u) {
		if cookie.Name == "SessionID" || strings.HasPrefix(cookie.Name, "SessionID_") {
			c.loggedIn = true
		}
	}
	if err != nil {
		return Fail("auth", "login proof rejected; no retries attempted")
	}
	// The router may have allocated a session even if proof verification below fails.
	c.loggedIn = true
	m, err = object(v)
	if err != nil {
		return err
	}
	if fmt.Sprint(m["err"]) != "0" {
		return Fail("auth", "login response missing success code")
	}
	signature, err := hex.DecodeString(text(m, "serversignature"))
	if err != nil || !hmac.Equal(signature, mac(auth, serverKey)) {
		return Fail("auth", "server signature verification failed")
	}
	public, err := hex.DecodeString(text(m, "rsan"))
	if err != nil || len(public) == 0 {
		return Fail("auth", "invalid RSA public key")
	}
	signature, err = hex.DecodeString(text(m, "rsapubkeysignature"))
	if err != nil || !hmac.Equal(signature, mac(serverKey, public)) {
		return Fail("auth", "RSA public key signature verification failed")
	}
	return nil
}

// Logout releases only this client's session. It makes at most one attempt and
// discards local session state even if the router cannot confirm the logout.
// Clients are intended for sequential use, not concurrent requests.
func (c *Client) Logout(ctx context.Context) error {
	defer c.http.CloseIdleConnections()
	if !c.loggedIn {
		return nil
	}
	c.loggedIn = false
	defer func() {
		c.csrf = map[string]string{}
		c.http.Jar, _ = cookiejar.New(nil)
	}()
	// Matches the firmware UI's commonPost({name: 'user_logout', writeOnly: true}).
	v, err := c.json(ctx, "POST", "/api/system/user_logout", map[string]any{"csrf": c.csrf})
	if err != nil {
		return err
	}
	m, err := object(v)
	if err != nil {
		return err
	}
	for _, key := range []string{"err", "errcode"} {
		if code, ok := m[key]; ok && safeCode(code) == "0" {
			return nil
		}
	}
	return Fail("api", "logout response missing success code")
}

func derive(password string, salt []byte, iterations int, first, final string) ([]byte, []byte, []byte, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
	if err != nil {
		return nil, nil, nil, Fail("auth", "cannot derive login key")
	}
	// Huawei reverses HMAC arguments compared to conventional SCRAM.
	client := mac([]byte("Client Key"), salted)
	server := mac([]byte("Server Key"), salted)
	stored := sha256.Sum256(client)
	auth := []byte(first + "," + final + "," + final)
	signature := mac(auth, stored[:])
	for i := range client {
		client[i] ^= signature[i]
	}
	return client, server, auth, nil
}

var reads = map[string]string{
	"devices": "system/HostInfo", "status": "system/deviceinfo", "topology": "device/topology",
	"reservations": "ntwk/lan_ipaddressreserve", "dhcp": "ntwk/lan_server", "lan": "ntwk/lan_all",
	"wan": "ntwk/wan?type=active", "port-forward": "ntwk/portmapping", "ipv6-wan": "ntwk/ipv6_wan",
}

func (c *Client) Get(ctx context.Context, name string) (any, error) {
	path, ok := reads[name]
	if !ok {
		return nil, Fail("usage", "unsupported read operation")
	}
	return c.json(ctx, "GET", "/api/"+path, nil)
}

// Redact strips credentials/session fields, not private network inventory.
func Redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range x {
			lower := strings.ToLower(k)
			compact := strings.NewReplacer("_", "", "-", "").Replace(lower)
			if strings.Contains(lower, "password") || strings.Contains(lower, "cookie") || strings.Contains(lower, "csrf") || strings.Contains(lower, "presharedkey") || lower == "pwd" || lower == "wepkey" ||
				strings.Contains(compact, "token") || strings.Contains(compact, "sessionid") || compact == "authorization" || compact == "proxyauthorization" || compact == "passwd" {
				continue
			}
			out[k] = Redact(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = Redact(v)
		}
		return out
	default:
		return v
	}
}
