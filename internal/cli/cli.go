// Package cli provides Cobra commands and a Huh interactive front end.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/RasmusLauritsen/huawei-mesh3-cli/internal/router"
	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const Version = "0.1.0-dev"

type app struct {
	in                                                                       io.Reader
	out, errOut                                                              io.Writer
	ctx                                                                      context.Context
	settings                                                                 config
	configFile, routerURL, username, caFile, output, passwordFile, bwsSecret string
	insecure, passwordStdin, nonInteractive, yes, dryRun                     bool
	timeout                                                                  time.Duration
}

func Run(args []string, in io.Reader, out, errOut io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := &app{in: in, out: out, errOut: errOut, ctx: ctx}
	root := a.command()
	root.SetArgs(args)
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	if err := root.ExecuteContext(ctx); err != nil {
		kind := "usage"
		var protocol *router.Error
		if errors.As(err, &protocol) {
			kind = protocol.Kind
		}
		codes := map[string]int{"usage": 2, "auth": 3, "connection": 4, "api": 5, "conflict": 6, "uncertain": 7}
		code := codes[kind]
		if code == 0 {
			code = 1
		}
		if a.output == "json" {
			_ = json.NewEncoder(errOut).Encode(map[string]any{"error": map[string]any{"kind": kind, "message": err.Error(), "exit_code": code}})
		} else {
			fmt.Fprintln(errOut, "Error:", err)
		}
		return code
	}
	return 0
}

func (a *app) canPrompt() bool {
	if a.nonInteractive || a.passwordStdin {
		return false
	}
	f, ok := a.in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	e, ok := a.errOut.(*os.File)
	return ok && term.IsTerminal(int(e.Fd()))
}

func (a *app) setup(cmd *cobra.Command) error {
	if a.output != "text" && a.output != "json" {
		return router.Fail("usage", "--output must be text or json")
	}
	if a.timeout <= 0 {
		return router.Fail("usage", "--timeout must be positive")
	}
	path, err := configPath(a.configFile)
	if err != nil {
		return err
	}
	a.configFile = path
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("router") {
		c.Router = a.routerURL
	}
	if cmd.Flags().Changed("username") {
		c.Username = a.username
	}
	if cmd.Flags().Changed("ca-cert") {
		c.CAFile = a.caFile
	}
	c.Router, err = router.NormalizeURL(c.Router)
	if err != nil {
		return err
	}
	if c.Username == "" {
		return router.Fail("usage", "username cannot be empty")
	}
	if c.CAFile != "" {
		c.CAFile, err = filepath.Abs(c.CAFile)
		if err != nil {
			return router.Fail("usage", "invalid CA certificate path")
		}
	}
	a.settings = c
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
		return router.Fail("usage", "choose only one explicit password source")
	}
	return nil
}

func (a *app) connect() (*router.Client, error) {
	c, err := router.New(router.Options{URL: a.settings.Router, Username: a.settings.Username, CAFile: a.settings.CAFile, Insecure: a.insecure, Timeout: a.timeout})
	if err != nil {
		return nil, err
	}
	password, err := a.password()
	if err != nil {
		return nil, err
	}
	if err = c.Login(a.ctx, password); err != nil {
		return nil, err
	}
	return c, nil
}

func (a *app) print(v any) error {
	v = router.Redact(v)
	e := json.NewEncoder(a.out)
	if a.output == "text" {
		e.SetIndent("", "  ")
	}
	if err := e.Encode(v); err != nil {
		return router.Fail("usage", "cannot write command output")
	}
	return nil
}

func (a *app) read(name string) error {
	c, err := a.connect()
	if err != nil {
		return err
	}
	v, err := c.Get(a.ctx, name)
	if err != nil {
		return err
	}
	return a.print(v)
}

func (a *app) command() *cobra.Command {
	root := &cobra.Command{Use: "hmesh", Short: "Manage a Huawei Mesh 3 router", Version: Version, SilenceErrors: true, SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error { return a.setup(cmd) },
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return router.Fail("usage", "unexpected arguments")
			}
			return a.menu()
		}}
	f := root.PersistentFlags()
	f.StringVar(&a.routerURL, "router", "https://192.168.3.1", "Router HTTPS origin (overrides saved config)")
	f.StringVar(&a.username, "username", "admin", "Router username (overrides saved config)")
	f.StringVar(&a.configFile, "config", "", "Config file (default: OS config directory/hmesh/config.json)")
	f.StringVar(&a.caFile, "ca-cert", "", "PEM CA/certificate bundle for TLS trust")
	f.BoolVar(&a.insecure, "insecure", false, "Explicitly disable TLS certificate verification")
	f.DurationVar(&a.timeout, "timeout", 20*time.Second, "Per-request timeout")
	f.StringVar(&a.output, "output", "text", "Output format: text (indented JSON) or json (compact JSON)")
	f.BoolVar(&a.nonInteractive, "non-interactive", false, "Never display CLI prompts")
	f.BoolVar(&a.passwordStdin, "password-stdin", false, "Read one password line from stdin")
	f.StringVar(&a.passwordFile, "password-file", "", "Read password from a protected file")
	f.StringVar(&a.bwsSecret, "bws-secret", "", "Optional BWS secret key (requires authenticated bws)")
	f.BoolVar(&a.yes, "yes", false, "Approve a planned configuration write without prompting")
	f.BoolVar(&a.dryRun, "dry-run", false, "Plan a reservation change without sending a configuration POST")
	root.AddCommand(&cobra.Command{Use: "status", Short: "Show router hardware/firmware status", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return a.read("status") }})
	for _, spec := range []struct{ group, verb, name, description string }{
		{"devices", "list", "devices", "List connected/known devices"},
		{"mesh", "topology", "topology", "Show mesh topology"},
		{"port-forward", "list", "port-forward", "List forwarding mappings (read-only; not full port definitions)"},
	} {
		spec := spec
		group := &cobra.Command{Use: spec.group, Short: spec.description}
		group.AddCommand(&cobra.Command{Use: spec.verb, Short: spec.description, Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return a.read(spec.name) }})
		root.AddCommand(group)
	}
	dns := &cobra.Command{Use: "dns", Short: "Read DNS resolver configuration"}
	dns.AddCommand(&cobra.Command{Use: "show", Short: "Show selected WAN, DHCP and IPv6 WAN DNS fields", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return a.dns() }})
	root.AddCommand(dns)
	dhcp := &cobra.Command{Use: "dhcp", Short: "Manage DHCP reservations"}
	reservations := &cobra.Command{Use: "reservations", Short: "List, create, update or delete reservations"}
	reservations.AddCommand(&cobra.Command{Use: "list", Short: "List DHCP reservations", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return a.read("reservations") }})
	for _, operation := range []string{"create", "update", "delete"} {
		operation := operation
		var mac, ip string
		var enabled bool
		cmd := &cobra.Command{Use: operation, Short: operation + " a DHCP reservation by MAC", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			var enable *bool
			if operation == "create" || cmd.Flags().Changed("enabled") {
				enable = &enabled
			}
			return a.mutate(operation, mac, ip, enable)
		}}
		cmd.Flags().StringVar(&mac, "mac", "", "Device MAC address (required)")
		_ = cmd.MarkFlagRequired("mac")
		if operation != "delete" {
			cmd.Flags().StringVar(&ip, "ip", "", "Reserved IPv4 address")
			cmd.Flags().BoolVar(&enabled, "enabled", true, "Desired enabled state (use --enabled=false to disable)")
		}
		if operation == "create" {
			_ = cmd.MarkFlagRequired("ip")
		}
		reservations.AddCommand(cmd)
	}
	dhcp.AddCommand(reservations)
	root.AddCommand(dhcp)
	auth := &cobra.Command{Use: "auth", Short: "Manage optional local OS-keyring credentials"}
	auth.AddCommand(&cobra.Command{Use: "login", Short: "Verify password, save it to OS keyring and save non-secret connection config", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return a.login() }})
	auth.AddCommand(&cobra.Command{Use: "logout", Short: "Remove locally stored credentials for this router/user (no router logout)", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		if !a.canPrompt() {
			return router.Fail("auth", "OS-keyring commands require an interactive terminal; use an explicit password source for automation")
		}
		remove := keyringDelete
		_, err := boundedCredential(a.ctx, a.timeout, func() (string, error) { return "", remove(keyringService, a.credentialAccount()) })
		if err != nil {
			return router.Fail("auth", "could not delete local credential (it may not exist or OS keyring is unavailable)")
		}
		return a.print(map[string]any{"status": "credential_removed", "router": a.settings.Router})
	}})
	root.AddCommand(auth)
	return root
}

func (a *app) login() error {
	if !a.canPrompt() {
		return router.Fail("auth", "OS-keyring commands require an interactive terminal; use an explicit password source for automation")
	}
	password, err := a.password()
	if err != nil {
		return err
	}
	c, err := router.New(router.Options{URL: a.settings.Router, Username: a.settings.Username, CAFile: a.settings.CAFile, Insecure: a.insecure, Timeout: a.timeout})
	if err != nil {
		return err
	}
	if err = c.Login(a.ctx, password); err != nil {
		return err
	}
	set := keyringSet
	if _, err = boundedCredential(a.ctx, a.timeout, func() (string, error) { return "", set(keyringService, a.credentialAccount(), password) }); err != nil {
		return router.Fail("auth", "router login succeeded but OS-keyring save failed; use stdin, environment or a protected password file instead")
	}
	if err = saveConfig(a.configFile, a.settings); err != nil {
		return router.Fail("usage", "password saved to OS keyring but config save failed; keep supplying router/user flags")
	}
	return a.print(map[string]any{"status": "credential_saved", "router": a.settings.Router, "username": a.settings.Username, "config_file": a.configFile})
}

func (a *app) mutate(operation, mac, ip string, enabled *bool) error {
	if !a.dryRun && !a.yes && !a.canPrompt() {
		return router.Fail("usage", "non-interactive writes require --yes; use --dry-run to preview")
	}
	c, err := a.connect()
	if err != nil {
		return err
	}
	p, err := c.PlanReservation(a.ctx, operation, mac, ip, enabled)
	if err != nil {
		return err
	}
	if a.dryRun {
		return a.print(p)
	}
	if !a.yes && p.Action != "unchanged" {
		if err = a.printPlan(p); err != nil {
			return err
		}
		ok := false
		form := huh.NewForm(huh.NewGroup(huh.NewConfirm().Title("Apply this DHCP reservation change?").Value(&ok)))
		if err = form.WithInput(a.in).WithOutput(a.errOut).Run(); err != nil || !ok {
			return router.Fail("usage", "change canceled; no configuration write sent")
		}
	}
	if err = c.ApplyReservation(a.ctx, p); err != nil {
		return err
	}
	return a.print(p)
}
func (a *app) printPlan(p *router.Plan) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(a.errOut, string(b))
	return err
}

func pick(v any, keys ...string) map[string]any {
	result := map[string]any{}
	m, _ := v.(map[string]any)
	for _, key := range keys {
		if value, ok := m[key]; ok {
			result[key] = value
		}
	}
	return result
}
func (a *app) dns() error {
	c, err := a.connect()
	if err != nil {
		return err
	}
	wan, err := c.Get(a.ctx, "wan")
	if err != nil {
		return err
	}
	dhcp, err := c.Get(a.ctx, "dhcp")
	if err != nil {
		return err
	}
	v6, err := c.Get(a.ctx, "ipv6-wan")
	if err != nil {
		return err
	}
	return a.print(map[string]any{
		"wan":      pick(wan, "DNSOverrideAllowed", "IPv4DnsServers", "IPv4StaticDnsServers"),
		"dhcp":     pick(dhcp, "dnsmode", "DNSServerone", "DNSServertwo"),
		"ipv6_wan": pick(v6, "X_IPv6DNSOverrideAllowed", "X_IPv6DNSServerOne", "X_IPv6DNSServerTwo"),
	})
}
