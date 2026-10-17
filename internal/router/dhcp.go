package router

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
)

type Plan struct {
	Operation   string         `json:"operation"`
	Action      string         `json:"action"`
	Reservation map[string]any `json:"reservation,omitempty"`
	DryRun      bool           `json:"dry_run"`
	Verified    bool           `json:"verified"`
	before      []map[string]any
	server      any
	disableOnly bool
}

func records(v any) ([]map[string]any, error) {
	a, ok := v.([]any)
	if !ok {
		return nil, Fail("api", "expected a JSON array from router")
	}
	result := make([]map[string]any, 0, len(a))
	for _, v := range a {
		m, err := object(v)
		if err != nil {
			return nil, err
		}
		result = append(result, m)
	}
	return result, nil
}

func (c *Client) Reservations(ctx context.Context) ([]map[string]any, error) {
	v, err := c.Get(ctx, "reservations")
	if err != nil {
		return nil, err
	}
	return records(v)
}

func NormalizeMAC(raw string) (string, error) {
	m, err := net.ParseMAC(raw)
	if err != nil || len(m) != 6 || m[0]&1 != 0 {
		return "", Fail("usage", "MAC must be a six-byte unicast address")
	}
	zero := true
	for _, b := range m {
		if b != 0 {
			zero = false
		}
	}
	if zero {
		return "", Fail("usage", "all-zero MAC is invalid")
	}
	return strings.ToUpper(m.String()), nil
}

func (c *Client) PlanReservation(ctx context.Context, operation, rawMAC, ip string, enabled *bool) (*Plan, error) {
	if operation != "create" && operation != "update" && operation != "delete" {
		return nil, Fail("usage", "unsupported reservation operation")
	}
	mac, err := NormalizeMAC(rawMAC)
	if err != nil {
		return nil, err
	}
	if operation == "create" && ip == "" {
		return nil, Fail("usage", "create requires --ip")
	}
	if operation == "update" && ip == "" && enabled == nil {
		return nil, Fail("usage", "update requires --ip or --enabled")
	}
	if ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() {
			return nil, Fail("usage", "reservation IP must be an IPv4 address")
		}
		ip = a.String()
	}
	before, err := c.Reservations(ctx)
	if err != nil {
		return nil, err
	}
	server, err := c.Get(ctx, "dhcp")
	if err != nil {
		return nil, err
	}
	p := &Plan{Operation: operation, Action: operation, DryRun: true, before: before, server: server}
	var existing map[string]any
	ids := map[string]bool{}
	for _, item := range before {
		id := text(item, "ID")
		if id == "" || ids[id] {
			return nil, Fail("api", "reservation IDs missing or duplicated")
		}
		ids[id] = true
		if strings.EqualFold(text(item, "Chaddr"), mac) {
			if existing != nil {
				return nil, Fail("conflict", "multiple reservations match this MAC")
			}
			existing = item
		}
	}
	if existing == nil && operation == "delete" {
		p.Action = "unchanged"
		return p, nil
	}
	if existing == nil && operation == "update" {
		return nil, Fail("conflict", "reservation not found; use create")
	}
	item := map[string]any{"ID": "", "Enable": true, "Chaddr": mac, "Yiaddr": ip}
	if existing != nil {
		item = map[string]any{}
		for k, v := range existing {
			item[k] = v
		}
	}
	if operation == "delete" {
		p.Reservation = item
		return p, nil
	}
	if ip != "" {
		item["Yiaddr"] = ip
	}
	if enabled != nil {
		item["Enable"] = *enabled
	}
	if operation == "create" && existing != nil {
		want := true
		if enabled != nil {
			want = *enabled
		}
		if text(existing, "Yiaddr") == ip && existing["Enable"] == want {
			p.Reservation = existing
			p.Action = "unchanged"
			return p, nil
		}
		return nil, Fail("conflict", "MAC already reserved with different settings; use update")
	}
	p.Reservation = item
	if existing != nil && reflect.DeepEqual(existing, item) {
		p.Action = "unchanged"
		return p, nil
	}
	// Disabling an existing allocation must remain possible even if its address
	// has become conflicting or falls outside a newly configured DHCP pool.
	p.disableOnly = operation == "update" && existing != nil && item["Enable"] == false && text(existing, "Yiaddr") == text(item, "Yiaddr")
	if p.disableOnly {
		return p, nil
	}
	for _, other := range before {
		if text(other, "ID") != text(item, "ID") && text(other, "Yiaddr") == text(item, "Yiaddr") {
			return nil, Fail("conflict", "IP is already reserved for another MAC")
		}
	}
	if err := c.validateAddress(ctx, text(item, "Yiaddr"), mac, server); err != nil {
		return nil, err
	}
	return p, nil
}

func (c *Client) validateAddress(ctx context.Context, raw, mac string, server any) error {
	s, err := object(server)
	if err != nil {
		return err
	}
	if s["ServerEnable"] != true {
		return Fail("conflict", "DHCP server is disabled")
	}
	a, err := netip.ParseAddr(raw)
	if err != nil || !a.Is4() {
		return Fail("usage", "invalid reservation IPv4")
	}
	v, err := c.Get(ctx, "lan")
	if err != nil {
		return err
	}
	interfaces, err := records(v)
	if err != nil {
		return err
	}
	inSubnet := false
	for _, item := range interfaces {
		gateway, err := netip.ParseAddr(text(item, "IPInterfaceIPAddress"))
		if err != nil || !gateway.Is4() {
			return Fail("api", "invalid LAN address returned by router")
		}
		mask := net.ParseIP(text(item, "IPInterfaceSubnetMask")).To4()
		if mask == nil {
			return Fail("api", "invalid LAN mask returned by router")
		}
		ones, bits := net.IPMask(mask).Size()
		if bits != 32 || ones < 1 || ones > 30 {
			return Fail("api", "unsupported LAN subnet mask")
		}
		prefix := netip.PrefixFrom(gateway, ones).Masked()
		if a == gateway {
			return Fail("conflict", "IP is a router LAN address")
		}
		if prefix.Contains(a) {
			bytes := a.As4()
			netbytes := prefix.Addr().As4()
			n := uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
			base := uint32(netbytes[0])<<24 | uint32(netbytes[1])<<16 | uint32(netbytes[2])<<8 | uint32(netbytes[3])
			broadcast := base | (uint32(1)<<uint(32-ones) - 1)
			if n == base || n == broadcast {
				return Fail("conflict", "IP is a subnet network or broadcast address")
			}
			inSubnet = true
		}
	}
	if !inSubnet {
		return Fail("conflict", "IP is outside the router's LAN subnets")
	}
	// Restrict initial tooling to the known DHCP pool; outside-pool semantics are unverified.
	lo, e1 := netip.ParseAddr(text(s, "MinIP"))
	hi, e2 := netip.ParseAddr(text(s, "MaxIP"))
	if e1 != nil || e2 != nil || !lo.Is4() || !hi.Is4() || lo.Compare(hi) > 0 {
		return Fail("api", "invalid DHCP pool returned by router")
	}
	if a.Compare(lo) < 0 || a.Compare(hi) > 0 {
		return Fail("conflict", "IP is outside DHCP pool (outside-pool reservations are not yet supported)")
	}
	v, err = c.Get(ctx, "devices")
	if err != nil {
		return err
	}
	hosts, err := records(v)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if text(host, "IPAddress") == raw && !strings.EqualFold(text(host, "MACAddress"), mac) {
			return Fail("conflict", "router host inventory associates IP with a different MAC")
		}
	}
	return nil
}

// ApplyReservation performs at most one POST. It never retries or rolls back.
func (c *Client) ApplyReservation(ctx context.Context, p *Plan) error {
	if p.Action != "create" && p.Action != "update" && p.Action != "delete" && p.Action != "unchanged" {
		return Fail("usage", "invalid reservation plan")
	}
	current, err := c.Reservations(ctx)
	if err != nil {
		return err
	}
	server, err := c.Get(ctx, "dhcp")
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(current, p.before) || !reflect.DeepEqual(server, p.server) {
		return Fail("conflict", "configuration changed since planning; no write sent")
	}
	if p.Action == "unchanged" {
		p.DryRun = false
		p.Verified = true
		return nil
	}
	// Recheck hosts/subnet before the POST, not only before the confirmation prompt.
	if p.Action != "delete" && !p.disableOnly {
		if err := c.validateAddress(ctx, text(p.Reservation, "Yiaddr"), text(p.Reservation, "Chaddr"), server); err != nil {
			return err
		}
	}
	v, writeErr := c.json(ctx, "POST", "/api/ntwk/lan_ipaddressreserve", map[string]any{"action": p.Action, "data": p.Reservation, "csrf": c.csrf})
	accepted := false
	if writeErr == nil {
		m, err := object(v)
		accepted = err == nil && fmt.Sprint(m["errcode"]) == "0"
	}
	p.DryRun = false
	after, err := c.Reservations(ctx)
	if err != nil {
		return Fail("uncertain", "write attempted but readback failed; inspect reservations before retrying")
	}
	afterServer, err := c.Get(ctx, "dhcp")
	if err != nil || !reflect.DeepEqual(afterServer, p.server) {
		return Fail("uncertain", "write attempted; DHCP settings could not be verified unchanged; inspect before retrying")
	}
	if !verify(p, after) {
		return Fail("uncertain", "write outcome does not match expected reservation state; inspect reservations before retrying")
	}
	p.Verified = true
	if !accepted {
		return Fail("uncertain", "desired state observed, but write response was not confirmed; no retry was attempted")
	}
	return nil
}

func verify(p *Plan, after []map[string]any) bool {
	old := map[string]map[string]any{}
	for _, item := range p.before {
		old[text(item, "ID")] = item
	}
	id := text(p.Reservation, "ID")
	if p.Action == "delete" || p.Action == "update" {
		delete(old, id)
	}
	matches := 0
	seen := map[string]bool{}
	for _, item := range after {
		itemID := text(item, "ID")
		if itemID == "" || seen[itemID] {
			return false
		}
		seen[itemID] = true
		if original, ok := old[itemID]; ok {
			if !reflect.DeepEqual(item, original) {
				return false
			}
			delete(old, itemID)
			continue
		}
		if p.Action == "delete" {
			return false
		}
		if p.Action == "update" && itemID != id {
			return false
		}
		for _, key := range []string{"Chaddr", "Yiaddr", "Enable"} {
			if !reflect.DeepEqual(item[key], p.Reservation[key]) {
				return false
			}
		}
		matches++
		p.Reservation = item
	}
	return len(old) == 0 && ((p.Action == "delete" && matches == 0) || (p.Action != "delete" && matches == 1))
}
