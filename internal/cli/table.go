package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/RasmusLauritsen/huawei-mesh3-cli/internal/router"
)

// printText normalizes structs as well as API responses, then renders every
// field without relying on a particular router firmware's response schema.
func printText(out io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil {
		return err
	}
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	var render func(any, string)
	render = func(v any, prefix string) {
		switch v := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if len(keys) == 0 {
				fmt.Fprintf(table, "%s\t(none)\n", tableCell(prefix))
			}
			for _, key := range keys {
				label := key
				if prefix != "" {
					label = prefix + "." + key
				}
				render(v[key], label)
			}
		case []any:
			if len(v) == 0 {
				fmt.Fprintf(table, "%s\t(none)\n", tableCell(prefix))
			}
			for i, item := range v {
				render(item, fmt.Sprintf("%s[%d]", prefix, i+1))
			}
		default:
			text := fmt.Sprint(v)
			if v == nil {
				text = "-"
			}
			fmt.Fprintf(table, "%s\t%s\n", tableCell(prefix), tableCell(text))
		}
	}
	render(normalized, "")
	return table.Flush()
}

// printReservations only formats the text view; it does not reorder or alter
// the original response used by the JSON output contract.
func (a *app) printReservations(value any) error {
	items, ok := value.([]any)
	if !ok {
		return router.Fail("api", "expected a reservation array from router")
	}
	type row struct {
		ip, mac, enabled string
		address          netip.Addr
	}
	rows := make([]row, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			return router.Fail("api", "expected reservation objects from router")
		}
		ip, _ := m["Yiaddr"].(string)
		mac, _ := m["Chaddr"].(string)
		address, _ := netip.ParseAddr(ip)
		if !address.Is4() {
			address = netip.Addr{}
		}
		enabled := "-"
		if state, ok := m["Enable"].(bool); ok {
			enabled = "no"
			if state {
				enabled = "yes"
			}
		}
		rows = append(rows, row{ip: tableCell(ip), mac: tableCell(mac), enabled: enabled, address: address})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		x, y := rows[i], rows[j]
		if x.address.IsValid() != y.address.IsValid() {
			return x.address.IsValid()
		}
		if x.address.IsValid() && x.address != y.address {
			return x.address.Compare(y.address) < 0
		}
		if x.ip != y.ip {
			return x.ip < y.ip
		}
		return x.mac < y.mac
	})
	var out bytes.Buffer
	if len(rows) == 0 {
		fmt.Fprintln(&out, "No DHCP reservations found.")
	} else {
		table := tabwriter.NewWriter(&out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(table, "IP ADDRESS\tMAC ADDRESS\tENABLED")
		for _, row := range rows {
			fmt.Fprintf(table, "%s\t%s\t%s\n", row.ip, row.mac, row.enabled)
		}
		if err := table.Flush(); err != nil {
			return router.Fail("usage", "cannot format reservation table")
		}
		noun := "reservations"
		if len(rows) == 1 {
			noun = "reservation"
		}
		fmt.Fprintf(&out, "\n%d %s\n", len(rows), noun)
	}
	if _, err := a.out.Write(out.Bytes()); err != nil {
		return router.Fail("usage", "cannot write command output")
	}
	return nil
}

// Router data must not inject terminal controls, new rows, or tabwriter escapes.
func tableCell(value string) string {
	if value == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, value)
}
