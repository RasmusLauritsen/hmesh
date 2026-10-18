package cli

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTextOutput(t *testing.T) {
	var out bytes.Buffer
	a := &app{out: &out, output: "text"}
	value := map[string]any{"status": "online", "devices": []any{map[string]any{"name": "test\n\t\x1b", "online": true}}, "empty": []any{}}
	if err := a.print(value); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"devices[1].name", "test???", "devices[1].online", "true", "empty", "(none)", "status", "online"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %q", want, out.String())
		}
	}
	if strings.ContainsAny(out.String(), "\t\x1b") {
		t.Fatalf("unsafe or unexpanded table output: %q", out.String())
	}
}

func TestTextOutputWriteFailure(t *testing.T) {
	if err := printText(brokenWriter{}, map[string]any{"status": "online"}); err == nil {
		t.Fatal("expected write failure")
	}
}

func TestReservationTable(t *testing.T) {
	value := []any{
		map[string]any{"ID": "hidden-id", "Yiaddr": "192.168.3.100", "Chaddr": "02:00:00:00:00:02", "Enable": false},
		map[string]any{"ID": "hidden-id-2", "Yiaddr": "192.168.3.9", "Chaddr": "02:00:00:00:00:01", "Enable": true},
	}
	before := append([]any(nil), value...)
	var out bytes.Buffer
	a := &app{out: &out}
	if err := a.printReservations(value); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out.String(), "\n")
	if got := strings.Fields(lines[0]); !reflect.DeepEqual(got, []string{"IP", "ADDRESS", "MAC", "ADDRESS", "ENABLED"}) {
		t.Fatal("missing headers", got)
	}
	if got := strings.Fields(lines[1]); !reflect.DeepEqual(got, []string{"192.168.3.9", "02:00:00:00:00:01", "yes"}) {
		t.Fatal("numeric sort or enabled state incorrect", got)
	}
	if got := strings.Fields(lines[2]); !reflect.DeepEqual(got, []string{"192.168.3.100", "02:00:00:00:00:02", "no"}) {
		t.Fatal("disabled row incorrect", got)
	}
	if !strings.HasSuffix(out.String(), "\n2 reservations\n") || strings.Contains(out.String(), "hidden-id") {
		t.Fatal("count or hidden ID incorrect", out.String())
	}
	if !reflect.DeepEqual(before, value) {
		t.Fatal("formatting reordered original response")
	}
}

func TestEmptyReservationTable(t *testing.T) {
	var out bytes.Buffer
	a := &app{out: &out}
	if err := a.printReservations([]any{}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "No DHCP reservations found.\n" {
		t.Fatal(out.String())
	}
}

func TestReservationTableMissingFields(t *testing.T) {
	var out bytes.Buffer
	a := &app{out: &out}
	if err := a.printReservations([]any{map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "1 reservation\n") || strings.Contains(out.String(), "<nil>") {
		t.Fatal("bad missing-field or singular output", out.String())
	}
	lines := strings.Split(out.String(), "\n")
	if !reflect.DeepEqual(strings.Fields(lines[1]), []string{"-", "-", "-"}) {
		t.Fatal("missing fields should use placeholders", out.String())
	}
}

func TestReservationTableInvalidAndUnsafeFields(t *testing.T) {
	var out bytes.Buffer
	a := &app{out: &out}
	value := []any{
		map[string]any{"Yiaddr": "invalid\nIP", "Chaddr": "bad\tMAC\x1b[31m\xff\u202e\u2028", "Enable": true},
		map[string]any{"Yiaddr": "192.168.3.2", "Chaddr": "02:00:00:00:00:01", "Enable": true},
	}
	if err := a.printReservations(value); err != nil {
		t.Fatal(err)
	}
	if strings.Index(out.String(), "192.168.3.2") > strings.Index(out.String(), "invalid?IP") {
		t.Fatal("invalid IP should sort after valid addresses")
	}
	if strings.ContainsAny(out.String(), "\t\x1b\u202e\u2028") || strings.Count(out.String(), "\n") != 5 {
		t.Fatal("unsafe field affected terminal layout", out.String())
	}
}

func TestReservationTableRejectsMalformedResponse(t *testing.T) {
	for _, value := range []any{nil, map[string]any{}, []any{"invalid-row"}} {
		var out bytes.Buffer
		a := &app{out: &out}
		if err := a.printReservations(value); err == nil || out.Len() != 0 {
			t.Fatal("invalid response should fail without partial output")
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken output") }

func TestReservationTableOutputError(t *testing.T) {
	a := &app{out: brokenWriter{}}
	if err := a.printReservations([]any{}); err == nil {
		t.Fatal("output error ignored")
	}
}

func TestReservationJSONStillIncludesIDs(t *testing.T) {
	var out bytes.Buffer
	a := &app{out: &out, output: "json"}
	if err := a.print([]any{map[string]any{"ID": "original-id", "Yiaddr": "192.168.3.2", "Enable": true}}); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[{\"Enable\":true,\"ID\":\"original-id\",\"Yiaddr\":\"192.168.3.2\"}]\n" {
		t.Fatal("JSON contract changed", out.String())
	}
}
