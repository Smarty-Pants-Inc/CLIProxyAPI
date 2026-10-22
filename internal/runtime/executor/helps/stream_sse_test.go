package helps

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Protocol boundary: do not interpret a physical data line as an event. A later
// event field or data field still belongs to the same native SSE event.
func TestStreamSSEEvent(t *testing.T) {
	for _, test := range []struct {
		name, wire, data, event string
	}{
		{"multiline", "event: message_stop\ndata: {\"type\":\ndata: \"message_stop\"}\n\n", "{\"type\":\n\"message_stop\"}", "message_stop"},
		{"late event field", "data: {}\ndata:  \nevent: message_stop\n\n", "{}\n ", "message_stop"},
		{"CRLF and EOF", "event: message_stop\r\ndata: {\"type\":\r\ndata: \"message_stop\"}", "{\"type\":\n\"message_stop\"}", "message_stop"},
		{"empty data fields and comment", "data\ndata:\n: comment\ndata: {}\n\n", "\n\n{}", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var state StreamSSEEvent
			count := 0
			check := func(data []byte, ready bool) {
				if !ready {
					return
				}
				count++
				if string(data) != test.data || state.Event != test.event {
					t.Fatalf("data=%q event=%q, want data=%q event=%q", data, state.Event, test.data, test.event)
				}
			}
			for _, line := range strings.Split(test.wire, "\n") {
				check(state.Observe([]byte(line)))
			}
			check(state.Flush())
			if count != 1 {
				t.Fatalf("want one event, got %d", count)
			}
		})
	}
}

func TestStreamSSEEventWaitsForBoundary(t *testing.T) {
	var state StreamSSEEvent
	for _, line := range []string{`data: {"type":"message_stop"}`, "data:  ", "event: message_stop"} {
		if data, ready := state.Observe([]byte(line)); ready {
			t.Fatalf("emitted before blank boundary: %s", data)
		}
	}
	data, ready := state.Observe(nil)
	if !ready || string(data) != "{\"type\":\"message_stop\"}\n " || state.Event != "message_stop" {
		t.Fatalf("lost event fields: data=%q event=%q ready=%t", data, state.Event, ready)
	}
	if _, ready := state.Flush(); ready {
		t.Fatal("dispatched the event twice")
	}
}

// Compatibility: Codex accepts delimiterless JSON records as well as multiline
// data fields. Its completion/error classification already sees joined JSON.
func TestStreamSSEData(t *testing.T) {
	var state StreamSSEData
	for _, line := range []string{"event: response.completed", `data: {"type":`} {
		if _, ready := state.Observe([]byte(line)); ready {
			t.Fatal("premature data")
		}
	}
	data, ready := state.Observe([]byte(`data: "response.completed"}`))
	if !ready || gjson.GetBytes(data, "type").String() != "response.completed" || state.Event != "response.completed" {
		t.Fatalf("lost reconstructed Codex completion: %s", data)
	}
	data, ready = state.Observe([]byte(`data: {"type":"response.done"}`))
	if !ready || gjson.GetBytes(data, "type").String() != "response.done" {
		t.Fatalf("lost delimiterless record: %s", data)
	}
	state.Observe(nil)
	if state.Event != "" {
		t.Fatal("event name leaked across separator")
	}
}
