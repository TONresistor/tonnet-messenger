package clientrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/client"
)

func TestStdioIdentityAPI(t *testing.T) {
	ctx := context.Background()
	c, err := client.Open(ctx, client.Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	input := io.NopCloser(strings.NewReader(
		"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"client.info\",\"params\":{}}\n" +
			"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"identity.get\",\"params\":{}}\n" +
			"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"identity.setName\",\"params\":{\"name\":\"alice\"}}\n",
	))
	var output bytes.Buffer
	if err := (&Server{Client: c, Version: "test"}).Serve(ctx, input, &output); err != nil {
		t.Fatal(err)
	}
	responses := map[float64]map[string]any{}
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	for scanner.Scan() {
		var value map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if id, ok := value["id"].(float64); ok {
			responses[id] = value
		}
	}
	if len(responses) != 3 {
		t.Fatalf("responses = %s", output.String())
	}
	info := responses[0]["result"].(map[string]any)
	if info["room_transport"] != "ton-quic" {
		t.Fatalf("client info = %#v", info)
	}
	identity := responses[2]["result"].(map[string]any)
	if identity["name"] != "alice" || len(identity["key"].(string)) != 43 {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestFitResponsePaginatesLargeTimelines(t *testing.T) {
	items := make([]map[string]any, 100)
	for i := range items {
		items[i] = map[string]any{"seqno": i + 1, "text": strings.Repeat("<", 2048)}
	}
	join := client.JoinResult{
		Room: "room", State: map[string]any{}, Connection: map[string]any{}, Presence: map[string]any{},
		Timeline: map[string]any{"items": append([]map[string]any(nil), items...), "has_more": false},
	}
	fitted := fitResponse("room.join", response{JSONRPC: "2.0", ID: json.RawMessage("1"), Result: join})
	if !responseFits(fitted) || fitted.Error != nil {
		t.Fatalf("join response was not fitted: %#v", fitted.Error)
	}
	fittedJoin := fitted.Result.(client.JoinResult)
	joinItems := fittedJoin.Timeline["items"].([]map[string]any)
	if len(joinItems) == 0 || len(joinItems) >= len(items) || fittedJoin.Timeline["has_more"] != true {
		t.Fatalf("join timeline = %d items, has_more=%v", len(joinItems), fittedJoin.Timeline["has_more"])
	}
	if joinItems[len(joinItems)-1]["seqno"] != 100 {
		t.Fatal("join pagination did not preserve newest event")
	}

	timeline := map[string]any{"items": append([]map[string]any(nil), items...), "has_more": false}
	fitted = fitResponse("room.getTimeline", response{JSONRPC: "2.0", ID: json.RawMessage("2"), Result: timeline})
	if !responseFits(fitted) || fitted.Error != nil {
		t.Fatalf("timeline response was not fitted: %#v", fitted.Error)
	}
	fittedTimeline := fitted.Result.(map[string]any)
	timelineItems := fittedTimeline["items"].([]map[string]any)
	if len(timelineItems) == 0 || len(timelineItems) >= len(items) || fittedTimeline["has_more"] != true {
		t.Fatalf("timeline = %d items, has_more=%v", len(timelineItems), fittedTimeline["has_more"])
	}
	if timelineItems[len(timelineItems)-1]["seqno"] != 100 {
		t.Fatal("timeline pagination did not preserve newest event")
	}
}

func TestServeStopsOnContextCancellationAndReleasesClient(t *testing.T) {
	stateDir := t.TempDir()
	clientInstance, err := client.Open(context.Background(), client.Config{StateDir: stateDir})
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Client: clientInstance, Version: "test"}).Serve(ctx, reader, io.Discard)
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdio server did not stop after cancellation")
	}
	_ = writer.Close()
	reopened, err := client.Open(context.Background(), client.Config{StateDir: stateDir})
	if err != nil {
		t.Fatalf("client lock was not released: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

var errBrokenOutput = errors.New("broken output")

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errBrokenOutput }

func TestServeStopsWhenNotificationOutputFails(t *testing.T) {
	clientInstance, err := client.Open(context.Background(), client.Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- (&Server{Client: clientInstance, Version: "test"}).Serve(context.Background(), reader, brokenWriter{})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errBrokenOutput) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stdio server did not stop after output failure")
	}
	_ = writer.Close()
}

func TestClassifyAuthoritativeClockErrors(t *testing.T) {
	tests := []struct {
		err     error
		code    string
		numeric int
	}{
		{client.ErrSequencerUnavailable, "SEQUENCER_UNAVAILABLE", -32030},
		{client.ErrSequencerClockSkew, "CLOCK_SKEW", -32031},
	}
	for _, test := range tests {
		got := classify(test.err)
		if got.Code != test.numeric || got.Data["code"] != test.code {
			t.Fatalf("classify(%v) = %#v", test.err, got)
		}
	}
}
