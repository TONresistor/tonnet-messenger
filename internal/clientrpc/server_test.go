package clientrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TONresistor/tonnet-messenger/internal/client"
)

func TestStdioIdentityAPI(t *testing.T) {
	ctx := context.Background()
	c, err := client.Open(ctx, client.Config{StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	input := strings.NewReader(
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"identity.get\",\"params\":{}}\n" +
			"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"identity.setName\",\"params\":{\"name\":\"alice\"}}\n",
	)
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
	if len(responses) != 2 {
		t.Fatalf("responses = %s", output.String())
	}
	identity := responses[2]["result"].(map[string]any)
	if identity["name"] != "alice" || len(identity["key"].(string)) != 43 {
		t.Fatalf("identity = %#v", identity)
	}
}
