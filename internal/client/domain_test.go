package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDomainReferencesUseDNSForRoomsAndIdentities(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		http.Error(response, "offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	instance := &Client{configURL: server.URL}
	for _, domain := range []string{"alice.ton", " Team_Member.T.ME "} {
		for _, resolve := range []func(context.Context, string) (string, error){instance.ResolveRoom, instance.ResolveIdentity} {
			before := requests.Load()
			_, err := resolve(context.Background(), domain)
			if err == nil || !strings.Contains(err.Error(), "connect liteservers") || requests.Load() <= before {
				t.Fatalf("domain %q bypassed DNS: %v", domain, err)
			}
		}
	}
}
