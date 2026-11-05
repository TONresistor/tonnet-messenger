package node

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

func TestCapabilitiesBypassApplicationLimitsWithoutMembership(t *testing.T) {
	for _, role := range []int32{community.NodeRoleSequencer, community.NodeRoleRelay} {
		t.Run(fmt.Sprint(role), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			room, sequencer, identity := integrationKey(t), integrationKey(t), integrationKey(t)
			genesis, err := community.NewGenesis(room, sequencer, time.Now(), "Capabilities", "", true, nil)
			if err != nil {
				t.Fatal(err)
			}
			db, err := store.Open(ctx, filepath.Join(t.TempDir(), "room.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			cfg := Config{Key: sequencer, Listen: integrationAddress(t), Genesis: &genesis, Store: db, NodeRole: role}
			if role == community.NodeRoleSequencer {
				cfg.RoomKey = room
				cfg.Socket = filepath.Join(t.TempDir(), "node.sock")
				if err := db.Initialize(ctx, genesis, room); err != nil {
					t.Fatal(err)
				}
			} else {
				cfg.Key = integrationKey(t)
				if err := db.InitializeReplica(ctx, genesis); err != nil {
					t.Fatal(err)
				}
			}
			runtime, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer runtime.Close()
			runtime.queries.mu.Lock()
			runtime.queries.tokens = 0
			runtime.queries.max = 0
			runtime.queries.refillPerSec = 0
			runtime.queries.mu.Unlock()
			client, err := roomnet.NewGateway(identity)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			raw, err := client.DialDefault(ctx, cfg.Key.Public().(ed25519.PublicKey), cfg.Listen)
			if err != nil {
				t.Fatal(err)
			}
			peer := roomnet.Wrap(raw)
			var capabilities community.Capabilities
			if err := peer.Query(ctx, community.GetCapabilities{}, &capabilities); err != nil {
				t.Fatal(err)
			}
			id, _ := community.KeyID(identity.Public().(ed25519.PublicKey))
			member, ok := runtime.peers.get(hex.EncodeToString(id))
			if !ok {
				t.Fatal("peer was not registered")
			}
			member.limiterMu.Lock()
			member.limiter = newTokenBucket(0, 0)
			member.limiterMu.Unlock()
			for i := 0; i < 5; i++ {
				if err := peer.Query(ctx, community.GetCapabilities{}, &capabilities); err != nil {
					t.Fatal(err)
				}
				if capabilities != (community.Capabilities{VersionMinor: 5}) {
					t.Fatalf("wire version/flags: %+v", capabilities)
				}
			}
			if runtime.stats.peerRateDrops.Load() != 0 || runtime.stats.queryRateDrops.Load() != 0 {
				t.Fatal("capability requests consumed application limits")
			}
			if count, _ := runtime.peers.counts(); count != 0 {
				t.Fatalf("capability requests joined %d members", count)
			}
			var remote broadcast.Time
			if err := peer.Query(ctx, broadcast.GetTime{}, &remote); err == nil {
				t.Fatal("ordinary query bypassed the exhausted limiter")
			}
			if runtime.stats.peerRateDrops.Load() != 1 {
				t.Fatal("ordinary query did not hit the exhausted peer limiter")
			}
			runtime.penalties.punish(member.id, time.Now())
			if got, err := peer.ProbeCapabilities(ctx); err != nil || got != (community.Capabilities{VersionMinor: 5}) {
				t.Fatalf("capabilities after limited query: %+v %v", got, err)
			}
			if count, _ := runtime.peers.counts(); count != 0 {
				t.Fatal("capability probe changed membership")
			}
		})
	}
}
