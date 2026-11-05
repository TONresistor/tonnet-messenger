package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/adnl/keys"
	tonoverlay "github.com/xssnick/tonutils-go/adnl/overlay"
)

type dmCandidate struct {
	key     ed25519.PublicKey
	address string
}

func dmRank(inbox, key []byte) [32]byte {
	raw := append(bytes.Clone(inbox), key...)
	return sha256.Sum256(raw)
}
func rankDM(inbox []byte, list []dmCandidate) []dmCandidate {
	sort.Slice(list, func(i, j int) bool {
		a, b := dmRank(inbox, list[i].key), dmRank(inbox, list[j].key)
		return bytes.Compare(a[:], b[:]) < 0
	})
	return list
}

func (r *dmRuntime) lookupOverlay(ctx context.Context, name []byte) []dmCandidate {
	id, err := ov.ID(string(name))
	if err != nil {
		return nil
	}
	type hint struct {
		key     ed25519.PublicKey
		address string
	}
	var queue []hint
	seen := make(map[string]bool)
	add := func(nd tonoverlay.Node) {
		if len(seen) >= 16 || !bytes.Equal(nd.Overlay, id) || !relayCardFresh(nd.Version, time.Now()) || nd.CheckSignature() != nil {
			return
		}
		key, ok := nd.ID.(keys.PublicKeyED25519)
		if !ok || len(key.Key) != 32 || seen[string(key.Key)] {
			return
		}
		seen[string(key.Key)] = true
		queue = append(queue, hint{key: key.Key})
	}
	if r.client.directAddress != "" {
		key := r.client.directPublic
		seen[string(key)] = true
		queue = append(queue, hint{key: key, address: r.client.directAddress})
	} else {
		if r.discovery == nil {
			open, cancel := context.WithTimeout(ctx, 5*time.Second)
			r.discovery, err = dht.NewDiscovery(open, r.client.configURL)
			cancel()
			if err != nil {
				r.discovery = nil
			}
		}
		if r.discovery != nil {
			query, cancel := context.WithTimeout(ctx, 5*time.Second)
			nodes, err := r.discovery.FindOverlayNodes(query, name)
			cancel()
			if err == nil && nodes != nil {
				for i, nd := range nodes.List {
					if i == 16 {
						break
					}
					add(nd)
				}
			}
		}
		if string(name) == ov.Relays {
			if lease := r.pool.choose(time.Now()); lease != nil && len(seen) < 16 && !seen[string(lease.PublicKey())] {
				key := lease.PublicKey()
				if endpoint := r.cachedAddress(key); endpoint != "" {
					seen[string(key)] = true
					queue = append(queue, hint{key: key, address: endpoint})
				}
			}
		}
	}
	type answer struct {
		candidate dmCandidate
		nodes     []tonoverlay.Node
		valid     bool
	}
	var found []dmCandidate
	for len(queue) > 0 && ctx.Err() == nil {
		n := min(3, len(queue))
		batch := append([]hint(nil), queue[:n]...)
		queue = queue[n:]
		results := make(chan answer, n)
		var workers sync.WaitGroup
		for _, h := range batch {
			workers.Add(1)
			go func() {
				defer workers.Done()
				out := answer{candidate: dmCandidate{key: h.key, address: h.address}}
				if !r.take(ctx) {
					results <- out
					return
				}
				defer r.release()
				if h.address == "" {
					out.candidate.address = r.cachedAddress(h.key)
					if out.candidate.address != "" {
						h.address = out.candidate.address
					}
				}
				if h.address == "" {
					if r.discovery == nil {
						results <- out
						return
					}
					query, cancel := context.WithTimeout(ctx, 5*time.Second)
					keyID, _ := community.KeyID(h.key)
					addresses, public, err := r.discovery.ResolveAll(query, keyID)
					cancel()
					if err != nil || !public.Equal(h.key) || len(addresses) == 0 {
						results <- out
						return
					}
					out.candidate.address = addresses[0]
				}
				lease, err := r.pool.acquire(ctx, h.key, out.candidate.address, time.Now())
				if err != nil {
					results <- out
					return
				}
				query, cancel := context.WithTimeout(ctx, 5*time.Second)
				var peers tonoverlay.NodesList
				err = lease.QueryOverlay(query, id, tonoverlay.GetRandomPeers{}, &peers)
				cancel()
				if err != nil {
					r.failed(h.key, err)
					results <- out
					return
				}
				for i, nd := range peers.List {
					if i == 16 {
						break
					}
					out.nodes = append(out.nodes, nd)
					if bytes.Equal(nd.Overlay, id) && relayCardFresh(nd.Version, time.Now()) && nd.CheckSignature() == nil {
						if key, ok := nd.ID.(keys.PublicKeyED25519); ok && key.Key.Equal(h.key) {
							out.valid = true
						}
					}
				}
				if out.valid {
					r.pool.observe(h.key, relaySuccess, time.Now())
				} else {
					r.pool.observe(h.key, relayMalformedAnswer, time.Now())
				}
				results <- out
			}()
		}
		workers.Wait()
		close(results)
		for out := range results {
			if out.valid {
				found = append(found, out.candidate)
			}
			for _, nd := range out.nodes {
				add(nd)
			}
		}
	}
	return found
}

func (r *dmRuntime) discover(ctx context.Context, inbox []byte) ([]dmCandidate, []dmCandidate) {
	r.discoverMu.Lock()
	defer r.discoverMu.Unlock()
	work, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	key, err := ov.InboxKey(inbox)
	if err != nil {
		return nil, nil
	}
	holders := rankDM(inbox, r.lookupOverlay(work, key))
	global := r.lookupOverlay(work, []byte(ov.Relays))
	global = rankDM(inbox, global)
	if len(global) > 5 {
		global = global[:5]
	} // This original ranking is never extended after rejection.
	return holders, global
}

func (r *dmRuntime) cachedAddress(key ed25519.PublicKey) string {
	card, ok := r.pool.card(key)
	if !ok {
		return ""
	}
	for _, a := range card.Addrs.Addresses {
		switch a.(type) {
		case address.QUIC, *address.QUIC:
			ip, port := address.IPValue(a), address.PortValue(a)
			if ip != nil && !ip.IsUnspecified() && port > 0 && port <= 65535 {
				return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			}
		}
	}
	return ""
}

func (r *dmRuntime) ownRelay() *dmCandidate {
	r.mu.Lock()
	var list []dmCandidate
	for _, s := range r.sessions {
		s.mu.Lock()
		used := s.subscribed && s.subscriptionUntil > time.Now().Unix() && relayLeaseLive(s.lease)
		s.mu.Unlock()
		if used {
			list = append(list, s.target)
		}
	}
	r.mu.Unlock()
	r.pool.mu.Lock()
	defer r.pool.mu.Unlock()
	var best *dmCandidate
	for _, target := range list {
		if !r.pool.policy.banned(string(target.key), time.Now()) && (best == nil || r.pool.policy.scores[string(target.key)] < r.pool.policy.scores[string(best.key)]) {
			copy := target
			best = &copy
		}
	}
	return best
}
