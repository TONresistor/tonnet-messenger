package node

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	ov "github.com/TONresistor/tonnet-messenger/internal/overlay"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

const holderPublishEach = 90 * time.Second
const holderWorkers = 2

type holderPublisher interface {
	roomPublisher
	PublishOverlay(context.Context, []byte, time.Time) error
}

type inboxHolder struct {
	inbox                     string
	overlay                   *globalOverlay
	until                     int64
	ctx                       context.Context
	cancel                    context.CancelFunc
	nextPublish, nextDiscover time.Time
	publishing, discovering   bool
}

// Membership is bounded by the persisted live envelopes, including those
// accepted under a previous, larger capacity. Only the work queues have a cap.
// Each namespace reuses globalOverlay verification/gossip, never its Run loop.
type inboxHolders struct {
	node                      *Node
	mu                        sync.Mutex
	byInbox                   map[string]*inboxHolder
	byOverlay                 map[string]*inboxHolder
	pub                       *roomPublication
	publishJobs, discoverJobs chan *inboxHolder
	wake                      chan struct{}
}

func newInboxHolders(n *Node) (*inboxHolders, error) {
	s := &inboxHolders{node: n, byInbox: make(map[string]*inboxHolder), byOverlay: make(map[string]*inboxHolder), publishJobs: make(chan *inboxHolder, holderWorkers), discoverJobs: make(chan *inboxHolder, holderWorkers), wake: make(chan struct{}, 1)}
	return s, s.restore(n.ctx, time.Now())
}

func (s *inboxHolders) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *inboxHolders) joinLocked(live store.LiveInbox, now time.Time) error {
	if old := s.byInbox[string(live.InboxID)]; old != nil {
		old.until = live.ExpireAt
		return nil
	}
	key, err := ov.InboxKey(live.InboxID)
	if err != nil {
		return err
	}
	g, err := newGlobalOverlay(s.node, string(key))
	if err != nil {
		return err
	}
	g.pub.Store(s.pub)
	ctx, cancel := context.WithCancel(s.node.backgroundContext())
	h := &inboxHolder{inbox: string(live.InboxID), overlay: g, until: live.ExpireAt, ctx: ctx, cancel: cancel, nextPublish: now, nextDiscover: now}
	s.byInbox[h.inbox], s.byOverlay[string(g.id)] = h, h
	return nil
}

func (s *inboxHolders) join(live store.LiveInbox, now time.Time) error {
	s.mu.Lock()
	if old := s.byInbox[string(live.InboxID)]; old != nil && old.until > live.ExpireAt {
		live.ExpireAt = old.until
	}
	err := s.joinLocked(live, now)
	s.mu.Unlock()
	s.signal()
	return err
}

func (s *inboxHolders) dropLocked(h *inboxHolder) {
	delete(s.byInbox, h.inbox)
	delete(s.byOverlay, string(h.overlay.id))
	h.overlay.pub.Store(nil)
	h.cancel()
}

// Caller serializes snapshots with admission/ack using inboxService.order.
func (s *inboxHolders) restore(ctx context.Context, now time.Time) error {
	live, err := s.node.database.LiveInboxes(ctx, now)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]bool, len(live))
	for _, entry := range live {
		if err := s.joinLocked(entry, now); err != nil {
			return err
		}
		seen[string(entry.InboxID)] = true
	}
	for id, h := range s.byInbox {
		if !seen[id] {
			s.dropLocked(h)
		}
	}
	s.signal()
	return nil
}

func (s *inboxHolders) lookup(id []byte, now time.Time) *inboxHolder {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := s.byOverlay[string(id)]
	if h != nil && h.until <= now.Unix() {
		s.dropLocked(h)
		return nil
	}
	return h
}

func (s *inboxHolders) setPublisher(pub *roomPublication) {
	s.mu.Lock()
	s.pub = pub
	for _, h := range s.byInbox {
		h.overlay.pub.Store(pub)
	}
	s.mu.Unlock()
	s.signal()
}

func (s *inboxHolders) forgetPeer(p *peer) {
	s.mu.Lock()
	list := make([]*globalOverlay, 0, len(s.byInbox))
	for _, h := range s.byInbox {
		list = append(list, h.overlay)
	}
	s.mu.Unlock()
	for _, g := range list {
		g.forgetPeer(p)
	}
}

func (s *inboxHolders) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.byInbox {
		s.dropLocked(h)
	}
	s.pub = nil
}

func (s *inboxHolders) dispatch(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.byInbox {
		if h.until <= now.Unix() {
			s.dropLocked(h)
		}
	}
	if s.pub == nil {
		return
	}
	for _, publish := range []bool{true, false} {
		jobs := s.discoverJobs
		if publish {
			jobs = s.publishJobs
		}
		for range holderWorkers * 2 {
			var chosen *inboxHolder
			var earliest time.Time
			for _, h := range s.byInbox {
				due, busy := h.nextDiscover, h.discovering
				if publish {
					due, busy = h.nextPublish, h.publishing
				} else if len(h.overlay.advertised) > 0 && due.After(now) {
					due = now
				}
				if !busy && !due.After(now) && (chosen == nil || due.Before(earliest) || due.Equal(earliest) && h.inbox < chosen.inbox) {
					chosen, earliest = h, due
				}
			}
			if chosen == nil {
				break
			}
			select {
			case jobs <- chosen:
				if publish {
					chosen.publishing = true
				} else {
					chosen.discovering = true
				}
			default:
				goto nextKind
			}
		}
	nextKind:
	}
}

func (s *inboxHolders) perform(ctx context.Context, h *inboxHolder, publish bool, now time.Time) error {
	s.mu.Lock()
	current := s.byInbox[h.inbox] == h && h.until > now.Unix()
	until := h.until
	pub := s.pub
	s.mu.Unlock()
	var err error
	if !current || pub == nil || ctx.Err() != nil || h.ctx.Err() != nil {
		err = context.Canceled
	} else {
		deadline := time.Now().Add(dialTimeout)
		if expiry := time.Unix(until, 0); expiry.Before(deadline) {
			deadline = expiry
		}
		work, cancel := context.WithDeadline(ctx, deadline)
		stop := context.AfterFunc(h.ctx, cancel)
		if publish {
			p, ok := pub.roomPublisher.(holderPublisher)
			if !ok {
				err = fmt.Errorf("DHT publisher does not support holder namespaces")
			} else {
				err = p.PublishOverlay(work, []byte(h.overlay.name), now)
			}
		} else {
			h.overlay.discover(work)
			for i := 0; i < maxGossipNodes && work.Err() == nil; i++ {
				select {
				case nd := <-h.overlay.advertised:
					h.overlay.consider(work, nd)
				default:
					goto discovered
				}
			}
		discovered:
			err = work.Err()
		}
		stop()
		cancel()
	}
	s.mu.Lock()
	if s.byInbox[h.inbox] == h {
		if publish {
			h.publishing = false
			delay := holderPublishEach
			if err != nil {
				delay = DiscoverEach
			}
			h.nextPublish = now.Add(delay)
		} else {
			h.discovering = false
			h.nextDiscover = now.Add(DiscoverEach)
		}
	}
	s.mu.Unlock()
	s.signal()
	return err
}

func (s *inboxHolders) run(ctx context.Context) {
	var workers sync.WaitGroup
	for _, publish := range []bool{true, false} {
		jobs := s.discoverJobs
		if publish {
			jobs = s.publishJobs
		}
		for range holderWorkers {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case h := <-jobs:
						if err := s.perform(ctx, h, publish, time.Now()); err != nil && ctx.Err() == nil && h.ctx.Err() == nil {
							log.Printf("inbox holder work: %v", err)
						}
					}
				}
			}()
		}
	}
	defer workers.Wait()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.dispatch(now)
		case <-s.wake:
			s.dispatch(time.Now())
		}
	}
}
