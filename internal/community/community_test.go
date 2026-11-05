package community

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/xssnick/tonutils-go/adnl/address"
	"github.com/xssnick/tonutils-go/tl"
)

func testPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testNonce(t *testing.T) []byte {
	t.Helper()
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestIdentityAndRoomKeyText(t *testing.T) {
	public := testPrivate(t).Public().(ed25519.PublicKey)
	text, err := RoomKeyText(public)
	if err != nil || len(text) != 43 {
		t.Fatalf("text=%q err=%v", text, err)
	}
	decoded, err := ParseRoomKeyText(text)
	if err != nil || !bytes.Equal(decoded, public) {
		t.Fatalf("roundtrip failed: %v", err)
	}
}

func TestV2ProposalCommitAndProfileBinding(t *testing.T) {
	for _, domain := range []string{"alice.ton", "alice.t.me", "team_member.t.me"} {
		t.Run(domain, func(t *testing.T) { testProposalProfileBinding(t, domain) })
	}
}

func testProposalProfileBinding(t *testing.T, domain string) {
	now := time.Unix(1_800_000_000, 0)
	room, node, author := testPrivate(t), testPrivate(t), testPrivate(t)
	proposal, err := SignProposal(author, node.Public().(ed25519.PublicKey), EventProposal{
		RoomID: room.Public().(ed25519.PublicKey), AuthorName: "alice", AuthorDomain: domain,
		Nonce: testNonce(t), Timestamp: now.Unix(), Body: EventMessage{Text: "hello"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := proposal.Verify(node.Public().(ed25519.PublicKey), now); err != nil {
		t.Fatal(err)
	}
	tampered := proposal
	tampered.AuthorDomain = "mallory.ton"
	if !errors.Is(tampered.Verify(node.Public().(ed25519.PublicKey), now), ErrBadSignature) {
		t.Fatal("profile change did not invalidate signature")
	}
	commit, err := SignCommit(room, proposal, 1, Zero256(), now)
	if err != nil || commit.Verify(room.Public().(ed25519.PublicKey), node.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("commit failed: %v", err)
	}
}

func TestDirectMessageIsRoomBound(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	from, to := testPrivate(t), testPrivate(t).Public().(ed25519.PublicKey)
	roomA, roomB := testPrivate(t).Public().(ed25519.PublicKey), testPrivate(t).Public().(ed25519.PublicKey)
	message, err := SignDirectMessage(from, DirectMessage{
		RoomID: roomA, ToKey: to, AuthorName: "alice", Timestamp: now.Unix(), Ciphertext: make([]byte, 28),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := message.Verify(roomA, now); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(message.Verify(roomB, now), ErrWrongRoom) {
		t.Fatal("cross-room direct message accepted")
	}
}

type wireV050Fixture struct {
	value       any
	constructor uint32
	decode      func([]byte) (any, error)
}

func wireV050Decoder[T any](decode func([]byte) (T, error)) func([]byte) (any, error) {
	return func(raw []byte) (any, error) { return decode(raw) }
}

func wireV050Fixtures() []wireV050Fixture {
	owner := bytes.Repeat([]byte{1}, 32)
	peer := bytes.Repeat([]byte{2}, 32)
	hash := bytes.Repeat([]byte{3}, 32)
	signature := bytes.Repeat([]byte{4}, 64)
	offer := RelayOfferV1{Tier: 7, Services: RelayServiceDM, MaxObjectBytes: 4096,
		RetentionSeconds: 3600, RequestsPerMinute: 60, InboxQuotaBytes: 1 << 20,
		PriceNanoton: 10, UnitBytes: 1024}
	relay := RelayCardV1{RelayKey: owner, Services: RelayServiceDM | RelayServicePaidTiers,
		PaymentKey: peer, Offers: []RelayOfferV1{offer}, Version: 1800000000, Signature: signature,
		Addrs: address.List{Addresses: []address.Address{address.QUIC{IP: net.IP{192, 0, 2, 1}, Port: 17400}},
			Version: 1, ReinitDate: 2, Priority: 3, ExpireAt: 4}}
	room := RoomCardV1{RoomKey: owner, NodeKey: peer, Alias: "example.ton", Name: "room",
		Description: "description", Version: 1800000001, Signature: signature}
	state := RoomStateV3{RoomID: owner, RevisionSeqno: 17, RevisionHash: hash, Name: "room",
		Description: "description", WritePolicy: WritePolicy{AnyoneCanWrite: true},
		Admins: [][]byte{peer}, Moderators: [][]byte{hash}, PinnedMessages: []int64{5, 9},
		Banned: [][]byte{bytes.Repeat([]byte{5}, 32)}, Signature: signature}
	message := DirectMessageV3{FromKey: owner, ToKey: peer, AuthorName: "alice",
		AuthorDomain: "alice.ton", CreatedAt: 1800000002, ExpireAt: 1800003602,
		Ciphertext: []byte{6, 7, 8}, Signature: signature}
	receipt := InboxReceiptV1{RelayKey: owner, DMID: hash, InboxID: peer,
		ExpireAt: 1800003602, Signature: signature}
	auth := InboxAuthV1{RecipientKey: peer, Nonce: hash, Signature: signature}
	authContext := InboxAuthV1ToSign{RelayKey: owner, InboxID: peer, Nonce: hash, ExpireAt: 1800003603}
	return []wireV050Fixture{
		{offer, 0xcf95135e, wireV050Decoder(DecodeRelayOfferV1)},
		{relay, 0x0d253b15, wireV050Decoder(DecodeRelayCardV1)},
		{relay.toSign(), 0x374f292c, DecodeAny},
		{room, 0xb3b5ef2a, wireV050Decoder(DecodeRoomCardV1)},
		{room.toSign(), 0x84d162a9, DecodeAny},
		{RelayPaymentV1{Tier: 7, ChannelKey: peer, State: []byte{9, 10}, Final: true}, 0xdae791f0, wireV050Decoder(DecodeRelayPaymentV1)},
		{RelayBalanceV1{Tier: 7, BalanceBytes: -176}, 0x41595a5c, wireV050Decoder(DecodeRelayBalanceV1)},
		{RelayPaymentRejectedV1{Code: RejectInsufficientPrepaidBalance, Message: "unpaid"}, 0xe688d192, wireV050Decoder(DecodeRelayPaymentRejectedV1)},
		{GetRelayCardV1{}, 0x1db2dadb, wireV050Decoder(DecodeGetRelayCardV1)},
		{GetRoomCardsV1{Limit: 100}, 0xf842edbc, wireV050Decoder(DecodeGetRoomCardsV1)},
		{RoomCardListV1{Cards: []RoomCardV1{room}}, 0xe563db2b, wireV050Decoder(DecodeRoomCardListV1)},
		{OverlayQueryV1{Overlay: hash, Tier: 0, Query: []byte{11, 12}}, 0x1e9b0930, wireV050Decoder(DecodeOverlayQueryV1)},
		{OverlayRejectedV1{Code: RejectOverlayNotServed, Message: "unserved"}, 0x1e718905, wireV050Decoder(DecodeOverlayRejectedV1)},
		{GetCapabilities{}, 0x94fa078e, wireV050Decoder(DecodeGetCapabilities)},
		{Capabilities{VersionMajor: 0, VersionMinor: 5, Flags: 6}, 0x012ab454, wireV050Decoder(DecodeCapabilities)},
		{EventBanV1{SubjectKey: peer}, 0xd3d85d7c, wireV050Decoder(DecodeEventBanV1)},
		{EventUnbanV1{SubjectKey: peer}, 0xce685dea, wireV050Decoder(DecodeEventUnbanV1)},
		{state, 0xb3071fbd, wireV050Decoder(DecodeRoomStateV3)},
		{state.toSign(), 0xdc340358, DecodeAny},
		{message, 0x6038a620, wireV050Decoder(DecodeDirectMessageV3)},
		{message.toSign(), 0x8d3b1b75, DecodeAny},
		{InboxDepositV1{Message: message, Tier: 7}, 0xca6e791c, wireV050Decoder(DecodeInboxDepositV1)},
		{receipt, 0x1f50c6bf, wireV050Decoder(DecodeInboxReceiptV1)},
		{receipt.toSign(), 0x7d41414e, DecodeAny},
		{InboxRejectedV1{Code: RejectRelayFullOrQuotaExceeded, Message: "full"}, 0x6c1396ca, wireV050Decoder(DecodeInboxRejectedV1)},
		{GetInboxChallengeV1{InboxID: peer}, 0x18ba1eb2, wireV050Decoder(DecodeGetInboxChallengeV1)},
		{InboxChallengeV1{Nonce: hash, ExpireAt: 1800003603}, 0xb4cfc322, wireV050Decoder(DecodeInboxChallengeV1)},
		{InboxChallengeRejectedV1{Code: RejectInboxAuthenticationFailed, Message: "auth"}, 0x24aa845a, wireV050Decoder(DecodeInboxChallengeRejectedV1)},
		{auth, 0x9061a8f9, wireV050Decoder(DecodeInboxAuthV1)},
		{authContext, 0x625bd30f, DecodeAny},
		{GetInboxV1{Auth: auth, After: 13, Limit: 100}, 0xaced70e5, wireV050Decoder(DecodeGetInboxV1)},
		{InboxPageV1{Messages: []DirectMessageV3{message}, HasMore: true, LastSeqno: 14}, 0x1b5b5e67, wireV050Decoder(DecodeInboxPageV1)},
		{InboxPageRejectedV1{Code: RejectMalformedRequest, Message: "bad page"}, 0xb0b27a75, wireV050Decoder(DecodeInboxPageRejectedV1)},
		{InboxAckV1{Auth: auth, IDs: [][]byte{hash}}, 0x6978b5fd, wireV050Decoder(DecodeInboxAckV1)},
		{InboxAckedV1{Deleted: 1}, 0xfac3ceb1, wireV050Decoder(DecodeInboxAckedV1)},
		{InboxAckRejectedV1{Code: RejectInboxAuthenticationFailed, Message: "auth"}, 0xad46e828, wireV050Decoder(DecodeInboxAckRejectedV1)},
		{InboxPushV1{Seqno: 15, Message: message}, 0xa4169b11, wireV050Decoder(DecodeInboxPushV1)},
	}
}

func TestV050WireRoundTripsAndStrictDecoders(t *testing.T) {
	for _, fixture := range wireV050Fixtures() {
		t.Run(reflect.TypeOf(fixture.value).Name(), func(t *testing.T) {
			raw, err := Encode(fixture.value)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint32(raw); got != fixture.constructor {
				t.Fatalf("constructor = %08x, want %08x", got, fixture.constructor)
			}
			for _, decode := range []func([]byte) (any, error){fixture.decode, DecodeAny} {
				decoded, err := decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(decoded, fixture.value) {
					t.Fatalf("roundtrip differs: got %#v, want %#v", decoded, fixture.value)
				}
				if _, err := decode(append(append([]byte(nil), raw...), 0)); err == nil {
					t.Fatal("trailing bytes accepted")
				}
				unknown := append([]byte(nil), raw...)
				binary.LittleEndian.PutUint32(unknown, 0xffffffff)
				if _, err := decode(unknown); err == nil {
					t.Fatal("unknown constructor accepted")
				}
			}
		})
	}
}

func TestV050ResultDecodersAreClosed(t *testing.T) {
	tests := []struct {
		name    string
		decode  func([]byte) (any, error)
		accepts func(any) bool
	}{
		{"payment", DecodeRelayPaymentResult, func(v any) bool {
			switch v.(type) {
			case RelayBalanceV1, RelayPaymentRejectedV1:
				return true
			}
			return false
		}},
		{"deposit", DecodeDepositResult, func(v any) bool {
			switch v.(type) {
			case InboxReceiptV1, InboxRejectedV1:
				return true
			}
			return false
		}},
		{"challenge", DecodeInboxChallengeResult, func(v any) bool {
			switch v.(type) {
			case InboxChallengeV1, InboxChallengeRejectedV1:
				return true
			}
			return false
		}},
		{"page", DecodeInboxPageResult, func(v any) bool {
			switch v.(type) {
			case InboxPageV1, InboxPageRejectedV1:
				return true
			}
			return false
		}},
		{"ack", DecodeInboxAckResult, func(v any) bool {
			switch v.(type) {
			case InboxAckedV1, InboxAckRejectedV1:
				return true
			}
			return false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, fixture := range wireV050Fixtures() {
				raw, err := Encode(fixture.value)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := test.decode(raw)
				if test.accepts(fixture.value) {
					if err != nil || !reflect.DeepEqual(decoded, fixture.value) {
						t.Fatalf("%T: decoded=%#v err=%v", fixture.value, decoded, err)
					}
				} else if err == nil {
					t.Fatalf("unrelated constructor %T accepted", fixture.value)
				}
				if _, err := test.decode(append(raw, 0)); err == nil {
					t.Fatal("trailing result bytes accepted")
				}
			}
		})
	}
}

func TestV050DirectAndStateConstructorsRemainDistinct(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	old := DirectMessage{RoomID: key, FromKey: key, ToKey: key}
	if _, err := Encode(old); err == nil {
		t.Fatal("obsolete V2 DM is still registered")
	}
	raw, err := Encode(DirectMessageToSign{RoomID: key, FromKey: key, ToKey: key})
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(raw, 0xa5529daf)
	raw = append(raw, 64)
	raw = append(raw, make([]byte, 67)...)
	if _, err := DecodeDirectMessage(raw); err == nil {
		t.Fatal("obsolete V2 DM decoded")
	}
	if _, err := DecodeDirectMessageV3(raw); err == nil {
		t.Fatal("V3 decoder accepted V2 DM")
	}
	deposit, err := Encode(InboxDepositV1{Message: DirectMessageV3{FromKey: key, ToKey: key}})
	if err != nil {
		t.Fatal(err)
	}
	// Replace the boxed V3 field with a complete, valid V2 message.
	wrong := append(append(append([]byte(nil), deposit[:4]...), raw...), deposit[len(deposit)-4:]...)
	if _, err := DecodeInboxDepositV1(wrong); err == nil {
		t.Fatal("deposit accepted V2 DM")
	}
	oldState := RoomState{RoomID: key, RevisionHash: key}
	raw, err = Encode(oldState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRoomState(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRoomStateV3(raw); err == nil {
		t.Fatal("V3 decoder accepted V2 state")
	}
}

func TestV050RelayCardValidation(t *testing.T) {
	freeCard := func() RelayCardV1 {
		return RelayCardV1{
			RelayKey: bytes.Repeat([]byte{1}, 32), Services: RelayServiceDM,
			PaymentKey: Zero256(), Offers: []RelayOfferV1{{Services: RelayServiceDM}},
		}
	}
	paidCard := func() RelayCardV1 {
		card := freeCard()
		card.Services |= RelayServicePaidTiers
		card.PaymentKey = bytes.Repeat([]byte{2}, 32)
		card.Offers = append(card.Offers, RelayOfferV1{Tier: 1, Services: RelayServiceDM, PriceNanoton: 1, UnitBytes: 1})
		return card
	}
	tests := []struct {
		name   string
		paid   bool
		change func(*RelayCardV1)
		valid  bool
	}{
		{"free", false, func(c *RelayCardV1) {}, true},
		{"free ignores price and unit", false, func(c *RelayCardV1) { c.Offers[0].PriceNanoton = -1; c.Offers[0].UnitBytes = -1 }, true},
		{"paid", true, func(c *RelayCardV1) {}, true},
		{"paid without free offer", true, func(c *RelayCardV1) { c.Offers = c.Offers[1:] }, true},
		{"object above protocol maximum", false, func(c *RelayCardV1) { c.Offers[0].MaxObjectBytes = MaxRelayObjectBytes + 1 }, false},
		{"no offers", false, func(c *RelayCardV1) { c.Offers = nil }, false},
		{"reserved card bit", false, func(c *RelayCardV1) { c.Services |= RelayServiceReserved }, false},
		{"zero offer services", false, func(c *RelayCardV1) { c.Offers[0].Services = 0 }, false},
		{"reserved offer bit", false, func(c *RelayCardV1) { c.Offers[0].Services |= RelayServiceReserved }, false},
		{"paid offer bit", true, func(c *RelayCardV1) { c.Offers[1].Services |= RelayServicePaidTiers }, false},
		{"unknown offer service", false, func(c *RelayCardV1) { c.Services |= 8; c.Offers[0].Services = 8 }, false},
		{"service not on card", false, func(c *RelayCardV1) { c.Services = 0 }, false},
		{"duplicate free tier", false, func(c *RelayCardV1) { c.Offers = append(c.Offers, c.Offers[0]) }, false},
		{"duplicate paid tier", true, func(c *RelayCardV1) { c.Offers = append(c.Offers, c.Offers[1]) }, false},
		{"zero price", true, func(c *RelayCardV1) { c.Offers[1].PriceNanoton = 0 }, false},
		{"negative price", true, func(c *RelayCardV1) { c.Offers[1].PriceNanoton = -1 }, false},
		{"zero unit", true, func(c *RelayCardV1) { c.Offers[1].UnitBytes = 0 }, false},
		{"negative unit", true, func(c *RelayCardV1) { c.Offers[1].UnitBytes = -1 }, false},
		{"free with payment key", false, func(c *RelayCardV1) { c.PaymentKey[0] = 1 }, false},
		{"free with paid offer", false, func(c *RelayCardV1) { c.Offers[0].Tier = 1; c.Offers[0].PriceNanoton = 1; c.Offers[0].UnitBytes = 1 }, false},
		{"paid with zero key", true, func(c *RelayCardV1) { c.PaymentKey = Zero256() }, false},
		{"paid without paid offer", true, func(c *RelayCardV1) { c.Offers = c.Offers[:1] }, false},
		{"short payment key", false, func(c *RelayCardV1) { c.PaymentKey = []byte{0} }, false},
		{"short relay key", false, func(c *RelayCardV1) { c.RelayKey = []byte{1} }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			card := freeCard()
			if test.paid {
				card = paidCard()
			}
			test.change(&card)
			if err := card.Validate(); (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
	// With the supported address constructors the sizes adjacent to 128 are
	// 120 and 132 bytes (24-byte boxed list plus 12 bytes per IPv4 address).
	for _, n := range []int{8, 9} {
		card := freeCard()
		for i := 0; i < n; i++ {
			card.Addrs.Addresses = append(card.Addrs.Addresses, address.QUIC{IP: net.IP{192, 0, 2, byte(i + 1)}, Port: 17400})
		}
		raw, err := Encode(card.Addrs)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) != 24+12*n {
			t.Fatalf("unexpected address size %d", len(raw))
		}
		bare, err := tl.Serialize(card.Addrs, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(bare) != 20+12*n || len(raw) != len(bare)+4 {
			t.Fatalf("boxed=%d bare=%d", len(raw), len(bare))
		}
		if err := card.Validate(); (err == nil) != (n == 8) {
			t.Fatalf("%d serialized address bytes: %v", len(raw), err)
		}
	}
}

func TestV050QueryValidation(t *testing.T) {
	for _, test := range []struct {
		limit, want int32
		valid       bool
	}{
		{0, DefaultPageLimit, true}, {1, 1, true}, {MaxPageLimit, MaxPageLimit, true},
		{-1, 0, false}, {MaxPageLimit + 1, 0, false},
	} {
		got, err := (GetRoomCardsV1{Limit: test.limit}).PageLimit()
		if (err == nil) != test.valid || got != test.want {
			t.Fatalf("limit=%d got=%d err=%v", test.limit, got, err)
		}
	}
	for _, n := range []int{0, 1, 256, 257} {
		if err := (InboxAckV1{IDs: make([][]byte, n)}).Validate(); (err == nil) != (n <= 256) {
			t.Fatalf("ack count=%d err=%v", n, err)
		}
	}
	for _, tier := range []int32{-1, 0, 1} {
		if err := (OverlayQueryV1{Tier: tier}).Validate(); (err == nil) != (tier == 0) {
			t.Fatalf("overlay tier=%d err=%v", tier, err)
		}
	}
	if RejectRelayFullOrQuotaExceeded != 16 || RejectInsufficientPrepaidBalance != 17 ||
		RejectInboxAuthenticationFailed != 18 || RejectOverlayNotServed != 19 {
		t.Fatal("incorrect v0.5.0 rejection codes")
	}
}

func TestV050SignedObjects(t *testing.T) {
	private := testPrivate(t)
	owner := []byte(private.Public().(ed25519.PublicKey))
	peer := []byte(testPrivate(t).Public().(ed25519.PublicKey))
	hash := testNonce(t)
	relay, err := SignRelayCardV1(private, RelayCardV1{
		RelayKey: owner, Services: RelayServiceDM, PaymentKey: Zero256(),
		Offers: []RelayOfferV1{{Services: RelayServiceDM}}, Version: 1800000000,
	})
	if err != nil {
		t.Fatal(err)
	}
	room, err := SignRoomCardV1(private, RoomCardV1{
		RoomKey: owner, NodeKey: peer, Name: "room", Alias: "example.ton", Version: 1800000000,
	})
	if err != nil {
		t.Fatal(err)
	}
	state, err := SignRoomStateV3(private, RoomStateV3{
		RoomID: owner, RevisionHash: hash, Name: "room", Banned: [][]byte{peer},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := SignDirectMessageV3(private, DirectMessageV3{
		ToKey: peer, AuthorName: "alice", AuthorDomain: "alice.ton",
		CreatedAt: 1800000000, ExpireAt: 1800003600, Ciphertext: make([]byte, 28),
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := SignInboxReceiptV1(private, InboxReceiptV1{
		RelayKey: owner, DMID: hash, InboxID: peer, ExpireAt: 1800003600,
	})
	if err != nil {
		t.Fatal(err)
	}
	inboxID, err := KeyID(owner)
	if err != nil {
		t.Fatal(err)
	}
	context := InboxAuthV1ToSign{RelayKey: peer, InboxID: inboxID, Nonce: hash, ExpireAt: 1800000300}
	auth, err := SignInboxAuthV1(private, context)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		toSign    any
		signature []byte
		verify    func() error
		tamper    func() error
	}{
		{"relay card", relay.toSign(), relay.Signature, relay.Verify, func() error { v := relay; v.Version++; return v.Verify() }},
		{"room card", room.toSign(), room.Signature, room.Verify, func() error { v := room; v.Name = "tampered"; return v.Verify() }},
		{"room state", state.toSign(), state.Signature, state.Verify, func() error { v := state; v.Banned = nil; return v.Verify() }},
		{"direct message", message.toSign(), message.Signature, message.Verify, func() error { v := message; v.AuthorDomain = "mallory.ton"; return v.Verify() }},
		{"receipt", receipt.toSign(), receipt.Signature, receipt.Verify, func() error { v := receipt; v.ExpireAt++; return v.Verify() }},
		{"inbox auth", context, auth.Signature, func() error { return auth.Verify(context) }, func() error { v := context; v.ExpireAt++; return auth.Verify(v) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.verify(); err != nil {
				t.Fatal(err)
			}
			digest, err := HashBoxed(test.toSign)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(ed25519.PublicKey(owner), digest, test.signature) {
				t.Fatal("signature does not cover boxed toSign hash")
			}
			if err := test.tamper(); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("tampered field: %v", err)
			}
		})
	}
	badAuth := auth
	badAuth.Nonce = testNonce(t)
	if badAuth.Verify(context) == nil {
		t.Fatal("auth nonce mismatch accepted")
	}
	badAuth = auth
	badAuth.RecipientKey = peer
	if badAuth.Verify(context) == nil {
		t.Fatal("wrong inbox recipient accepted")
	}
	badContext := context
	badContext.RelayKey = owner
	if !errors.Is(auth.Verify(badContext), ErrBadSignature) {
		t.Fatal("wrong relay context accepted")
	}
	badContext = context
	badContext.InboxID = peer
	if _, err := SignInboxAuthV1(private, badContext); err == nil {
		t.Fatal("wrong inbox context signed")
	}
	if _, err := signWire(nil, owner, context); !errors.Is(err, ErrMalformedKey) {
		t.Fatal("short private key accepted")
	}
	if _, err := signWire(private, peer, context); !errors.Is(err, ErrMalformedKey) {
		t.Fatal("wrong signer accepted")
	}
	if err := verifyWire(nil, auth.Signature, context); !errors.Is(err, ErrMalformedKey) {
		t.Fatal("short public key accepted")
	}
	if err := verifyWire(owner, nil, context); !errors.Is(err, ErrBadSignature) {
		t.Fatal("short signature accepted")
	}
}

func TestV050RelayCardBareAddressEncoding(t *testing.T) {
	card := RelayCardV1{
		RelayKey: bytes.Repeat([]byte{0x11}, 32),
		Addrs: address.List{
			Addresses: []address.Address{address.QUIC{IP: net.IP{192, 0, 2, 1}, Port: 0x1234}},
			Version:   1, ReinitDate: 2, Priority: 3, ExpireAt: 4,
		},
		Services: RelayServiceDM, PaymentKey: Zero256(),
		Offers: []RelayOfferV1{{Services: RelayServiceDM, MaxObjectBytes: 65536,
			RetentionSeconds: 86400, RequestsPerMinute: 60, InboxQuotaBytes: 1048576}},
		Version: 5, Signature: bytes.Repeat([]byte{0x66}, 64),
	}
	// Independent wire fixture: the address vector count follows relay_key
	// immediately. Only each address carries a constructor, not addressList.
	const fields = "1111111111111111111111111111111111111111111111111111111111111111" +
		"01000000" + // Address count.
		"53720178010200c034120000" + // QUIC constructor, IPv4 integer, port.
		"01000000020000000300000004000000" + // Address-list metadata.
		"02000000" + // Card services.
		"0000000000000000000000000000000000000000000000000000000000000000" + // Payment key.
		"010000005e1395cf" + // Offer count and constructor.
		"000000000200000000000100805101003c000000" + // Tier, services, size, retention, rate.
		"000010000000000000000000000000000000000000000000" + // Quota, price, unit.
		"05000000" // Card version.
	const signature = "40" +
		"6666666666666666666666666666666666666666666666666666666666666666" +
		"6666666666666666666666666666666666666666666666666666666666666666" + "000000"
	for _, test := range []struct {
		value any
		want  string
	}{
		{card, "153b250d" + fields + signature},
		{card.toSign(), "2c294f37" + fields},
	} {
		t.Run(reflect.TypeOf(test.value).Name(), func(t *testing.T) {
			want, err := hex.DecodeString(test.want)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := Encode(test.value)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, want) {
				t.Fatalf("wire bytes = %x, want %x", raw, want)
			}
			decoded, err := DecodeAny(want)
			if err != nil || !reflect.DeepEqual(decoded, test.value) {
				t.Fatalf("golden decode = %#v, err=%v", decoded, err)
			}
		})
	}
}

func TestV050BanProposalWireBodies(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	signature := bytes.Repeat([]byte{2}, 64)
	unrelated, err := Encode(GetInboxChallengeV1{InboxID: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []any{EventBanV1{SubjectKey: key}, EventUnbanV1{SubjectKey: key}} {
		t.Run(reflect.TypeOf(body).Name(), func(t *testing.T) {
			bodyRaw, err := Encode(body)
			if err != nil {
				t.Fatal(err)
			}
			proposal := EventProposal{RoomID: key, AuthorKey: key, Nonce: key,
				Timestamp: 1800000000, Body: body, Signature: signature}
			commit := CommittedEvent{Seqno: 1, PreviousHash: Zero256(), Proposal: proposal,
				CommittedAt: 1800000001, Signature: signature}
			// All other EventBody carriers nest EventProposal; they need no new tags.
			for _, test := range []struct {
				value  any
				decode func([]byte) (any, error)
			}{
				{proposal, wireV050Decoder(DecodeProposal)},
				{commit, wireV050Decoder(DecodeCommittedEvent)},
				{SubmitEvent{Proposal: proposal}, DecodeAny},
				{SubmitAccepted{Event: commit}, DecodeAny},
				{SubmitDuplicate{Event: commit}, DecodeAny},
				{EventList{Events: []CommittedEvent{commit}}, DecodeAny},
				{MessageList{Messages: []CommittedEvent{commit}}, DecodeAny},
			} {
				raw, err := Encode(test.value)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := test.decode(raw)
				if err != nil || !reflect.DeepEqual(decoded, test.value) {
					t.Fatalf("%T roundtrip = %#v, err=%v", test.value, decoded, err)
				}
				offset := bytes.Index(raw, bodyRaw)
				if offset < 0 {
					t.Fatalf("%T: missing event body", test.value)
				}
				for _, constructor := range [][]byte{{0xff, 0xff, 0xff, 0xff}, unrelated[:4]} {
					invalid := append([]byte(nil), raw...)
					copy(invalid[offset:offset+4], constructor)
					if _, err := test.decode(invalid); err == nil {
						t.Fatalf("%T accepted body constructor %x", test.value, constructor)
					}
				}
			}
		})
	}
	if _, err := Encode(EventProposal{RoomID: key, AuthorKey: key, Nonce: key,
		Body: GetInboxChallengeV1{InboxID: key}}); err == nil {
		t.Fatal("proposal encoded an unrelated body type")
	}
}

func TestV050RelayOfferProtocolMaxima(t *testing.T) {
	for _, tier := range []int32{0, 1} {
		for _, size := range []int32{MaxRelayObjectBytes - 1, MaxRelayObjectBytes, MaxRelayObjectBytes + 1} {
			offer := RelayOfferV1{Tier: tier, Services: RelayServiceDM, MaxObjectBytes: size,
				PriceNanoton: 1, UnitBytes: 1}
			if err := offer.Validate(RelayServiceDM); (err == nil) != (size <= 64<<10) {
				t.Fatalf("tier=%d size=%d: %v", tier, size, err)
			}
		}
	}
	// Section 8 gives no DM-retention, per-minute-rate or per-inbox quota cap.
	// In particular, author nonce retention is not a DM retention limit.
	for _, offer := range []RelayOfferV1{
		{Services: RelayServiceDM, RetentionSeconds: 1<<31 - 1},
		{Services: RelayServiceDM, RequestsPerMinute: 1<<31 - 1},
		{Services: RelayServiceDM, InboxQuotaBytes: 1<<63 - 1},
	} {
		if err := offer.Validate(RelayServiceDM); err != nil {
			t.Fatalf("uncapped field rejected: %+v: %v", offer, err)
		}
	}
}

func TestRoomStateV3Validation(t *testing.T) {
	private := testPrivate(t)
	key := []byte(private.Public().(ed25519.PublicKey))
	keys := func(n int) [][]byte {
		values := make([][]byte, n)
		for i := range values {
			values[i] = Zero256()
			binary.BigEndian.PutUint64(values[i][24:], uint64(i+1))
		}
		return values
	}
	base := func() RoomStateV3 {
		return RoomStateV3{RoomID: key, RevisionHash: Zero256(), Name: "Room"}
	}
	tests := []struct {
		name   string
		change func(*RoomStateV3)
		valid  bool
	}{
		{"empty lists", func(s *RoomStateV3) {}, true},
		{"all caps", func(s *RoomStateV3) {
			s.Admins = keys(64)
			s.Moderators = keys(256)
			s.Banned = keys(256)
			s.PinnedMessages = make([]int64, 100)
			for i := range s.PinnedMessages {
				s.PinnedMessages[i] = int64(i + 1)
			}
			s.Name = string(bytes.Repeat([]byte{'n'}, 64))
			s.Description = string(bytes.Repeat([]byte{'d'}, 512))
		}, true},
		{"admins cap", func(s *RoomStateV3) { s.Admins = keys(65) }, false},
		{"moderators cap", func(s *RoomStateV3) { s.Moderators = keys(257) }, false},
		{"banned cap", func(s *RoomStateV3) { s.Banned = keys(257) }, false},
		{"pins cap", func(s *RoomStateV3) {
			s.PinnedMessages = make([]int64, 101)
			for i := range s.PinnedMessages {
				s.PinnedMessages[i] = int64(i + 1)
			}
		}, false},
		{"admins order", func(s *RoomStateV3) { s.Admins = keys(2); s.Admins[0], s.Admins[1] = s.Admins[1], s.Admins[0] }, false},
		{"moderators order", func(s *RoomStateV3) {
			s.Moderators = keys(2)
			s.Moderators[0], s.Moderators[1] = s.Moderators[1], s.Moderators[0]
		}, false},
		{"banned order", func(s *RoomStateV3) { s.Banned = keys(2); s.Banned[0], s.Banned[1] = s.Banned[1], s.Banned[0] }, false},
		{"pins order", func(s *RoomStateV3) { s.PinnedMessages = []int64{2, 1} }, false},
		{"duplicate admins", func(s *RoomStateV3) { s.Admins = [][]byte{key, key} }, false},
		{"duplicate moderators", func(s *RoomStateV3) { s.Moderators = [][]byte{key, key} }, false},
		{"duplicate banned", func(s *RoomStateV3) { s.Banned = [][]byte{key, key} }, false},
		{"duplicate pins", func(s *RoomStateV3) { s.PinnedMessages = []int64{1, 1} }, false},
		{"zero pin", func(s *RoomStateV3) { s.PinnedMessages = []int64{0} }, false},
		{"short admin", func(s *RoomStateV3) { s.Admins = [][]byte{{1}} }, false},
		{"short moderator", func(s *RoomStateV3) { s.Moderators = [][]byte{{1}} }, false},
		{"short banned", func(s *RoomStateV3) { s.Banned = [][]byte{{1}} }, false},
		{"short room key", func(s *RoomStateV3) { s.RoomID = []byte{1} }, false},
		{"short revision hash", func(s *RoomStateV3) { s.RevisionHash = []byte{1} }, false},
		{"negative revision", func(s *RoomStateV3) { s.RevisionSeqno = -1 }, false},
		{"empty name", func(s *RoomStateV3) { s.Name = "" }, false},
		{"name size", func(s *RoomStateV3) { s.Name = string(bytes.Repeat([]byte{'n'}, 65)) }, false},
		{"name utf8", func(s *RoomStateV3) { s.Name = string([]byte{0xff}) }, false},
		{"name control", func(s *RoomStateV3) { s.Name = "room\n" }, false},
		{"description size", func(s *RoomStateV3) { s.Description = string(bytes.Repeat([]byte{'d'}, 513)) }, false},
		{"description utf8", func(s *RoomStateV3) { s.Description = string([]byte{0xff}) }, false},
		{"description nul", func(s *RoomStateV3) { s.Description = "a\x00b" }, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base()
			test.change(&state)
			// Sign directly so invalid order is not repaired by SignRoomStateV3.
			digest, err := HashBoxed(state.toSign())
			if err == nil {
				state.Signature = ed25519.Sign(private, digest)
			}
			if err := state.Verify(); (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
	state := base()
	state.Admins, state.Moderators, state.Banned = keys(2), keys(2), keys(2)
	for _, values := range [][][]byte{state.Admins, state.Moderators, state.Banned} {
		values[0], values[1] = values[1], values[0]
	}
	state.PinnedMessages = []int64{2, 1}
	signed, err := SignRoomStateV3(private, state)
	if err != nil || signed.Verify() != nil {
		t.Fatalf("canonical signing: %v", err)
	}
	if bytes.Compare(state.Banned[0], state.Banned[1]) < 0 || state.PinnedMessages[0] != 2 {
		t.Fatal("signer mutated input lists")
	}
	for _, values := range [][][]byte{signed.Admins, signed.Moderators, signed.Banned} {
		if bytes.Compare(values[0], values[1]) >= 0 {
			t.Fatal("signed keys are not sorted")
		}
	}
	if signed.PinnedMessages[0] != 1 {
		t.Fatal("signed pins are not sorted")
	}
	tooMany := base()
	tooMany.Banned = keys(257)
	if _, err := SignRoomStateV3(private, tooMany); err == nil {
		t.Fatal("signer accepted banned overflow")
	}
}

func TestBanProposalSignaturesAndSubjectKeys(t *testing.T) {
	room, node, author := testPrivate(t), testPrivate(t), testPrivate(t)
	now := time.Now()
	for _, body := range []any{EventBanV1{SubjectKey: room.Public().(ed25519.PublicKey)}, EventUnbanV1{SubjectKey: room.Public().(ed25519.PublicKey)}} {
		proposal, err := SignProposal(author, node.Public().(ed25519.PublicKey), EventProposal{
			RoomID: room.Public().(ed25519.PublicKey), Nonce: testNonce(t), Timestamp: now.Unix(), Body: body,
		})
		if err != nil || proposal.Verify(node.Public().(ed25519.PublicKey), now) != nil {
			t.Fatalf("ban signing: %v", err)
		}
		switch body.(type) {
		case EventBanV1:
			proposal.Body = EventBanV1{SubjectKey: node.Public().(ed25519.PublicKey)}
		case EventUnbanV1:
			proposal.Body = EventUnbanV1{SubjectKey: node.Public().(ed25519.PublicKey)}
		}
		if err := proposal.Verify(node.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("tampered ban: %v", err)
		}
	}
	for _, body := range []any{EventBanV1{SubjectKey: []byte{1}}, EventUnbanV1{SubjectKey: make([]byte, 33)}, (*EventBanV1)(nil), (*EventUnbanV1)(nil)} {
		if err := ValidateBody(body); !errors.Is(err, ErrMalformedKey) {
			t.Fatalf("invalid %T accepted: %v", body, err)
		}
	}
}
