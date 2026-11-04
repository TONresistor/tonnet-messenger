package community

import (
	"fmt"

	"github.com/xssnick/tonutils-go/tl"
)

func Encode(value any) ([]byte, error) { return tl.Serialize(value, true) }

func DecodeAny(raw []byte) (any, error) {
	var value any
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("community: trailing TL bytes")
	}
	return value, nil
}

func DecodeGenesis(raw []byte) (Genesis, error) {
	var value Genesis
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return Genesis{}, err
	}
	if len(rest) != 0 {
		return Genesis{}, fmt.Errorf("community: trailing genesis bytes")
	}
	return value, nil
}

func DecodeRoomState(raw []byte) (RoomState, error) {
	var value RoomState
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return RoomState{}, err
	}
	if len(rest) != 0 {
		return RoomState{}, fmt.Errorf("community: trailing state bytes")
	}
	return value, nil
}

func DecodeProposal(raw []byte) (EventProposal, error) {
	var value EventProposal
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return EventProposal{}, err
	}
	if len(rest) != 0 {
		return EventProposal{}, fmt.Errorf("community: trailing proposal bytes")
	}
	return value, nil
}

func DecodeCommittedEvent(raw []byte) (CommittedEvent, error) {
	var value CommittedEvent
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return CommittedEvent{}, err
	}
	if len(rest) != 0 {
		return CommittedEvent{}, fmt.Errorf("community: trailing committed-event bytes")
	}
	return value, nil
}

func DecodeDirectMessage(raw []byte) (DirectMessage, error) {
	var value DirectMessage
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		return DirectMessage{}, err
	}
	if len(rest) != 0 {
		return DirectMessage{}, fmt.Errorf("community: trailing direct-message bytes")
	}
	return value, nil
}

// decodeWire keeps new wire decoders strict without changing the V2 entry points.
func decodeWire[T any](raw []byte) (T, error) {
	var value T
	rest, err := tl.Parse(&value, raw, true)
	if err != nil {
		var zero T
		return zero, err
	}
	if len(rest) != 0 {
		var zero T
		return zero, fmt.Errorf("community: trailing TL bytes")
	}
	return value, nil
}

func DecodeRelayOfferV1(raw []byte) (RelayOfferV1, error) {
	return decodeWire[RelayOfferV1](raw)
}

func DecodeRelayCardV1(raw []byte) (RelayCardV1, error) {
	return decodeWire[RelayCardV1](raw)
}

func DecodeRoomCardV1(raw []byte) (RoomCardV1, error) {
	return decodeWire[RoomCardV1](raw)
}

func DecodeRelayPaymentV1(raw []byte) (RelayPaymentV1, error) {
	return decodeWire[RelayPaymentV1](raw)
}

func DecodeRelayBalanceV1(raw []byte) (RelayBalanceV1, error) {
	return decodeWire[RelayBalanceV1](raw)
}

func DecodeRelayPaymentRejectedV1(raw []byte) (RelayPaymentRejectedV1, error) {
	return decodeWire[RelayPaymentRejectedV1](raw)
}

func DecodeGetRelayCardV1(raw []byte) (GetRelayCardV1, error) {
	return decodeWire[GetRelayCardV1](raw)
}

func DecodeGetRoomCardsV1(raw []byte) (GetRoomCardsV1, error) {
	return decodeWire[GetRoomCardsV1](raw)
}

func DecodeRoomCardListV1(raw []byte) (RoomCardListV1, error) {
	return decodeWire[RoomCardListV1](raw)
}

func DecodeOverlayQueryV1(raw []byte) (OverlayQueryV1, error) {
	return decodeWire[OverlayQueryV1](raw)
}

func DecodeOverlayRejectedV1(raw []byte) (OverlayRejectedV1, error) {
	return decodeWire[OverlayRejectedV1](raw)
}

func DecodeGetCapabilities(raw []byte) (GetCapabilities, error) {
	return decodeWire[GetCapabilities](raw)
}

func DecodeCapabilities(raw []byte) (Capabilities, error) {
	return decodeWire[Capabilities](raw)
}

func DecodeEventBanV1(raw []byte) (EventBanV1, error) {
	return decodeWire[EventBanV1](raw)
}

func DecodeEventUnbanV1(raw []byte) (EventUnbanV1, error) {
	return decodeWire[EventUnbanV1](raw)
}

func DecodeRoomStateV3(raw []byte) (RoomStateV3, error) {
	return decodeWire[RoomStateV3](raw)
}

func DecodeDirectMessageV3(raw []byte) (DirectMessageV3, error) {
	return decodeWire[DirectMessageV3](raw)
}

func DecodeInboxDepositV1(raw []byte) (InboxDepositV1, error) {
	return decodeWire[InboxDepositV1](raw)
}

func DecodeInboxReceiptV1(raw []byte) (InboxReceiptV1, error) {
	return decodeWire[InboxReceiptV1](raw)
}

func DecodeInboxRejectedV1(raw []byte) (InboxRejectedV1, error) {
	return decodeWire[InboxRejectedV1](raw)
}

func DecodeGetInboxChallengeV1(raw []byte) (GetInboxChallengeV1, error) {
	return decodeWire[GetInboxChallengeV1](raw)
}

func DecodeInboxChallengeV1(raw []byte) (InboxChallengeV1, error) {
	return decodeWire[InboxChallengeV1](raw)
}

func DecodeInboxChallengeRejectedV1(raw []byte) (InboxChallengeRejectedV1, error) {
	return decodeWire[InboxChallengeRejectedV1](raw)
}

func DecodeInboxAuthV1(raw []byte) (InboxAuthV1, error) {
	return decodeWire[InboxAuthV1](raw)
}

func DecodeGetInboxV1(raw []byte) (GetInboxV1, error) {
	return decodeWire[GetInboxV1](raw)
}

func DecodeInboxPageV1(raw []byte) (InboxPageV1, error) {
	return decodeWire[InboxPageV1](raw)
}

func DecodeInboxPageRejectedV1(raw []byte) (InboxPageRejectedV1, error) {
	return decodeWire[InboxPageRejectedV1](raw)
}

func DecodeInboxAckV1(raw []byte) (InboxAckV1, error) {
	return decodeWire[InboxAckV1](raw)
}

func DecodeInboxAckedV1(raw []byte) (InboxAckedV1, error) {
	return decodeWire[InboxAckedV1](raw)
}

func DecodeInboxAckRejectedV1(raw []byte) (InboxAckRejectedV1, error) {
	return decodeWire[InboxAckRejectedV1](raw)
}

func DecodeInboxPushV1(raw []byte) (InboxPushV1, error) {
	return decodeWire[InboxPushV1](raw)
}

func DecodeRelayPaymentResult(raw []byte) (any, error) {
	value, err := DecodeAny(raw)
	if err != nil {
		return nil, err
	}
	switch value.(type) {
	case RelayBalanceV1, RelayPaymentRejectedV1:
		return value, nil
	default:
		return nil, fmt.Errorf("community: unexpected RelayPaymentResult constructor %T", value)
	}
}

func DecodeDepositResult(raw []byte) (any, error) {
	value, err := DecodeAny(raw)
	if err != nil {
		return nil, err
	}
	switch value.(type) {
	case InboxReceiptV1, InboxRejectedV1:
		return value, nil
	default:
		return nil, fmt.Errorf("community: unexpected DepositResult constructor %T", value)
	}
}

func DecodeInboxChallengeResult(raw []byte) (any, error) {
	value, err := DecodeAny(raw)
	if err != nil {
		return nil, err
	}
	switch value.(type) {
	case InboxChallengeV1, InboxChallengeRejectedV1:
		return value, nil
	default:
		return nil, fmt.Errorf("community: unexpected InboxChallengeResult constructor %T", value)
	}
}

func DecodeInboxPageResult(raw []byte) (any, error) {
	value, err := DecodeAny(raw)
	if err != nil {
		return nil, err
	}
	switch value.(type) {
	case InboxPageV1, InboxPageRejectedV1:
		return value, nil
	default:
		return nil, fmt.Errorf("community: unexpected InboxPageResult constructor %T", value)
	}
}

func DecodeInboxAckResult(raw []byte) (any, error) {
	value, err := DecodeAny(raw)
	if err != nil {
		return nil, err
	}
	switch value.(type) {
	case InboxAckedV1, InboxAckRejectedV1:
		return value, nil
	default:
		return nil, fmt.Errorf("community: unexpected InboxAckResult constructor %T", value)
	}
}
