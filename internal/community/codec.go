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
