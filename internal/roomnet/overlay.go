package roomnet

import (
	"bytes"
	"context"
	"fmt"

	"github.com/xssnick/tonutils-go/adnl/overlay"
	"github.com/xssnick/tonutils-go/tl"

	"github.com/TONresistor/tonnet-messenger/internal/broadcast"
	"github.com/TONresistor/tonnet-messenger/internal/community"
)

type OverlayRejection struct {
	community.OverlayRejectedV1
}

func (e *OverlayRejection) Error() string {
	return fmt.Sprintf("overlay rejected (%d): %s", e.Code, e.Message)
}

func (p *Peer) QueryRoom(ctx context.Context, roomKey []byte, request, result any) error {
	id, err := community.OverlayID(roomKey)
	if err != nil {
		return err
	}
	return p.QueryOverlay(ctx, id, request, result)
}

func (p *Peer) QueryOverlay(ctx context.Context, id []byte, request, result any) error {
	raw, err := tl.Serialize(request, true)
	if err != nil {
		return err
	}
	answer, err := p.query(ctx, community.OverlayQueryV1{Overlay: id, Query: raw})
	if err != nil {
		return err
	}
	if rejected, err := community.DecodeOverlayRejectedV1(answer); err == nil {
		err := &OverlayRejection{rejected}
		if rejected.Code != community.RejectMalformedRequest && rejected.Code != community.RejectOverlayNotServed {
			return fmt.Errorf("%w: %w", ErrMalformedAnswer, err)
		}
		return err
	}
	return decodeAnswer(answer, result)
}

// SelectOverlay returns true only when the inner query may be dispatched. Bare
// time queries bypass room selection; all room traffic requires the wrapper.
// A false result with nil error means a wrapper rejection was already answered.
func (q *Query) SelectOverlay(id []byte) (bool, error) {
	var wrapper community.OverlayQueryV1
	switch request := q.Data.(type) {
	case community.OverlayQueryV1:
		wrapper = request
	case *community.OverlayQueryV1:
		wrapper = *request
	case broadcast.GetTime, *broadcast.GetTime:
		return true, nil
	default:
		return false, ErrNoAnswer
	}
	if !bytes.Equal(wrapper.Overlay, id) {
		return false, q.Answer(community.OverlayRejectedV1{Code: community.RejectOverlayNotServed, Message: "overlay not served"})
	}
	if wrapper.Tier != 0 {
		return false, q.Answer(community.OverlayRejectedV1{Code: community.RejectMalformedRequest, Message: "overlay tier must be zero"})
	}
	inner, err := decodeAny(wrapper.Query)
	if err != nil {
		return false, err
	}
	switch inner.(type) {
	case overlay.GetRandomPeers, *overlay.GetRandomPeers,
		community.GetRoomGenesis, *community.GetRoomGenesis, community.GetRoomState, *community.GetRoomState,
		community.GetEvents, *community.GetEvents, community.GetMessagesRecent, *community.GetMessagesRecent,
		community.GetMessagesBefore, *community.GetMessagesBefore, community.SubmitEvent, *community.SubmitEvent,
		community.Batch, *community.Batch:
		q.Data = inner
		return true, nil
	default:
		return false, ErrNoAnswer
	}
}
