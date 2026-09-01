package clientrpc

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/TONresistor/tonnet-messenger/internal/client"
	"github.com/TONresistor/tonnet-messenger/internal/community"
)

const maxLineBytes = 64 * 1024

type Server struct {
	Client  *client.Client
	Version string
	mu      sync.Mutex
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (s *Server) Serve(ctx context.Context, input io.Reader, output io.Writer) error {
	if s.Client == nil {
		return fmt.Errorf("clientrpc: client is required")
	}
	if err := s.Client.Start(); err != nil {
		return err
	}
	notifyDone := make(chan struct{})
	go func() {
		defer close(notifyDone)
		for notification := range s.Client.Notifications() {
			_ = s.write(output, map[string]any{"jsonrpc": "2.0", "method": notification.Method, "params": notification.Params})
		}
	}()

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), maxLineBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			_ = s.write(output, response{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error", Data: map[string]any{"code": "PARSE_ERROR"}}})
			continue
		}
		if req.JSONRPC != "2.0" || req.Method == "" {
			_ = s.write(output, response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32600, Message: "invalid request", Data: map[string]any{"code": "INVALID_REQUEST"}}})
			continue
		}
		result, rpcErr := s.dispatch(ctx, req.Method, req.Params)
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue
		}
		if err := s.write(output, response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rpcErr}); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("clientrpc: request exceeds %d bytes", maxLineBytes)
		}
		return err
	}
	_ = s.Client.Close()
	<-notifyDone
	return nil
}

func (s *Server) dispatch(ctx context.Context, method string, raw json.RawMessage) (any, *rpcError) {
	params := func(target any) *rpcError {
		if len(raw) == 0 || string(raw) == "null" {
			raw = []byte("{}")
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return &rpcError{Code: -32602, Message: "invalid params", Data: map[string]any{"code": "INVALID_ARGUMENT"}}
		}
		return nil
	}
	fail := func(err error) (any, *rpcError) { return nil, classify(err) }

	switch method {
	case "client.info":
		return map[string]any{"version": s.Version, "protocol": "0.4.0", "transport": "stdio-jsonrpc", "identity": s.Client.Identity()}, nil
	case "identity.get":
		return s.Client.Identity(), nil
	case "identity.setName":
		var p struct {
			Name string `json:"name"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.SetName(ctx, p.Name)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "identity.prepareDomainLink":
		var p struct {
			Domain string `json:"domain"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.PrepareDomainLink(ctx, p.Domain)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "identity.confirmDomainLink":
		var p struct {
			Domain string `json:"domain"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.ConfirmDomain(ctx, p.Domain)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "identity.clearDomain":
		value, err := s.Client.ClearDomain(ctx)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "identity.reset":
		var p struct {
			ExpectedKey string `json:"expected_key"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.ResetIdentity(ctx, p.ExpectedKey)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "room.resolve":
		var p struct {
			Reference string `json:"reference"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.ResolveRoom(ctx, p.Reference)
		if err != nil {
			return fail(err)
		}
		return map[string]any{"room": value}, nil
	case "room.list":
		value, err := s.Client.Rooms(ctx)
		if err != nil {
			return fail(err)
		}
		return map[string]any{"rooms": value}, nil
	case "room.join":
		var p struct {
			Reference string `json:"reference"`
			Bootstrap string `json:"bootstrap,omitempty"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		bootstrap, err := decodeOptionalKey(p.Bootstrap)
		if err != nil {
			return fail(err)
		}
		value, err := s.Client.Join(ctx, p.Reference, bootstrap)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "room.leave":
		var p struct {
			Reference string `json:"reference"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		if err := s.Client.Leave(ctx, p.Reference); err != nil {
			return fail(err)
		}
		return map[string]any{"left": true}, nil
	case "room.getState":
		var p struct {
			Room string `json:"room"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.RoomState(p.Room)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "room.getTimeline":
		var p struct {
			Room   string `json:"room"`
			Before string `json:"before_seqno,omitempty"`
			Limit  int    `json:"limit,omitempty"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		roomKey, err := client.ParseKeyText(p.Room)
		if err != nil {
			return fail(err)
		}
		before, err := parseLong(p.Before)
		if err != nil {
			return fail(err)
		}
		items, more, err := s.Client.Timeline(ctx, roomKey, before, p.Limit)
		if err != nil {
			return fail(err)
		}
		return map[string]any{"items": items, "has_more": more}, nil
	case "room.sendMessage":
		var p struct {
			Room string `json:"room"`
			Text string `json:"text"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.SendMessage(ctx, p.Room, p.Text)
		if err != nil {
			return fail(err)
		}
		return value, nil
	case "room.setMetadata":
		var p struct {
			Room        string `json:"room"`
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		return mutation(ctx, s.Client, p.Room, community.EventMetadata{Name: p.Name, Description: p.Description})
	case "room.setWritePolicy":
		var p struct {
			Room   string `json:"room"`
			Policy string `json:"policy"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		if p.Policy != "everyone" && p.Policy != "admins" {
			return fail(fmt.Errorf("policy must be everyone or admins"))
		}
		return mutation(ctx, s.Client, p.Room, community.EventWritePolicy{AnyoneCanWrite: p.Policy == "everyone"})
	case "room.pin", "room.unpin":
		var p struct {
			Room      string `json:"room"`
			MessageID string `json:"message_id"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		id, err := parsePositiveLong(p.MessageID)
		if err != nil {
			return fail(err)
		}
		if method == "room.pin" {
			return mutation(ctx, s.Client, p.Room, community.EventPin{MessageID: id})
		}
		return mutation(ctx, s.Client, p.Room, community.EventUnpin{MessageID: id})
	case "room.grantModerator", "room.revokeModerator":
		var p struct {
			Room        string `json:"room"`
			IdentityKey string `json:"identity_key"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		key, err := client.ParseKeyText(p.IdentityKey)
		if err != nil {
			return fail(err)
		}
		if method == "room.grantModerator" {
			return mutation(ctx, s.Client, p.Room, community.EventModeratorGrant{SubjectKey: key})
		}
		return mutation(ctx, s.Client, p.Room, community.EventModeratorRevoke{SubjectKey: key})
	case "dm.send":
		var p struct {
			Room      string `json:"room"`
			Recipient string `json:"recipient"`
			Text      string `json:"text"`
		}
		if e := params(&p); e != nil {
			return nil, e
		}
		value, err := s.Client.SendDM(ctx, p.Room, p.Recipient, p.Text)
		if err != nil {
			return fail(err)
		}
		return value, nil
	default:
		return nil, &rpcError{Code: -32601, Message: "method not found", Data: map[string]any{"code": "METHOD_NOT_FOUND"}}
	}
}

func mutation(ctx context.Context, c *client.Client, room string, body any) (any, *rpcError) {
	value, err := c.SubmitMutation(ctx, room, body)
	if err != nil {
		return nil, classify(err)
	}
	return value, nil
}

func (s *Server) write(output io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded)+1 > maxLineBytes {
		return fmt.Errorf("clientrpc: response exceeds %d bytes", maxLineBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = output.Write(append(encoded, '\n'))
	return err
}

func classify(err error) *rpcError {
	code := "OPERATION_FAILED"
	numeric := -32000
	message := err.Error()
	var rejected *client.RejectedError
	if errors.As(err, &rejected) {
		numeric = -32010 - int(rejected.Code)
		switch rejected.Code {
		case community.RejectPermissionDenied:
			code = "PERMISSION_DENIED"
		case community.RejectSequencerUnavailable:
			code = "SEQUENCER_UNAVAILABLE"
		case community.RejectInvalidIdentityDomain:
			code = "INVALID_IDENTITY_DOMAIN"
		case community.RejectUnknownMessage:
			code = "UNKNOWN_MESSAGE"
		case community.RejectRoleConflict:
			code = "ROLE_CONFLICT"
		case community.RejectLimitExceeded:
			code = "LIMIT_EXCEEDED"
		default:
			code = "ROOM_REJECTED"
		}
	} else if errors.Is(err, context.DeadlineExceeded) {
		code, numeric, message = "TIMEOUT", -32001, "operation timed out"
	} else {
		lower := strings.ToLower(message)
		switch {
		case strings.Contains(lower, "invalid") || strings.Contains(lower, "must be") || strings.Contains(lower, "exceeds"):
			code, numeric = "INVALID_ARGUMENT", -32602
		case strings.Contains(lower, "not connected") || strings.Contains(lower, "not joined"):
			code, numeric = "NOT_CONNECTED", -32002
		case strings.Contains(lower, "no live") || strings.Contains(lower, "unavailable"):
			code, numeric = "ROOM_UNAVAILABLE", -32003
		}
	}
	return &rpcError{Code: numeric, Message: message, Data: map[string]any{"code": code}}
}

func parseLong(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return 0, fmt.Errorf("invalid decimal integer")
	}
	return parsed, nil
}

func parsePositiveLong(value string) (int64, error) {
	parsed, err := parseLong(value)
	if err != nil || parsed < 1 {
		return 0, fmt.Errorf("invalid positive decimal integer")
	}
	return parsed, nil
}

func decodeOptionalKey(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		decoded, err := encoding.DecodeString(strings.TrimSpace(value))
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid ADNL id")
}
