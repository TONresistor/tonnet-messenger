package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dm"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

// SendDM uses the current identity, independently of room membership.
func(c *Client)SendDM(ctx context.Context,recipient,text string)(map[string]any,error){
	if err:=community.ValidateDMPlaintext(text);err!=nil{return nil,err}
	to,err:=c.resolveIdentity(ctx,recipient);if err!=nil{return nil,err}
	c.identityOps.Lock();defer c.identityOps.Unlock()
	r,err:=c.ensureDM();if err!=nil{return nil,err}
	work,cancel:=context.WithCancel(ctx);stop:=context.AfterFunc(r.ctx,cancel);defer func(){stop();cancel()}()
	c.mu.RLock();name,domain:=c.name,c.domain;c.mu.RUnlock()
	if bytes.Equal(to,r.key.Public().(ed25519.PublicKey)){return nil,errors.New("cannot send a direct message to this identity")}
	box,err:=dm.SealV3(r.key,to,[]byte(text));if err!=nil{return nil,err}
	created:=time.Now().Unix()
	m:=community.DirectMessageV3{FromKey:r.key.Public().(ed25519.PublicKey),ToKey:to,AuthorName:name,AuthorDomain:domain,CreatedAt:created,ExpireAt:created+1,Ciphertext:box,Signature:make([]byte,64)}
	encoded,err:=community.Encode(community.InboxDepositV1{Message:m});if err!=nil{return nil,err}
	envelope,err:=community.Encode(m);if err!=nil{return nil,err}
	inbox,_:=community.KeyID(to)
	holders,ranked:=r.discover(work,inbox)
	var targets []dmCandidate
	targets=append(targets,holders...)
	if own:=r.ownRelay();own!=nil{targets=append(targets,*own)}
	targets=append(targets,ranked...)
	type selected struct{target dmCandidate;lease *replica.RelayLease;offer community.RelayOfferV1}
	var selectedRelays []selected
	seen:=make(map[string]bool)
	retention:=int64(0)
	for _,target:=range targets{
		if len(selectedRelays)==5{break};id:=string(target.key);if seen[id]{continue};seen[id]=true
		lease,err:=r.pool.acquire(work,target.key,target.address,time.Now());if err!=nil{continue}
		card,ok:=r.pool.card(target.key);if !ok{continue}
		for _,offer:=range card.Offers{
			if offer.Tier==0&&offer.Services==community.RelayServiceDM&&offer.MaxObjectBytes>=int32(len(encoded))&&offer.RetentionSeconds>0&&offer.RequestsPerMinute>0&&offer.InboxQuotaBytes>=int64(len(envelope)){
				selectedRelays=append(selectedRelays,selected{target,lease,offer});if retention==0||int64(offer.RetentionSeconds)<retention{retention=int64(offer.RetentionSeconds)};break
			}
		}
	}
	if len(selectedRelays)==0{return nil,ErrDMUnavailable}
	created=time.Now().Unix();m.CreatedAt=created
	m.ExpireAt=created+retention;m.Signature=nil
	m,err=community.SignDirectMessageV3(r.key,m);if err!=nil{return nil,err}
	id,err:=community.HashBoxed(m);if err!=nil{return nil,err}
	var receipts []string
	var firstRejection,firstProtocol error
	for _,selected:=range selectedRelays{
		query,cancel:=context.WithTimeout(work,5*time.Second);var response any
		err:=selected.lease.Query(query,community.InboxDepositV1{Message:m,Tier:0},&response);cancel()
		if err!=nil{r.failed(selected.target.key,err);continue}
		switch value:=response.(type){
		case community.InboxRejectedV1:
			r.pool.rejected(selected.target.key,value.Code,time.Now())
			if firstRejection==nil{if value.Code<1||value.Code>19{firstRejection=dmProtocolError(roomnet.ErrMalformedAnswer)}else{firstRejection=&RejectedError{Code:value.Code,Message:value.Message}}}
		case community.InboxReceiptV1:
			if !bytes.Equal(value.RelayKey,selected.lease.PublicKey())||!bytes.Equal(value.DMID,id)||!bytes.Equal(value.InboxID,inbox)||value.ExpireAt!=m.ExpireAt{
				r.pool.observe(selected.target.key,relayMalformedAnswer,time.Now());if firstProtocol==nil{firstProtocol=dmProtocolError(roomnet.ErrMalformedAnswer)};continue
			}
			if err:=value.Verify();err!=nil{r.failed(selected.target.key,err);if firstProtocol==nil{firstProtocol=dmProtocolError(err)};continue}
			r.pool.observe(selected.target.key,relaySuccess,time.Now());receipts=append(receipts,keyText(value.RelayKey))
		default:
			r.pool.observe(selected.target.key,relayMalformedAnswer,time.Now());if firstProtocol==nil{firstProtocol=dmProtocolError(roomnet.ErrMalformedAnswer)}
		}
		if len(receipts)>=3{break}
	}
	if len(receipts)==0{if firstRejection!=nil{return nil,firstRejection};if firstProtocol!=nil{return nil,firstProtocol};return nil,ErrDMUnavailable}
	view:=map[string]any{"id":keyText(id),"peer_key":keyText(to),"text":text,"timestamp":created,"direction":"sent","author_name":name,"status":"stored","receipts":receipts}
	if alias:=strings.ToLower(strings.TrimSpace(recipient));community.IsDomainName(alias){view["domain"]=alias}
	// Receipt durability is definitive even if shutdown cancels notification.
	c.notify(c.ctx,"dm.message",view)
	return view,nil
}
