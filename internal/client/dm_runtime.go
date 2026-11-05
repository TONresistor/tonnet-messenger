package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/dht"
	"github.com/TONresistor/tonnet-messenger/internal/replica"
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

type dmInboxSession struct {
	mu sync.Mutex
	target dmCandidate
	lease *replica.RelayLease
	auth community.InboxAuthV1
	expire int64
	subscriptionUntil int64
	next time.Time
	fetching,subscribed bool
}
type dmPush struct { session *dmInboxSession; message community.InboxPushV1 }
type dmRuntime struct {
	client *Client
	key ed25519.PrivateKey
	epoch uint64
	pool *relayPool
	ctx context.Context
	cancel context.CancelFunc
	wg sync.WaitGroup
	discoverMu sync.Mutex
	discovery dht.Discovery
	mu sync.Mutex
	sessions map[string]*dmInboxSession
	incoming chan dmPush
	wake chan struct{}
	requests chan struct{}
}

// Caller holds identityOps. Runtime ownership changes atomically with the key.
func (c *Client) ensureDM()(*dmRuntime,error){
	c.mu.Lock();defer c.mu.Unlock()
	if c.closed{return nil,context.Canceled}
	if c.dmRuntime!=nil{return c.dmRuntime,nil}
	ctx,cancel:=context.WithCancel(c.ctx)
	r:=&dmRuntime{client:c,key:bytes.Clone(c.key),epoch:c.identityEpoch,pool:c.relays,ctx:ctx,cancel:cancel,sessions:make(map[string]*dmInboxSession),incoming:make(chan dmPush,128),wake:make(chan struct{},1),requests:make(chan struct{},3)}
	c.dmRuntime=r;r.wg.Add(1);go func(){defer r.wg.Done();r.run()}()
	return r,nil
}
func(r *dmRuntime)stop(){
	r.cancel();r.wg.Wait()
	r.mu.Lock();for _,s:=range r.sessions{s.lease.SubscribeInboxPush(nil)};r.mu.Unlock()
	r.discoverMu.Lock();if r.discovery!=nil{r.discovery.Close()};r.discoverMu.Unlock()
}
func(r *dmRuntime)failed(key ed25519.PublicKey,err error){
	var rejection *roomnet.OverlayRejection
	if errors.As(err,&rejection)&&!errors.Is(err,roomnet.ErrMalformedAnswer){r.pool.rejected(key,rejection.Code,time.Now());return}
	if errors.Is(err,context.Canceled){return}
	outcome:=relayNoAnswer
	if errors.Is(err,community.ErrBadSignature){outcome=relayInvalidSignature}else if errors.Is(err,roomnet.ErrMalformedAnswer){outcome=relayMalformedAnswer}else if errors.Is(err,context.DeadlineExceeded){outcome=relayTimeout}
	r.pool.observe(key,outcome,time.Now())
}
func(r *dmRuntime)run(){
	var discovery sync.WaitGroup
	discovery.Add(1)
	go func(){defer discovery.Done();tick:=time.NewTimer(0);defer tick.Stop();for{select{
	case <-r.ctx.Done():return
	case <-tick.C:r.updateSessions();tick.Reset(20*time.Second)
	}}}()
	defer discovery.Wait()
	timer:=time.NewTimer(0);defer timer.Stop()
	for{select{
	case <-r.ctx.Done():return
	case <-r.wake:timer.Reset(0)
	case push:=<-r.incoming:
		r.processPush(push)
	case <-timer.C:

		var due []*dmInboxSession
		r.mu.Lock();for _,s:=range r.sessions{s.mu.Lock();ready:=!time.Now().Before(s.next)||!relayLeaseLive(s.lease);s.mu.Unlock();if ready{due=append(due,s)}};r.mu.Unlock()
		jobs:=make(chan *dmInboxSession,len(due));for _,s:=range due{jobs<-s};close(jobs)
		var workers sync.WaitGroup
		for i:=0;i<min(3,len(due));i++{workers.Add(1);go func(){defer workers.Done();for s:=range jobs{r.fetch(s)}}()};workers.Wait()
		delay:=5*time.Second
		r.mu.Lock();for _,s:=range r.sessions{s.mu.Lock();delay=min(delay,time.Until(s.next));s.mu.Unlock()};r.mu.Unlock()
		timer.Reset(max(200*time.Millisecond,delay))
	}}
}
func(r *dmRuntime)updateSessions(){
			inbox,_:=community.KeyID(r.key.Public().(ed25519.PublicKey))
			holders,ranked:=r.discover(r.ctx,inbox)
			seen:=make(map[string]bool)
			for _,target:=range append(holders,ranked...){
				id:=string(target.key);if seen[id]{continue};seen[id]=true
				lease,err:=r.pool.acquire(r.ctx,target.key,target.address,time.Now());if err!=nil{continue}
				r.mu.Lock();s:=r.sessions[id]
				if s==nil||s.lease!=lease{
					if s!=nil{s.lease.SubscribeInboxPush(nil)}
					if len(r.sessions)>=maxRelayPeers&&s==nil{for key,old:=range r.sessions{old.lease.SubscribeInboxPush(nil);delete(r.sessions,key);break}}
					s=&dmInboxSession{target:target,lease:lease};r.sessions[id]=s
					lease.SubscribeInboxPush(func(message community.InboxPushV1)error{
						s.mu.Lock();now:=time.Now().Unix();eligible:=s.fetching&&now<s.expire||s.subscribed&&now<s.subscriptionUntil;s.mu.Unlock()
						if eligible{select{case r.incoming<-dmPush{s,message}:case <-r.ctx.Done():default:}}
						return nil
					})
				}
				r.mu.Unlock()
			}

 select{case r.wake<-struct{}{}:default:}
}
func(r *dmRuntime)take(ctx context.Context)bool{select{case r.requests<-struct{}{}:return true;case <-ctx.Done():return false}}
func(r *dmRuntime)release(){<-r.requests}

func(r *dmRuntime)fetch(s *dmInboxSession){
	if !r.take(r.ctx){return};defer r.release()
	s.mu.Lock();s.next=time.Now().Add(20*time.Second);s.mu.Unlock()
	if !relayLeaseLive(s.lease){return}
	ctx,cancel:=context.WithTimeout(r.ctx,10*time.Second);defer cancel()
	inbox,_:=community.KeyID(r.key.Public().(ed25519.PublicKey))
	var challenge community.InboxChallengeV1
	var response any
	if err:=s.lease.Query(ctx,community.GetInboxChallengeV1{InboxID:inbox},&response);err!=nil{r.failed(s.target.key,err);return}
	switch value:=response.(type){case community.InboxChallengeV1:challenge=value;case community.InboxChallengeRejectedV1:r.pool.rejected(s.target.key,value.Code,time.Now());return;default:r.failed(s.target.key,roomnet.ErrMalformedAnswer);return}
	if len(challenge.Nonce)!=32||challenge.ExpireAt<=time.Now().Unix(){r.failed(s.target.key,roomnet.ErrMalformedAnswer);return}
	auth,err:=community.SignInboxAuthV1(r.key,community.InboxAuthV1ToSign{RelayKey:s.lease.PublicKey(),InboxID:inbox,Nonce:challenge.Nonce,ExpireAt:challenge.ExpireAt})
	if err!=nil{return}
	r.pool.observe(s.target.key,relaySuccess,time.Now())
	s.mu.Lock();oldExpiry:=s.expire;s.auth,s.expire=auth,challenge.ExpireAt;s.mu.Unlock()
	if !r.ack(ctx,s){return}
	cursor,err:=r.client.store.inboxCursor(ctx,r.key.Public().(ed25519.PublicKey),s.target.key);if err!=nil{return}
	for ctx.Err()==nil {
		s.mu.Lock();s.fetching=true;s.mu.Unlock()
		response=nil
		err:=s.lease.Query(ctx,community.GetInboxV1{Auth:auth,After:cursor,Limit:100},&response)
		if err!=nil{s.mu.Lock();s.fetching=false;s.mu.Unlock();r.failed(s.target.key,err);return}
		page,ok:=response.(community.InboxPageV1)
		if !ok{s.mu.Lock();s.fetching=false;s.mu.Unlock();if refusal,ok:=response.(community.InboxPageRejectedV1);ok{r.pool.rejected(s.target.key,refusal.Code,time.Now())}else{r.failed(s.target.key,roomnet.ErrMalformedAnswer)};return}
		result,err:=r.client.store.receiveInboxPage(ctx,r.key,s.target.key,cursor,page,time.Now())
		s.mu.Lock();s.fetching=false;if err==nil&&!page.HasMore{s.subscribed=true;s.subscriptionUntil=challenge.ExpireAt};s.mu.Unlock()
		if err!=nil{if errors.Is(err,roomnet.ErrMalformedAnswer){r.failed(s.target.key,err)};return}
		r.pool.observe(s.target.key,relaySuccess,time.Now())
		r.deliver(r.ctx,result)
		r.ack(ctx,s)
		cursor=max(cursor,page.LastSeqno)
		if !page.HasMore{
			remaining:=time.Until(time.Unix(challenge.ExpireAt,0));renew:=time.Now().Add(remaining*2/3)
			if challenge.ExpireAt<=oldExpiry{renew=time.Unix(challenge.ExpireAt,0).Add(200*time.Millisecond)}
			s.mu.Lock();s.next=renew;s.mu.Unlock();return
		}
	}
}
func(r *dmRuntime)ack(ctx context.Context,s *dmInboxSession)bool{
	for ctx.Err()==nil{
		ids,err:=r.client.store.pendingInboxAcks(ctx,r.key.Public().(ed25519.PublicKey),s.target.key);if err!=nil{return false};if len(ids)==0{return true}
		s.mu.Lock();auth:=s.auth;s.mu.Unlock();var response any
		if err:=s.lease.Query(ctx,community.InboxAckV1{Auth:auth,IDs:ids},&response);err!=nil{r.failed(s.target.key,err);return false}
		if ack,ok:=response.(community.InboxAckedV1);!ok{if refusal,ok:=response.(community.InboxAckRejectedV1);ok{r.pool.rejected(s.target.key,refusal.Code,time.Now())}else{r.failed(s.target.key,roomnet.ErrMalformedAnswer)};return false}else if ack.Deleted<0||int(ack.Deleted)>len(ids){r.failed(s.target.key,roomnet.ErrMalformedAnswer);return false}
		if err:=r.client.store.completeInboxAcks(ctx,r.key.Public().(ed25519.PublicKey),s.target.key,ids);err!=nil{return false}
		r.pool.observe(s.target.key,relaySuccess,time.Now())
	}
	return false
}
func(r *dmRuntime)processPush(push dmPush){
	if !relayLeaseLive(push.session.lease){return}
	ctx,cancel:=context.WithTimeout(r.ctx,5*time.Second);defer cancel()
	result,err:=r.client.store.receiveInboxPush(ctx,r.key,push.session.target.key,push.message,time.Now());if err!=nil{return}
	r.deliver(r.ctx,result);if r.take(ctx){r.ack(ctx,push.session);r.release()}
}
func(r *dmRuntime)deliver(ctx context.Context,result inboxReceiveResult){
	for _,decision:=range result.decisions{
		if decision.disposition!=inboxAccepted||decision.message==nil{continue}
		m:=decision.message
		view:=map[string]any{"id":keyText(m.id),"peer_key":keyText(m.fromKey),"text":m.text,"timestamp":m.createdAt,"direction":"received","author_name":m.authorName}
		if m.claimedDomain!=""{query,cancel:=context.WithTimeout(ctx,5*time.Second);resolved,err:=r.client.resolveIdentity(query,m.claimedDomain);cancel();if err==nil&&bytes.Equal(resolved,m.fromKey){view["domain"]=m.claimedDomain}}
		r.client.mu.RLock()
		if !r.client.closed&&r.client.identityEpoch==r.epoch{r.client.notify(ctx,"dm.message",view)}
		r.client.mu.RUnlock()
	}
}

var ErrDMUnavailable=errors.New("no reachable DM relay")
func dmProtocolError(err error)error{return fmt.Errorf("%w: DM: %w",ErrProtocol,err)}
