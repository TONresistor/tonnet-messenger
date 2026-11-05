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
	"github.com/TONresistor/tonnet-messenger/internal/roomnet"
)

// SendDM uses the current identity, independently of room membership.
func(c *Client)SendDM(ctx context.Context,recipient,text string)(map[string]any,error){
 if err:=community.ValidateDMPlaintext(text);err!=nil{return nil,err}
 to,err:=c.resolveIdentity(ctx,recipient);if err!=nil{return nil,err}
 c.identityOps.Lock();defer c.identityOps.Unlock()
 r,err:=c.ensureDM();if err!=nil{return nil,err}
 work,cancel:=context.WithCancel(ctx);stop:=context.AfterFunc(r.ctx,cancel);defer func(){stop();cancel()}()
 owner:=r.key.Public().(ed25519.PublicKey)
 if bytes.Equal(to,owner){return nil,errors.New("cannot send a direct message to this identity")}
 fingerprint:=dmFingerprint(to,text)
 out,err:=c.store.outgoing(work,owner,fingerprint);if err!=nil{return nil,err}
 if out==nil{
  c.mu.RLock();name,domain:=c.name,c.domain;c.mu.RUnlock()
  box,err:=dm.SealV3(r.key,to,[]byte(text));if err!=nil{return nil,err}
  created:=time.Now().Unix()
  m:=community.DirectMessageV3{FromKey:owner,ToKey:to,AuthorName:name,AuthorDomain:domain,CreatedAt:created,ExpireAt:created+1,Ciphertext:box,Signature:make([]byte,64)}
  encoded,err:=community.Encode(community.InboxDepositV1{Message:m});if err!=nil{return nil,err}
  envelope,err:=community.Encode(m);if err!=nil{return nil,err}
  inbox,_:=community.KeyID(to);holders,ranked:=r.discover(work,inbox)
  targets:=append([]dmCandidate(nil),holders...);if own:=r.ownRelay();own!=nil{targets=append(targets,*own)};targets=append(targets,ranked...)
  out=&outgoingDM{};seen:=make(map[string]bool);retention:=int64(0)
  for _,target:=range targets{
   if len(out.Targets)==5{break};if seen[string(target.key)]{continue};seen[string(target.key)]=true
   if _,err:=r.pool.acquire(work,target.key,target.address,time.Now());err!=nil{continue}
   card,ok:=r.pool.card(target.key);if !ok{continue}
   offer,ok:=selectDMOffer(card,len(encoded),len(envelope),c.tpn!=nil);if !ok{continue}
   out.Targets=append(out.Targets,dmSendTarget{Key:target.key,Address:target.address,PaymentKey:card.PaymentKey,Offer:offer})
   if retention==0||int64(offer.RetentionSeconds)<retention{retention=int64(offer.RetentionSeconds)}
  }
  if len(out.Targets)==0{return nil,ErrDMUnavailable}
  m.CreatedAt=time.Now().Unix();m.ExpireAt=m.CreatedAt+retention;m.Signature=nil
  out.Message,err=community.SignDirectMessageV3(r.key,m);if err!=nil{return nil,err}
  if err:=c.store.saveOutgoing(work,owner,fingerprint,*out);err!=nil{return nil,err}
 }
 m:=out.Message;id,err:=community.HashBoxed(m);if err!=nil{return nil,err};inbox,_:=community.KeyID(to)
 if !bytes.Equal(m.ToKey,to){return nil,ErrProtocol}
 var receipts []string;var firstRejection,firstProtocol error;definitive:=0
 validReceipt:=func(value community.InboxReceiptV1,key []byte)bool{return bytes.Equal(value.RelayKey,key)&&bytes.Equal(value.DMID,id)&&bytes.Equal(value.InboxID,inbox)&&value.ExpireAt==m.ExpireAt&&value.Verify()==nil}
 for _,target:=range out.Targets{
  old,attempted,err:=c.store.depositAttempt(work,owner,id,target.Key);if err!=nil{return nil,err}
  if len(old)!=0{value,err:=community.DecodeInboxReceiptV1(old);if err!=nil||!validReceipt(value,target.Key){return nil,ErrProtocol};receipts=append(receipts,keyText(target.Key));if len(receipts)==3{break};continue}
  if target.Offer.Tier!=0&&c.tpn==nil{if firstRejection==nil{firstRejection=&RejectedError{Code:17,Message:"TPN payer is disabled"}};continue}
  lease,err:=r.pool.acquire(work,target.Key,target.Address,time.Now());if err!=nil{continue}
  request:=community.InboxDepositV1{Message:m,Tier:target.Offer.Tier};raw,err:=community.Encode(request);if err!=nil{return nil,err}
  cost:=int64(len(raw)+176);baseline:=int64(0);fresh:=!attempted
  if fresh&&target.Offer.Tier!=0{
   baseline,err=r.ensurePrepaid(work,lease,target,cost,false)
   if err!=nil{var rejected *RejectedError;if errors.As(err,&rejected){if firstRejection==nil{firstRejection=err}}else if errors.Is(err,ErrProtocol)&&firstProtocol==nil{firstProtocol=err};continue}
  }
  if err:=c.store.beginDeposit(work,owner,id,target);err!=nil{return nil,err}
  var failure error
  for attempt:=0;attempt<2;attempt++{
   query,cancel:=context.WithTimeout(work,5*time.Second);var response any
   err:=lease.Query(query,request,&response);cancel()
   if err!=nil{r.failed(target.Key,err);fresh=false;failure=err;continue}
   switch value:=response.(type){
   case community.InboxRejectedV1:
    r.pool.rejected(target.Key,value.Code,time.Now())
    if value.Code<1||value.Code>19{failure=dmProtocolError(roomnet.ErrMalformedAnswer);break}
    failure=&RejectedError{Code:value.Code,Message:value.Message}
    if value.Code==17&&attempt==0&&target.Offer.Tier!=0&&c.tpn!=nil{
     // A retry first asks for its free duplicate receipt. Only a definitive
     // code 17 leads to authoritative balance recovery and another top-up.
     card,ok:=r.pool.card(target.Key);offered:=false
     if ok&&bytes.Equal(card.PaymentKey,target.PaymentKey){for _,o:=range card.Offers{if o.Tier==target.Offer.Tier&&o.Services==community.RelayServiceDM{target.Offer=o;offered=true;break}}}
     if offered{
      baseline,err=r.ensurePrepaid(work,lease,target,cost,true)
      if err==nil{fresh=false;if err:=c.store.beginDeposit(work,owner,id,target);err!=nil{return nil,err};continue}
      failure=err
     }
    }
    if fresh{definitive++}
   case community.InboxReceiptV1:
    if !validReceipt(value,lease.PublicKey()){r.pool.observe(target.Key,relayMalformedAnswer,time.Now());failure=dmProtocolError(roomnet.ErrMalformedAnswer);break}
    durable,finish:=context.WithTimeout(context.WithoutCancel(work),5*time.Second)
    _=c.store.finishDeposit(durable,owner,id,target,value,fresh,baseline,cost);finish()
    // The pre-send journal already made the balance unknown. A failed local
    // receipt write must not turn a valid relay receipt into a failed send.
    if target.Offer.Tier!=0&&!fresh&&c.tpn!=nil{
     // A duplicate may have been included in a previous reported baseline.
     // Never subtract it again; refresh after its definitive receipt instead.
     if ch,e:=c.store.payerChannel(work,owner,target.Key,target.Offer.Tier);e==nil&&ch!=nil&&len(ch.State)!=0{_,_=r.exchangePayment(work,lease,ch)}
    }
    r.pool.observe(target.Key,relaySuccess,time.Now());receipts=append(receipts,keyText(value.RelayKey));failure=nil
   default:r.pool.observe(target.Key,relayMalformedAnswer,time.Now());failure=dmProtocolError(roomnet.ErrMalformedAnswer)
   }
   break
  }
  if failure!=nil{
   var rejected *RejectedError
   if errors.As(failure,&rejected){if firstRejection==nil{firstRejection=failure}}else if errors.Is(failure,ErrProtocol){if firstProtocol==nil{firstProtocol=failure}}
  }
  if len(receipts)>=3{break}
 }
 if len(receipts)==0{
  if definitive==len(out.Targets){_,_=c.store.db.ExecContext(work,"UPDATE outgoing_dms SET done=1 WHERE identity=? AND fingerprint=?",owner,fingerprint)}
  if firstRejection!=nil{return nil,firstRejection};if firstProtocol!=nil{return nil,firstProtocol};return nil,ErrDMUnavailable
 }
 durable,finish:=context.WithTimeout(context.WithoutCancel(work),5*time.Second)
 _,_=c.store.db.ExecContext(durable,"UPDATE outgoing_dms SET done=1 WHERE identity=? AND fingerprint=?",owner,fingerprint);finish()
 view:=map[string]any{"id":keyText(id),"peer_key":keyText(to),"text":text,"timestamp":m.CreatedAt,"direction":"sent","author_name":m.AuthorName,"status":"stored","receipts":receipts}
 if alias:=strings.ToLower(strings.TrimSpace(recipient));community.IsDomainName(alias){view["domain"]=alias}
 c.notify(c.ctx,"dm.message",view)
 return view,nil
}
