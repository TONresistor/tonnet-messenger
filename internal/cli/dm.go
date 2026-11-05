package cli

import (
	"context"
	"fmt"
	"math"
	"time"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/payments"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type dmOptions struct {
	retention,challenge time.Duration
	rate,maxObject int
	quota,messages,bytes int64
	tpnConfig string
	paidOffers []string
	maxChannels int
}

func addDMFlags(cmd *cobra.Command,o *dmOptions){
	f:=cmd.Flags()
	f.DurationVar(&o.retention,"dm-retention",24*time.Hour,"maximum free DM retention from creation")
	f.IntVar(&o.rate,"dm-rate",60,"accepted DM deposits per sender per minute")
	f.Int64Var(&o.quota,"dm-inbox-bytes",1<<20,"maximum stored envelope bytes per recipient")
	f.Int64Var(&o.messages,"dm-max-messages",10000,"maximum live stored DM envelopes")
	f.Int64Var(&o.bytes,"dm-total-bytes",64<<20,"maximum total live stored DM envelope bytes")
	f.IntVar(&o.maxObject,"dm-max-object-bytes",64<<10,"maximum boxed DM deposit bytes (at most 65536)")
	f.DurationVar(&o.challenge,"dm-challenge-ttl",time.Minute,"inbox proof lifetime (integer 1..60 seconds)")
	f.StringVar(&o.tpnConfig,"tpn-config","","existing TPN operator config; enable receiving SDK")
	f.StringArrayVar(&o.paidOffers,"dm-paid-offer",nil,"paid tier:price_nanoton:unit_bytes (repeat; other limits follow DM flags)")
	f.IntVar(&o.maxChannels,"tpn-max-channels",4096,"maximum durable credited/pending receiving channels")
}

func(o dmOptions)config()(*node.DMConfig,error){
	if len(o.paidOffers)!=0&&o.tpnConfig==""{return nil,fmt.Errorf("--dm-paid-offer requires --tpn-config")}
	if o.tpnConfig!=""&&o.maxChannels<=0{return nil,fmt.Errorf("--tpn-max-channels must be positive")}
	if o.retention<time.Second||o.retention%time.Second!=0||o.retention/time.Second>math.MaxInt32||o.rate<1||int64(o.rate)>math.MaxInt32||o.maxObject<1||o.maxObject>64<<10{return nil,fmt.Errorf("invalid finite DM retention, rate or object limit")}
	c:=&node.DMConfig{ChallengeTTL:o.challenge,Limits:store.InboxLimits{
		Offer:&community.RelayOfferV1{Tier:0,Services:community.RelayServiceDM,MaxObjectBytes:int32(o.maxObject),RetentionSeconds:int32(o.retention/time.Second),RequestsPerMinute:int32(o.rate),InboxQuotaBytes:o.quota},
		MaxMessages:o.messages,MaxBytes:o.bytes,
	}}
	if err:=c.Validate();err!=nil{return nil,err}
	if _,err:=o.offers(*c.Limits.Offer);err!=nil{return nil,err}
	return c,nil
}

func(o dmOptions)offers(base community.RelayOfferV1)([]community.RelayOfferV1,error){
	var offers []community.RelayOfferV1;seen:=make(map[int32]bool)
	for _,arg:=range o.paidOffers{
		parts:=strings.Split(arg,":");if len(parts)!=3{return nil,fmt.Errorf("paid offer requires tier:price_nanoton:unit_bytes")}
		tier,e1:=strconv.ParseInt(parts[0],10,32);price,e2:=strconv.ParseInt(parts[1],10,64);unit,e3:=strconv.ParseInt(parts[2],10,64)
		if e1!=nil||e2!=nil||e3!=nil||tier==0||price<=0||unit<=0||seen[int32(tier)]{return nil,fmt.Errorf("invalid or duplicate paid offer")}
		seen[int32(tier)]=true;offer:=base;offer.Tier,offer.PriceNanoton,offer.UnitBytes=int32(tier),price,unit
		if err:=offer.Validate(community.RelayServiceDM|community.RelayServicePaidTiers);err!=nil{return nil,err};offers=append(offers,offer)
	}
	return offers,nil
}

func(o dmOptions)startPayments(ctx context.Context,c *node.DMConfig)(*payments.Runtime,error){
	if o.tpnConfig==""{return nil,nil}
	offers,err:=o.offers(*c.Limits.Offer);if err!=nil{return nil,err}
	runtime,err:=payments.OpenRuntime(ctx,o.tpnConfig,false);if err!=nil{return nil,err}
	backend,err:=runtime.Receiver();if err!=nil{runtime.Close();return nil,err}
	c.Payments=&payments.Config{Backend:backend,Offers:offers,MaxChannels:o.maxChannels}
	if err:=c.Validate();err!=nil{runtime.Close();return nil,err}
	return runtime,nil
}
