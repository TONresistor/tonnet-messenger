package cli

import (
	"fmt"
	"math"
	"time"

	"github.com/spf13/cobra"
	"github.com/TONresistor/tonnet-messenger/internal/community"
	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/store"
)

type dmOptions struct {
	retention,challenge time.Duration
	rate,maxObject int
	quota,messages,bytes int64
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
}

func(o dmOptions)config()(*node.DMConfig,error){
	if o.retention<time.Second||o.retention%time.Second!=0||o.retention/time.Second>math.MaxInt32||o.rate<1||int64(o.rate)>math.MaxInt32||o.maxObject<1||o.maxObject>64<<10{return nil,fmt.Errorf("invalid finite DM retention, rate or object limit")}
	c:=&node.DMConfig{ChallengeTTL:o.challenge,Limits:store.InboxLimits{
		Offer:&community.RelayOfferV1{Tier:0,Services:community.RelayServiceDM,MaxObjectBytes:int32(o.maxObject),RetentionSeconds:int32(o.retention/time.Second),RequestsPerMinute:int32(o.rate),InboxQuotaBytes:o.quota},
		MaxMessages:o.messages,MaxBytes:o.bytes,
	}}
	if err:=c.Validate();err!=nil{return nil,err}
	return c,nil
}
