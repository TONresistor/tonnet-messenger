package cli

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/TONresistor/tonnet-messenger/internal/node"
	"github.com/TONresistor/tonnet-messenger/internal/roomstate"
)

func newRelayCmd() *cobra.Command {
 var stateDir,listen,advertise,cfgURL string
 var maxLeaves int
 var localOnly bool
 var dmFlags dmOptions
 cmd:=&cobra.Command{Use:"relay",Short:"Run the free DM relay service without serving rooms",Args:cobra.NoArgs,RunE:func(cmd *cobra.Command,_ []string)error{
  dm,err:=dmFlags.config();if err!=nil{return err}
  state,err:=roomstate.OpenNode(cmd.Context(),stateDir);if err!=nil{return err}
  defer state.Close()
	 payer,err:=dmFlags.startPayments(cmd.Context(),dm);if err!=nil{return err};if payer!=nil{defer payer.Close()}
  advertised:=""
  if !localOnly{advertised,err=resolveAdvertise(cmd.Context(),advertise,listen);if err!=nil{return fmt.Errorf("TON QUIC advertise address: %w",err)}}
  runtime,err:=node.New(node.Config{Key:state.NodePrivate,Listen:listen,Advertise:advertised,ConfigURL:cfgURL,Socket:state.Paths.Socket,MaxLeaves:maxLeaves,Store:state.Store,DM:dm,LocalOnly:localOnly})
  if err!=nil{return err}
  defer runtime.Close()
  printServeBanner(cmd.OutOrStdout(),runtime.ADNLID(),state,listen,advertised)
  fmt.Fprintln(cmd.OutOrStdout(),"DM relay enabled")
  ctx,stop:=signal.NotifyContext(cmd.Context(),syscall.SIGINT,syscall.SIGTERM);defer stop()
  if err:=runtime.Run(ctx);err!=nil&&err!=context.Canceled{return err}
  return nil
 }}
 cmd.Flags().StringVar(&stateDir,"state","","shared node state directory")
 cmd.Flags().StringVar(&listen,"listen","0.0.0.0:17400","TON QUIC UDP bind address ip:port")
 cmd.Flags().StringVar(&advertise,"advertise","","public TON QUIC ip:port to publish (default: autodetect)")
 cmd.Flags().StringVar(&cfgURL,"config",defaultConfigURL,"TON global config url")
 cmd.Flags().IntVar(&maxLeaves,"max-leaves",node.DefaultMaxLeaves,"maximum connected member leaves (1..2048)")
 cmd.Flags().BoolVar(&localOnly,"local",false,"run without DHT publication for direct local testing")
 addDMFlags(cmd,&dmFlags)
 _=cmd.MarkFlagRequired("state")
 return cmd
}
