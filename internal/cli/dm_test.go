package cli

import (
	"github.com/spf13/cobra"
	"testing"
)

func TestPaidOperatorFlagsAreExplicitAndValidatedBeforeStartup(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ok   bool
	}{
		{nil, true},
		{[]string{"--dm-paid-offer", "1:7:4096"}, false},
		{[]string{"--tpn-config", "unused.json", "--dm-paid-offer", "1:7:4096"}, true},
		{[]string{"--tpn-config", "unused.json", "--dm-paid-offer", "1:0:4096"}, false},
		{[]string{"--tpn-config", "unused.json", "--dm-paid-offer", "1:7:4096", "--dm-paid-offer", "1:9:8192"}, false},
		{[]string{"--tpn-config", "unused.json", "--tpn-max-channels", "0"}, false},
	} {
		var opts dmOptions
		cmd := &cobra.Command{}
		addDMFlags(cmd, &opts)
		if e := cmd.ParseFlags(tc.args); e != nil {
			t.Fatal(e)
		}
		cfg, e := opts.config()
		if (e == nil) != tc.ok {
			t.Fatalf("%v: %v", tc.args, e)
		}
		if e == nil && cfg.Payments != nil {
			t.Fatal("flag validation started SDK")
		}
	}
}
