package node

import (
	"context"
	"log"
	"time"
)

func (n *Node) paymentMaintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := n.payments.Maintain(pctx)
			cancel()
			if err != nil && ctx.Err() == nil { log.Printf("payment maintenance: %v", err) }
		}
	}
}
