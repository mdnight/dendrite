package slidingsync

import (
	"context"
	"time"

	"github.com/element-hq/dendrite/syncapi/slidingsync/pubsub"
	"github.com/element-hq/dendrite/syncapi/slidingsync/state"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync2"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync2/handler2"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync3/handler"
	"github.com/element-hq/dendrite/syncapi/storage/shared"
	"github.com/element-hq/dendrite/syncapi/sync"
	"github.com/matrix-org/util"
)

var logger = util.GetLogger(context.Background())

type Opts struct {
	AddPrometheusMetrics bool
	// The max number of events the client is eligible to read (unfiltered) which we are willing to
	// buffer on this connection. Too large and we consume lots of memory. Too small and busy accounts
	// will trip the connection knifing. Customisable as tests might want to test filling the buffer.
	MaxPendingEventUpdates int
	// if true, publishing messages will block until the consumer has consumed it.
	// Assumes a single producer and a single consumer.
	TestingSynchronousPubsub bool
	// MaxTransactionIDDelay is the longest amount of time that we will wait for
	// confirmation of an event's transaction_id before sending it to its sender.
	// Set to 0 to disable this delay mechanism entirely.
	MaxTransactionIDDelay time.Duration

	// HTTPTimeout is used for "normal" HTTP requests
	HTTPTimeout time.Duration
	// HTTPLongTimeout is used for initial sync requests
	HTTPLongTimeout time.Duration
}

// Setup the proxy
func Setup(db *shared.Database, rp *sync.RequestPool, opts Opts) (*handler2.Handler, *handler.SyncLiveHandler) {
	store := state.NewStorageWithDB(db, opts.AddPrometheusMetrics)

	bufferSize := 50
	deviceDataUpdateFrequency := time.Second
	if opts.TestingSynchronousPubsub {
		bufferSize = 0
		deviceDataUpdateFrequency = 0 // don't batch
	}
	if opts.MaxPendingEventUpdates == 0 {
		opts.MaxPendingEventUpdates = 2000
	}
	pubSub := pubsub.NewPubSub(bufferSize)

	v2Client := sync2.NewPseudoClient(rp)
	pMap := sync2.NewPollerMap(v2Client, opts.AddPrometheusMetrics)
	// create v2 handler
	h2, err := handler2.NewHandler(pMap, store, pubSub, pubSub, opts.AddPrometheusMetrics, deviceDataUpdateFrequency)
	if err != nil {
		panic(err)
	}
	pMap.SetCallbacks(h2)

	// create v3 handler
	h3, err := handler.NewSync3Handler(store, pubSub, pubSub, opts.AddPrometheusMetrics, opts.MaxPendingEventUpdates, opts.MaxTransactionIDDelay)
	if err != nil {
		panic(err)
	}
	storeSnapshot, err := store.GlobalSnapshot(context.Background())
	if err != nil {
		panic(err)
	}
	logger.Info("retrieved global snapshot from database")
	h3.Startup(&storeSnapshot)

	// begin consuming from these positions
	h2.Listen()
	h3.Listen()
	return h2, h3
}
