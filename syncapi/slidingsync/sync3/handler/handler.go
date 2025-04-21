package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
	"github.com/sirupsen/logrus"

	"github.com/element-hq/dendrite/syncapi/slidingsync/internal"
	"github.com/element-hq/dendrite/syncapi/slidingsync/pubsub"
	"github.com/element-hq/dendrite/syncapi/slidingsync/state"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync2"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync3"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync3/caches"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync3/extensions"
	"github.com/element-hq/dendrite/syncapi/types"
	userapi "github.com/element-hq/dendrite/userapi/api"
	"github.com/prometheus/client_golang/prometheus"
)

const DefaultSessionID = "default"

var logger = util.GetLogger(context.Background())

// This is a net.http Handler for sync v3. It is responsible for pairing requests to Conns and to
// ensure that the sync v2 poller is running for this client.
type SyncLiveHandler struct {
	Storage      *state.Storage
	ConnMap      *sync3.ConnMap
	EnsurePoller *EnsurePoller
	Extensions   *extensions.Handler
	V2Sub        *pubsub.V2Sub

	// inserts are done by v2 poll loops, selects are done by v3 request threads
	// but the v3 requests touch non-overlapping keys, which is a good use case for sync.Map
	// > (2) when multiple goroutines read, write, and overwrite entries for disjoint sets of keys.
	userCaches *sync.Map // map[user_id]*UserCache
	Dispatcher *sync3.Dispatcher

	GlobalCache            *caches.GlobalCache
	maxPendingEventUpdates int
	maxTransactionIDDelay  time.Duration

	setupHistVec *prometheus.HistogramVec
	histVec      *prometheus.HistogramVec
	slowReqs     prometheus.Counter
	// destroyedConns is the number of connections that have been destoryed after
	// a room invalidation payload.
	// TODO: could make this a CounterVec labelled by reason, to track expiry due
	//       to update buffer filling, expiry due to inactivity, etc.
	destroyedConns prometheus.Counter
}

func NewSync3Handler(
	store *state.Storage,
	pub pubsub.Notifier, sub pubsub.Listener, enablePrometheus bool, maxPendingEventUpdates int,
	maxTransactionIDDelay time.Duration,
) (*SyncLiveHandler, error) {
	logger.Info("creating handler")
	sh := &SyncLiveHandler{
		Storage:                store,
		ConnMap:                sync3.NewConnMap(enablePrometheus, 30*time.Minute),
		userCaches:             &sync.Map{},
		Dispatcher:             sync3.NewDispatcher(),
		GlobalCache:            caches.NewGlobalCache(store),
		maxPendingEventUpdates: maxPendingEventUpdates,
		maxTransactionIDDelay:  maxTransactionIDDelay,
	}
	sh.Extensions = &extensions.Handler{
		Store:       store,
		E2EEFetcher: sh,
		GlobalCache: sh.GlobalCache,
	}

	if enablePrometheus {
		sh.addPrometheusMetrics()
	}
	// set up pubsub mechanism to start from this point
	sh.EnsurePoller = NewEnsurePoller(pub, enablePrometheus)
	sh.V2Sub = pubsub.NewV2Sub(sub, sh)

	return sh, nil
}

func (h *SyncLiveHandler) Startup(storeSnapshot *state.StartupSnapshot) error {
	if err := h.Dispatcher.Startup(storeSnapshot.AllJoinedMembers); err != nil {
		return fmt.Errorf("failed to load sync3.Dispatcher: %s", err)
	}
	h.Dispatcher.Register(context.Background(), sync3.DispatcherAllUsers, h.GlobalCache)
	if err := h.GlobalCache.Startup(storeSnapshot.GlobalMetadata); err != nil {
		return fmt.Errorf("failed to populate global cache: %s", err)
	}
	return nil
}

// Listen starts all consumers
func (h *SyncLiveHandler) Listen() {
	go func() {
		defer internal.ReportPanicsToSentry()
		err := h.V2Sub.Listen()
		if err != nil {
			logger.WithError(err).Error("Failed to listen for v2 messages")
			sentry.CaptureException(err)
		}
	}()
}

func (h *SyncLiveHandler) addPrometheusMetrics() {
	h.setupHistVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "sliding_sync",
		Subsystem: "api",
		Name:      "setup_duration_secs",
		Help:      "Time taken in seconds after receiving a request before we start calculating a sliding sync response.",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"initial"})
	h.histVec = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "sliding_sync",
		Subsystem: "api",
		Name:      "process_duration_secs",
		Help:      "Time taken in seconds for the sliding sync response to be calculated, excludes long polling",
		Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"initial"})
	h.slowReqs = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "sliding_sync",
		Subsystem: "api",
		Name:      "slow_requests",
		Help:      "Counter of slow (>=50s) requests, initial or otherwise.",
	})
	h.destroyedConns = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "sliding_sync",
		Subsystem: "api",
		Name:      "destroyed_conns",
		Help:      "Counter of conns that were destroyed.",
	})

	prometheus.MustRegister(h.setupHistVec)
	prometheus.MustRegister(h.histVec)
	prometheus.MustRegister(h.slowReqs)
	prometheus.MustRegister(h.destroyedConns)
}

func (h *SyncLiveHandler) OnIncomingSyncRequest(req *http.Request, device *userapi.Device) util.JSONResponse {
	resp, err := h.serve(req, device)
	if err != nil {
		herr, ok := err.(*internal.HandlerError)
		if !ok {
			return util.ErrorResponse(err)
		}
		if herr.ErrCode != string(spec.ErrorUnknownPos) {
			// artificially wait a bit before sending back the error
			// this guards against tightlooping when the client hammers the server with invalid requests,
			// but not for M_UNKNOWN_POS which we expect to send back after expiring a client's connection.
			// We want to recover rapidly in that scenario, hence not sleeping.
			time.Sleep(time.Second)
		}
		return util.JSONResponse{
			Code: herr.StatusCode,
			JSON: spec.Unknown(herr.Unwrap().Error()),
		}
	}
	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: resp,
	}
}

// Entry point for sync v3
func (h *SyncLiveHandler) serve(req *http.Request, device *userapi.Device) (*sync3.Response, error) {
	start := time.Now()
	defer func() {
		dur := time.Since(start)
		if dur > 50*time.Second {
			if h.slowReqs != nil {
				h.slowReqs.Add(1.0)
			}
			internal.DecorateLogger(req.Context(), logger).WithField("duration", dur).Warn("slow request")
		}
	}()
	var requestBody sync3.Request
	if req.ContentLength != 0 {
		defer req.Body.Close()
		if err := json.NewDecoder(req.Body).Decode(&requestBody); err != nil {
			util.GetLogger(req.Context()).WithError(err).Warn("failed to read/decode request body")
			return nil, &internal.HandlerError{
				StatusCode: 400,
				Err:        err,
			}
		}
		if err := requestBody.Validate(); err != nil {
			return nil, &internal.HandlerError{
				StatusCode: 400,
				Err:        err,
			}
		}
	}
	if requestBody.ConnID != "" {
		req = req.WithContext(internal.SetAttributeOnContext(req.Context(), internal.OTLPTagConnID, requestBody.ConnID))
	}
	if requestBody.TxnID != "" {
		req = req.WithContext(internal.SetAttributeOnContext(req.Context(), internal.OTLPTagTxnID, requestBody.TxnID))
	}

	for listKey, l := range requestBody.Lists {
		if l.Ranges != nil && !l.Ranges.Valid() {
			return nil, &internal.HandlerError{
				StatusCode: 400,
				Err:        fmt.Errorf("list[%v] invalid ranges %v", listKey, l.Ranges),
			}
		}
	}

	logErrorOrWarning := func(msg string, herr *internal.HandlerError) {
		if herr.StatusCode >= 500 {
			util.GetLogger(req.Context()).WithError(herr).Error(msg)
		} else {
			util.GetLogger(req.Context()).WithError(herr).Warn(msg)
		}
	}

	cancelCtx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(cancelCtx)
	req, conn, herr := h.setupConnection(req, cancel, &requestBody, req.URL.Query().Get("pos") != "", device.UserID, device.ID)
	if herr != nil {
		logErrorOrWarning("failed to get or create Conn", herr)
		return nil, herr
	}
	// set pos and timeout if specified
	cpos, herr := parseIntFromQuery(req.URL, "pos")
	if herr != nil {
		return nil, herr
	}
	requestBody.SetPos(cpos)
	log := util.GetLogger(req.Context()).WithField("user", conn.UserID).WithField("pos", cpos)

	var timeout int
	if req.URL.Query().Get("timeout") == "" {
		timeout = sync3.DefaultTimeoutMSecs
	} else {
		timeout64, herr := parseIntFromQuery(req.URL, "timeout")
		if herr != nil {
			return nil, herr
		}
		timeout = int(timeout64)
	}

	requestBody.SetTimeoutMSecs(timeout)
	log.WithField("timeout", timeout).Trace("recv")

	resp, herr := conn.OnIncomingRequest(req.Context(), &requestBody, start)
	if herr != nil {
		logErrorOrWarning("failed to OnIncomingRequest", herr)
		return nil, herr
	}
	// for logging
	var numToDeviceEvents int
	if resp.Extensions.ToDevice != nil {
		numToDeviceEvents = len(resp.Extensions.ToDevice.Events)
	}
	var numGlobalAccountData int
	if resp.Extensions.AccountData != nil {
		numGlobalAccountData = len(resp.Extensions.AccountData.Global)
	}
	var numChangedDevices, numLeftDevices int
	if resp.Extensions.E2EE != nil && resp.Extensions.E2EE.DeviceLists != nil {
		numChangedDevices = len(resp.Extensions.E2EE.DeviceLists.Changed)
		numLeftDevices = len(resp.Extensions.E2EE.DeviceLists.Left)
	}
	internal.SetRequestContextResponseInfo(
		req.Context(), cpos, resp.PosInt(), len(resp.Rooms), requestBody.TxnID, numToDeviceEvents, numGlobalAccountData,
		numChangedDevices, numLeftDevices, requestBody.ConnID, len(requestBody.Lists), len(requestBody.RoomSubscriptions), len(requestBody.UnsubscribeRooms),
	)
	return resp, nil
}

// setupConnection associates this request with an existing connection or makes a new connection.
// It also sets a v2 sync poll loop going if one didn't exist already for this user.
// When this function returns, the connection is alive and active.
func (h *SyncLiveHandler) setupConnection(req *http.Request, cancel context.CancelFunc, syncReq *sync3.Request, containsPos bool, userID, deviceID string) (*http.Request, *sync3.Conn, *internal.HandlerError) {
	ctx, task := internal.StartTask(req.Context(), "setupConnection")
	req = req.WithContext(ctx)
	defer task.End()
	var conn *sync3.Conn

	connID := sync3.ConnID{
		UserID:   userID,
		DeviceID: deviceID,
		CID:      syncReq.ConnID,
	}
	// client thinks they have a connection
	if containsPos {
		// Lookup the connection
		conn = h.ConnMap.Conn(connID)
		if conn != nil {
			conn.SetCancelCallback(cancel)
			util.GetLogger(req.Context()).WithField("conn", conn.ConnID.String()).Trace("reusing conn")
			return req, conn, nil
		}
		// conn doesn't exist, we probably nuked it.
		return req, nil, internal.ExpiredSessionError()
	}

	pid := sync2.PollerID{UserID: userID, DeviceID: deviceID}
	h.EnsurePoller.EnsurePolling(req.Context(), pid)

	userCache, err := h.userCache(ctx, userID)
	if err != nil {
		util.GetLogger(req.Context()).WithError(err).Warn("failed to load user cache")
		return req, nil, &internal.HandlerError{
			StatusCode: 500,
			Err:        err,
		}
	}

	// once we have the conn, make sure our metrics are correct
	defer h.ConnMap.UpdateMetrics()

	// Now the v2 side of things are running, we can make a v3 live sync conn
	// NB: this isn't inherently racey (we did the check for an existing conn before EnsurePolling)
	// because we *either* do the existing check *or* make a new conn. It's important for CreateConn
	// to check for an existing connection though, as it's possible for the client to call /sync
	// twice for a new connection.
	conn = h.ConnMap.CreateConn(connID, cancel, func() sync3.ConnHandler {
		return NewConnState(userID, deviceID, userCache, h.GlobalCache, h.Extensions, h.Dispatcher, h.setupHistVec, h.histVec, h.maxPendingEventUpdates, h.maxTransactionIDDelay)
	})
	util.GetLogger(req.Context()).Info("created new connection")
	return req, conn, nil
}

func (h *SyncLiveHandler) CacheForUser(userID string) *caches.UserCache {
	c, ok := h.userCaches.Load(userID)
	if ok {
		return c.(*caches.UserCache)
	}
	return nil
}

// userCache fetches an existing caches.UserCache for this user if one exists. If not,
// it
//   - creates a blank caches.UserCache struct,
//   - fires callbacks on that struct as necessary to populate it with initial state,
//   - stores the struct so it will not be recreated in the future, and
//   - registers the cache with the Dispatcher.
//
// Some extra initialisation takes place in caches.UserCache.OnRegister.
// TODO: the calls to uc.OnBlahBlah etc can be moved into NewUserCache, now that the
//
//	UserCache holds a reference to the storage layer.
func (h *SyncLiveHandler) userCache(ctx context.Context, userID string) (*caches.UserCache, error) {
	// bail if we already have a cache
	c, ok := h.userCaches.Load(userID)
	if ok {
		return c.(*caches.UserCache), nil
	}
	uc := caches.NewUserCache(userID, h.GlobalCache, h.Storage, h, h.Dispatcher)
	// select all non-zero highlight or notif counts and set them, as this is less costly than looping every room/user pair
	err := h.Storage.UnreadTable.SelectAllNonZeroCountsForUser(ctx, nil, userID, func(roomID string, highlightCount, notificationCount int) {
		uc.OnUnreadCounts(context.Background(), roomID, &highlightCount, &notificationCount)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load unread counts: %s", err)
	}
	// select the DM account data event and set DM room status
	directEvent, err := h.Storage.AccountData(ctx, userID, sync2.AccountDataGlobalRoom, []string{"m.direct"})
	if err != nil {
		return nil, fmt.Errorf("failed to load direct message status for rooms: %s", err)
	}
	if len(directEvent) == 1 {
		uc.OnAccountData(context.Background(), []types.SlidingSyncAccountData{directEvent[0]})
	}

	// select the ignored users account data event and set ignored user list
	ignoreEvent, err := h.Storage.AccountData(ctx, userID, sync2.AccountDataGlobalRoom, []string{"m.ignored_user_list"})
	if err != nil {
		return nil, fmt.Errorf("failed to load ignored user list for user %s: %w", userID, err)
	}
	if len(ignoreEvent) == 1 {
		uc.OnAccountData(context.Background(), []types.SlidingSyncAccountData{ignoreEvent[0]})
	}

	// select all room tag account data and set it
	tagEvents, err := h.Storage.RoomAccountDatasWithType(ctx, userID, "m.tag")
	if err != nil {
		return nil, fmt.Errorf("failed to load room tags %s", err)
	}
	if len(tagEvents) > 0 {
		uc.OnAccountData(context.Background(), tagEvents)
	}

	// select outstanding invites
	invites, err := h.Storage.InvitesTable.SelectAllInvitesForUser(ctx, nil, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load outstanding invites for user: %s", err)
	}
	for roomID, inviteState := range invites {
		uc.OnInvite(context.Background(), roomID, inviteState)
	}

	// use LoadOrStore here else we can race as 2 brand new /sync conns can both get to this point
	// at the same time
	actualUC, loaded := h.userCaches.LoadOrStore(userID, uc)
	uc = actualUC.(*caches.UserCache)
	if !loaded { // we actually inserted the cache, so register with the dispatcher.
		if err = h.Dispatcher.Register(context.Background(), userID, uc); err != nil {
			h.Dispatcher.Unregister(userID)
			h.userCaches.Delete(userID)
			return nil, fmt.Errorf("failed to register user cache with dispatcher: %s", err)
		}
	}

	return uc, nil
}

// Implements E2EEFetcher
// DeviceData returns the latest device data for this user. isInitial should be set if this is for
// an initial /sync request.
func (h *SyncLiveHandler) DeviceData(ctx context.Context, userID, deviceID string, isInitial bool) *types.SlidingSyncDeviceData {
	// We have 2 sources of DeviceData:
	// - pubsub updates stored in deviceDataMap
	// - the database itself
	// Most of the time we would like to pull from deviceDataMap and ignore the database entirely,
	// however in most cases we need to do a database hit to atomically swap device lists over. Why?
	//
	// changed|left are much more important and special because:
	//
	// - sync v2 only sends deltas, rather than all of them unlike otk counts and fallback key types
	// - we MUST guarantee that we send this to the client, as missing a user in `changed` can result in us having the wrong
	//   device lists for that user resulting in encryption breaking when the client encrypts for known devices.
	// - we MUST NOT continually send the same device list changes on each subsequent request i.e we need to delete them
	//
	// We accumulate device list deltas on the v2 poller side, upserting into the database and sending pubsub notifs for.
	// The accumulated deltas are stored in DeviceData.DeviceLists.New
	// To guarantee we send this to the client, we need to consider a few failure modes:
	// - The response is lost and the request is retried to this proxy -> ConnMap caches will get it.
	// - The response is lost and the client doesn't retry until the connection expires. They then retry ->
	//   ConnMap cache miss, sends HTTP 400 due to invalid ?pos=
	// - The response is received and the client sends the next request -> do not send deltas.

	// To handle the case where responses are lost, we just need to see if this is an initial request
	// and if so, return a "Read-Only" snapshot of the last sent device list changes. This means we may send
	// duplicate device list changes if the response did in fact get to the client and the next request hit a
	// new proxy, but that's better than losing updates. In this scenario, we do not delete any data.
	// To ensure we delete device list updates over time, we now want to swap what was New to Sent and then
	// send Sent. That means we forget what was originally in Sent and New is empty. We need to read and swap
	// atomically else the v2 poller may insert a new update after the read but before the swap (DELETE on New)
	// To ensure atomicity, we need to do this in a txn.
	// Atomically move New to Sent so New is now empty and what was originally in Sent is forgotten.
	shouldSwap := !isInitial

	dd, err := h.Storage.DeviceDataTable.Select(ctx, nil, userID, deviceID, shouldSwap)
	if err != nil && err != sql.ErrNoRows {
		logger.WithError(err).WithField("user", userID).Error("failed to SelectAndSwap device data")
		internal.GetSentryHubFromContextOrDefault(ctx).CaptureException(err)
		return nil
	}

	return dd
}

// Implements TransactionIDFetcher
func (h *SyncLiveHandler) TransactionIDForEvents(userID string, deviceID string, eventIDs []string) (eventIDToTxnID map[string]string) {
	ctx := context.Background()
	eventIDToTxnID, err := h.Storage.TransactionsTable.Select(ctx, nil, userID, deviceID, eventIDs)
	if err != nil {
		util.GetLogger(ctx).WithError(err).WithField("device", deviceID).Error("failed to select txn IDs for events")
	}
	return
}

func (h *SyncLiveHandler) OnInitialSyncComplete(p *pubsub.V2InitialSyncComplete) {
	h.EnsurePoller.OnInitialSyncComplete(p)
}

// Called from the v2 poller, implements V2DataReceiver
func (h *SyncLiveHandler) Accumulate(p *pubsub.V2Accumulate) {
	ctx, task := internal.StartTask(context.Background(), "Accumulate")
	defer task.End()
	// note: events is sorted in ascending NID order, event if p.EventNIDs isn't.
	events, err := h.Storage.EventNIDs(ctx, p.EventNIDs)
	if err != nil {
		logger.WithError(err).WithField("room", p.RoomID).Error("Accumulate: failed to EventNIDs")
		internal.GetSentryHubFromContextOrDefault(ctx).CaptureException(err)
		return
	}
	if len(events) == 0 {
		return
	}
	internal.Logf(ctx, "room", "%s: %d events", p.RoomID, len(events))
	// we have new events, notify active connections
	for i := range events {
		h.Dispatcher.OnNewEvent(ctx, p.RoomID, events[i], p.EventNIDs[i])
	}
}

// OnTransactionID is called from the v2 poller, implements V2DataReceiver.
func (h *SyncLiveHandler) OnTransactionID(p *pubsub.V2TransactionID) {
	_, task := internal.StartTask(context.Background(), "TransactionID")
	defer task.End()

	// There is some event E for which we now have a transaction ID, or else now know
	// that we will never get a transaction ID. In either case, tell the sender's
	// connections to unblock that event in the transaction ID waiter.
	h.ConnMap.ClearUpdateQueues(p.UserID, p.RoomID, p.NID)
}

// Called from the v2 poller, implements V2DataReceiver
func (h *SyncLiveHandler) Initialise(p *pubsub.V2Initialise) {
	ctx, task := internal.StartTask(context.Background(), "Initialise")
	defer task.End()
	state, err := h.Storage.StateSnapshot(ctx, p.SnapshotNID)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"room": p.RoomID,
			"snap": p.SnapshotNID,
		}).WithError(err).Error("Initialise: failed to get StateSnapshot")
		internal.GetSentryHubFromContextOrDefault(ctx).CaptureException(err)
		return
	}
	// we have new state, notify caches
	h.Dispatcher.OnNewInitialRoomState(ctx, p.RoomID, state)
}

func (h *SyncLiveHandler) OnUnreadCounts(p *pubsub.V2UnreadCounts) {
	ctx, task := internal.StartTask(context.Background(), "OnUnreadCounts")
	defer task.End()
	userCache, ok := h.userCaches.Load(p.UserID)
	if !ok {
		return
	}
	userCache.(*caches.UserCache).OnUnreadCounts(ctx, p.RoomID, p.HighlightCount, p.NotificationCount)
}

// push device data updates on waiting conns (otk counts, device list changes)
func (h *SyncLiveHandler) OnDeviceData(p *pubsub.V2DeviceData) {
	ctx, task := internal.StartTask(context.Background(), "OnDeviceData")
	defer task.End()
	internal.Logf(ctx, "device_data", "%d users to notify", len(p.UserIDToDeviceIDs))
	for userID, deviceIDs := range p.UserIDToDeviceIDs {
		for _, deviceID := range deviceIDs {
			conns := h.ConnMap.Conns(userID, deviceID)
			for _, conn := range conns {
				conn.OnUpdate(ctx, caches.DeviceDataUpdate{})
			}
		}
	}
}

func (h *SyncLiveHandler) OnDeviceMessages(p *pubsub.V2DeviceMessages) {
	ctx, task := internal.StartTask(context.Background(), "OnDeviceMessages")
	defer task.End()
	conns := h.ConnMap.Conns(p.UserID, p.DeviceID)
	for _, conn := range conns {
		conn.OnUpdate(ctx, caches.DeviceEventsUpdate{})
	}

}

func (h *SyncLiveHandler) OnInvite(p *pubsub.V2InviteRoom) {
	ctx, task := internal.StartTask(context.Background(), "OnInvite")
	defer task.End()
	userCache, ok := h.userCaches.Load(p.UserID)
	if !ok {
		return
	}
	inviteState, err := h.Storage.InvitesTable.SelectInviteState(ctx, nil, p.UserID, p.RoomID)
	if err != nil {
		logger.WithError(err).WithField("user", p.UserID).WithField("room", p.RoomID).Error("failed to get invite state")
		internal.GetSentryHubFromContextOrDefault(ctx).CaptureException(err)
		return
	}
	userCache.(*caches.UserCache).OnInvite(ctx, p.RoomID, inviteState)
}

func (h *SyncLiveHandler) OnLeftRoom(p *pubsub.V2LeaveRoom) {
	ctx, task := internal.StartTask(context.Background(), "OnLeftRoom")
	defer task.End()
	userCache, ok := h.userCaches.Load(p.UserID)
	if !ok {
		return
	}
	userCache.(*caches.UserCache).OnLeftRoom(ctx, p.RoomID, p.LeaveEvent)
}

func (h *SyncLiveHandler) OnReceipt(p *pubsub.V2Receipt) {
	ctx, task := internal.StartTask(context.Background(), "OnReceipt")
	defer task.End()
	// split receipts into public / private
	userToPrivateReceipts := make(map[string][]types.SlidingSyncReceipt)
	publicReceipts := make([]types.SlidingSyncReceipt, 0, len(p.Receipts))
	for _, r := range p.Receipts {
		if r.IsPrivate {
			userToPrivateReceipts[r.UserID] = append(userToPrivateReceipts[r.UserID], r)
		} else {
			publicReceipts = append(publicReceipts, r)
		}
	}
	// always send private receipts, directly to the connected user cache if one exists
	for userID, privateReceipts := range userToPrivateReceipts {
		userCache, ok := h.userCaches.Load(userID)
		if !ok {
			continue
		}
		for _, pr := range privateReceipts {
			userCache.(*caches.UserCache).OnReceipt(ctx, pr)
		}
	}
	if len(publicReceipts) == 0 {
		return
	}
	// inform the dispatcher of global receipts
	for _, pr := range publicReceipts {
		h.Dispatcher.OnReceipt(ctx, pr)
	}
}

func (h *SyncLiveHandler) OnTyping(p *pubsub.V2Typing) {
	ctx, task := internal.StartTask(context.Background(), "OnTyping")
	defer task.End()
	rooms := h.GlobalCache.LoadRooms(ctx, p.RoomID)
	if rooms[p.RoomID] != nil {
		if reflect.DeepEqual(p.EphemeralEvent, rooms[p.RoomID].TypingEvent) {
			return // it's a duplicate, which happens when 2+ users are in the same room
		}
	}
	h.Dispatcher.OnEphemeralEvent(ctx, p.RoomID, spec.MTyping, p.EphemeralEvent)
}

func (h *SyncLiveHandler) OnAccountData(p *pubsub.V2AccountData) {
	ctx, task := internal.StartTask(context.Background(), "OnAccountData")
	defer task.End()
	userCache, ok := h.userCaches.Load(p.UserID)
	if !ok {
		return
	}
	data, err := h.Storage.AccountData(ctx, p.UserID, p.RoomID, p.Types)
	if err != nil {
		logger.WithError(err).WithField("user", p.UserID).WithField("room", p.RoomID).Error("OnAccountData: failed to lookup")
		internal.GetSentryHubFromContextOrDefault(ctx).CaptureException(err)
		return
	}
	userCache.(*caches.UserCache).OnAccountData(ctx, data)
}

func (h *SyncLiveHandler) OnExpiredToken(p *pubsub.V2ExpiredToken) {
	//logger.Fatal("OnExpiredToken: not implemented")
}

func (h *SyncLiveHandler) OnStateRedaction(p *pubsub.V2StateRedaction) {
	// We only need to reload the global metadata here: mercifully, there isn't anything
	// in the user cache that needs to be reloaded after state gets redacted.
	ctx, task := internal.StartTask(context.Background(), "OnStateRedaction")
	defer task.End()
	h.GlobalCache.OnInvalidateRoom(ctx, p.RoomID)
}

func (h *SyncLiveHandler) OnInvalidateRoom(p *pubsub.V2InvalidateRoom) {
	ctx, task := internal.StartTask(context.Background(), "OnInvalidateRoom")
	defer task.End()

	// 1. Reload the global cache.
	h.GlobalCache.OnInvalidateRoom(ctx, p.RoomID)

	// Work out who is affected.
	joins, invites, leaves, err := h.Storage.FetchMemberships(ctx, p.RoomID)
	involvedUsers := make([]string, 0, len(joins)+len(invites)+len(leaves))
	involvedUsers = append(involvedUsers, joins...)
	involvedUsers = append(involvedUsers, invites...)
	involvedUsers = append(involvedUsers, leaves...)

	if err != nil {
		hub := internal.GetSentryHubFromContextOrDefault(ctx)
		hub.WithScope(func(scope *sentry.Scope) {
			scope.SetContext(internal.SentryCtxKey, map[string]any{
				"room_id": p.RoomID,
			})
			hub.CaptureException(err)
		})
		logger.WithError(err).
			WithField("room_id", p.RoomID).
			Error("Failed to fetch members after cache invalidation")
		return
	}

	// 2. Reload the joined-room tracker.
	h.Dispatcher.OnInvalidateRoom(p.RoomID, joins, invites)

	// 3. Destroy involved users' caches.
	// We filter to only those users which had a userCache registered to receive updates.
	unregistered := h.Dispatcher.UnregisterBulk(involvedUsers)
	for _, userID := range unregistered {
		h.userCaches.Delete(userID)
	}

	// 4. Destroy involved users' connections.
	// Since creating a conn creates a user cache, it is safe to loop over
	destroyed := h.ConnMap.CloseConnsForUsers(unregistered)
	if h.destroyedConns != nil {
		h.destroyedConns.Add(float64(destroyed))
	}
	// invalidations are rare and dangerous if we get it wrong, so log information about it.
	logger.
		WithField("room_id", p.RoomID).WithField("joins", len(joins)).WithField("invites", len(invites)).WithField("leaves", len(leaves)).
		WithField("del_user_caches", len(unregistered)).WithField("conns_destroyed", destroyed).Info("OnInvalidateRoom")
}

func parseIntFromQuery(u *url.URL, param string) (result int64, err *internal.HandlerError) {
	queryPos := u.Query().Get(param)
	if queryPos != "" {
		var err error
		result, err = strconv.ParseInt(queryPos, 10, 64)
		if err != nil {
			return 0, &internal.HandlerError{
				StatusCode: 400,
				Err:        fmt.Errorf("invalid %s: %s", param, queryPos),
			}
		}
	}
	return
}
