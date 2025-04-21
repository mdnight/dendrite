package extensions

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/element-hq/dendrite/syncapi/slidingsync/state"
	"github.com/element-hq/dendrite/syncapi/slidingsync/sync3/caches"
	"github.com/element-hq/dendrite/syncapi/types"
)

// Test that aggregation works, which is hard to assert in integration tests
func TestLiveReceiptsAggregation(t *testing.T) {
	boolTrue := true
	ext := &ReceiptsRequest{
		Core: Core{
			Enabled: &boolTrue,
			Lists:   []string{"*"},
			Rooms:   []string{"*"},
		},
	}
	var res Response
	extCtx := Context{
		AllSubscribedRooms: []string{roomA, roomB},
	}
	receiptA1 := &caches.ReceiptUpdate{
		Receipt: types.SlidingSyncReceipt{
			RoomID:  roomA,
			EventID: "$aaa",
			UserID:  "@someone:here",
			TS:      12345,
		},
		RoomUpdate: &dummyRoomUpdate{
			roomID: roomA,
		},
	}
	receiptB1 := &caches.ReceiptUpdate{
		Receipt: types.SlidingSyncReceipt{
			RoomID:  roomB,
			EventID: "$bbb",
			UserID:  "@someone:here",
			TS:      45678,
		},
		RoomUpdate: &dummyRoomUpdate{
			roomID: roomB,
		},
	}
	receiptA2 := &caches.ReceiptUpdate{ // this should aggregate with receiptA1 - not replace it.
		Receipt: types.SlidingSyncReceipt{
			RoomID:  roomA,
			EventID: "$aaa",
			UserID:  "@someone2:here",
			TS:      45678,
		},
		RoomUpdate: &dummyRoomUpdate{
			roomID: roomA,
		},
	}
	// tests that the receipt response is made
	ext.AppendLive(ctx, &res, extCtx, receiptA1)
	// test that aggregations work in different rooms
	ext.AppendLive(ctx, &res, extCtx, receiptB1)
	// test that aggregation work in the same room (aggregate not replace)
	ext.AppendLive(ctx, &res, extCtx, receiptA2)
	if res.Receipts == nil {
		t.Fatalf("receipts response is empty")
	}
	eduA, err := state.PackReceiptsIntoEDU([]types.SlidingSyncReceipt{receiptA1.Receipt, receiptA2.Receipt})
	assertNoError(t, err)
	eduB, err := state.PackReceiptsIntoEDU([]types.SlidingSyncReceipt{receiptB1.Receipt})
	assertNoError(t, err)
	want := map[string]json.RawMessage{
		roomA: eduA,
		roomB: eduB,
	}
	if !reflect.DeepEqual(res.Receipts.Rooms, want) {
		t.Fatalf("got  %+v\nwant %+v", res.Receipts.Rooms, want)
	}
}
