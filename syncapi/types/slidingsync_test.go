package types

import "testing"

func TestDeviceDataBitset(t *testing.T) {
	testCases := []struct {
		get         func() SlidingSyncDeviceData
		fallbackSet bool
		otkSet      bool
	}{
		{
			get: func() SlidingSyncDeviceData {
				var dd SlidingSyncDeviceData
				dd.SetFallbackKeysChanged()
				return dd
			},
			fallbackSet: true,
			otkSet:      false,
		},
		{
			get: func() SlidingSyncDeviceData {
				var dd SlidingSyncDeviceData
				dd.SetOTKCountChanged()
				return dd
			},
			fallbackSet: false,
			otkSet:      true,
		},
		{
			get: func() SlidingSyncDeviceData {
				var dd SlidingSyncDeviceData
				dd.SetFallbackKeysChanged()
				dd.SetOTKCountChanged()
				return dd
			},
			fallbackSet: true,
			otkSet:      true,
		},
		{
			get: func() SlidingSyncDeviceData {
				var dd SlidingSyncDeviceData
				return dd
			},
			fallbackSet: false,
			otkSet:      false,
		},
	}
	for _, tc := range testCases {
		dd := tc.get()
		if dd.FallbackKeysChanged() != tc.fallbackSet {
			t.Errorf("%v : wrong fallback value, want %v", dd, tc.fallbackSet)
		}
		if dd.OTKCountChanged() != tc.otkSet {
			t.Errorf("%v : wrong OTK value, want %v", dd, tc.otkSet)
		}
	}
}
