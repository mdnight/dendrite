// Copyright 2024 New Vector Ltd.
// Copyright 2021 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package routing

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/element-hq/dendrite/clientapi/auth"
	"github.com/element-hq/dendrite/clientapi/auth/authtypes"
	"github.com/element-hq/dendrite/clientapi/httputil"
	"github.com/element-hq/dendrite/setup/config"
	"github.com/element-hq/dendrite/userapi/api"
	"github.com/matrix-org/gomatrixserverlib/fclient"
	"github.com/matrix-org/gomatrixserverlib/spec"
	"github.com/matrix-org/util"
)

const CrossSigningResetStage = "org.matrix.cross_signing_reset"

type crossSigningRequest struct {
	api.PerformUploadDeviceKeysRequest
	Auth newPasswordAuth `json:"auth"`
}

func UploadCrossSigningDeviceKeys(
	req *http.Request, userInteractiveAuth *auth.UserInteractive,
	keyserverAPI api.ClientKeyAPI, device *api.Device,
	accountAPI api.ClientUserAPI, cfg *config.ClientAPI,
) util.JSONResponse {
	uploadReq := &crossSigningRequest{}
	uploadRes := &api.PerformUploadDeviceKeysResponse{}

	resErr := httputil.UnmarshalJSONRequest(req, &uploadReq)
	if resErr != nil {
		return *resErr
	}
	sessionID := uploadReq.Auth.Session
	if sessionID == "" {
		sessionID = util.RandomString(sessionIDLength)
	}

	isCrossSigningSetup := false
	masterKeyUpdatableWithoutUIA := false
	{
		var keysResp api.QueryMasterKeysResponse
		keyserverAPI.QueryMasterKeys(req.Context(), &api.QueryMasterKeysRequest{UserID: device.UserID}, &keysResp)
		if err := keysResp.Error; err != nil {
			return convertKeyError(err)
		}
		if k := keysResp.Key; k != nil {
			isCrossSigningSetup = true
			if k.UpdatableWithoutUIABeforeMs != nil {
				masterKeyUpdatableWithoutUIA = time.Now().UnixMilli() < *k.UpdatableWithoutUIABeforeMs
			}
		}
	}

	{
		var keysResp api.QueryKeysResponse
		keyserverAPI.QueryKeys(req.Context(), &api.QueryKeysRequest{UserID: device.UserID, UserToDevices: map[string][]string{device.UserID: []string{}}}, &keysResp)
		if err := keysResp.Error; err != nil {
			return convertKeyError(err)
		}
		hasDifferentKeys := func(userID string, uploadReqCSKey *fclient.CrossSigningKey, dbCSKeys map[string]fclient.CrossSigningKey) bool {
			dbCSKey, ok := dbCSKeys[userID]
			if !ok {
				return true
			}
			dbKeysExist := len(dbCSKey.Keys) > 0
			for keyID, key := range uploadReqCSKey.Keys {
				// If dbKeysExist is false and we enter the loop, it means we have received at least one key that is not in the DB, and we want to persist it.
				if !dbKeysExist {
					return true
				}
				dbKey, ok := dbCSKey.Keys[keyID]
				if !ok || !slices.Equal(dbKey, key) {
					return true
				}
			}
			return false
		}

		if !hasDifferentKeys(device.UserID, &uploadReq.MasterKey, keysResp.MasterKeys) &&
			!hasDifferentKeys(device.UserID, &uploadReq.SelfSigningKey, keysResp.SelfSigningKeys) &&
			!hasDifferentKeys(device.UserID, &uploadReq.UserSigningKey, keysResp.UserSigningKeys) {
			return util.JSONResponse{
				Code: http.StatusOK,
				JSON: map[int]interface{}{},
			}
		}
	}

	if isCrossSigningSetup {
		// With MSC3861, UIA is not possible. Instead, the auth service has to explicitly mark the master key as replaceable.
		if cfg.MSCs.MSC3861Enabled() {
			if !masterKeyUpdatableWithoutUIA {
				url := ""
				if m := cfg.MSCs.MSC3861; m.AccountManagementURL != "" {
					url = strings.Join([]string{m.AccountManagementURL, "?action=", CrossSigningResetStage}, "")
				} else {
					url = m.Issuer
				}
				return util.JSONResponse{
					Code: http.StatusUnauthorized,
					JSON: newUserInteractiveResponse(
						"dummy",
						[]authtypes.Flow{
							{
								Stages: []authtypes.LoginType{CrossSigningResetStage},
							},
						},
						map[string]interface{}{
							CrossSigningResetStage: map[string]string{
								"url": url,
							},
						},
						strings.Join([]string{
							"To reset your end-to-end encryption cross-signing identity, you first need to approve it at",
							url,
							"and then try again.",
						}, " "),
					),
				}
			}
			// XXX: is it necessary?
			sessions.addCompletedSessionStage(sessionID, CrossSigningResetStage)
		} else {
			if uploadReq.Auth.Type != authtypes.LoginTypePassword {
				return util.JSONResponse{
					Code: http.StatusUnauthorized,
					JSON: newUserInteractiveResponse(
						sessionID,
						[]authtypes.Flow{
							{
								Stages: []authtypes.LoginType{authtypes.LoginTypePassword},
							},
						},
						nil,
						"",
					),
				}
			}
			typePassword := auth.LoginTypePassword{
				GetAccountByPassword: accountAPI.QueryAccountByPassword,
				Config:               cfg,
			}
			if _, authErr := typePassword.Login(req.Context(), &uploadReq.Auth.PasswordRequest); authErr != nil {
				return *authErr
			}
			sessions.addCompletedSessionStage(sessionID, authtypes.LoginTypePassword)
		}
	}

	uploadReq.UserID = device.UserID
	keyserverAPI.PerformUploadDeviceKeys(req.Context(), &uploadReq.PerformUploadDeviceKeysRequest, uploadRes)

	if err := uploadRes.Error; err != nil {
		switch {
		case err.IsInvalidSignature:
			return util.JSONResponse{
				Code: http.StatusBadRequest,
				JSON: spec.InvalidSignature(err.Error()),
			}
		case err.IsMissingParam:
			return util.JSONResponse{
				Code: http.StatusBadRequest,
				JSON: spec.MissingParam(err.Error()),
			}
		case err.IsInvalidParam:
			return util.JSONResponse{
				Code: http.StatusBadRequest,
				JSON: spec.InvalidParam(err.Error()),
			}
		default:
			return util.JSONResponse{
				Code: http.StatusBadRequest,
				JSON: spec.Unknown(err.Error()),
			}
		}
	}

	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: struct{}{},
	}
}

func UploadCrossSigningDeviceSignatures(req *http.Request, keyserverAPI api.ClientKeyAPI, device *api.Device) util.JSONResponse {
	uploadReq := &api.PerformUploadDeviceSignaturesRequest{}
	uploadRes := &api.PerformUploadDeviceSignaturesResponse{}

	if err := httputil.UnmarshalJSONRequest(req, &uploadReq.Signatures); err != nil {
		return *err
	}

	uploadReq.UserID = device.UserID
	keyserverAPI.PerformUploadDeviceSignatures(req.Context(), uploadReq, uploadRes)

	if err := uploadRes.Error; err != nil {
		return convertKeyError(err)
	}

	return util.JSONResponse{
		Code: http.StatusOK,
		JSON: struct{}{},
	}
}

func convertKeyError(err *api.KeyError) util.JSONResponse {
	switch {
	case err.IsInvalidSignature:
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: spec.InvalidSignature(err.Error()),
		}
	case err.IsMissingParam:
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: spec.MissingParam(err.Error()),
		}
	case err.IsInvalidParam:
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: spec.InvalidParam(err.Error()),
		}
	default:
		return util.JSONResponse{
			Code: http.StatusBadRequest,
			JSON: spec.Unknown(err.Error()),
		}
	}
}
