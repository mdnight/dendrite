// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package msc3861

import (
	"github.com/element-hq/dendrite/setup"
	"github.com/matrix-org/gomatrixserverlib/fclient"
)

func Enable(m *setup.Monolith) error {
	client := fclient.NewClient()
	userVerifier, err := newMSC3861UserVerifier(
		m.UserAPI, m.Config.Global.ServerName,
		m.Config.MSCs.MSC3861, !m.Config.ClientAPI.GuestsDisabled,
		client,
	)
	if err != nil {
		return err
	}
	m.UserVerifierProvider = setup.NewUserVerifierProvider(userVerifier)
	return nil
}
