package msc3861

import (
	"github.com/element-hq/dendrite/setup"
)

func Enable(m *setup.Monolith) error {
	userVerifier, err := newMSC3861UserVerifier(
		m.UserAPI, m.Config.Global.ServerName,
		m.Config.MSCs.MSC3861, !m.Config.ClientAPI.GuestsDisabled,
	)
	if err != nil {
		return err
	}
	m.UserVerifierProvider.UserVerifier = userVerifier
	return nil
}
