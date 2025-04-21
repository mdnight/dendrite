package caches_test

import (
	"os"
	"testing"

	"github.com/element-hq/dendrite/syncapi/slidingsync/testutils"
)

var postgresConnectionString = "user=xxxxx dbname=syncv3_test sslmode=disable"

func TestMain(m *testing.M) {
	postgresConnectionString = testutils.PrepareDBConnectionString()
	exitCode := m.Run()
	os.Exit(exitCode)
}
