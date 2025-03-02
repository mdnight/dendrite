module github.com/element-hq/dendrite

require (
	github.com/Arceliar/phony v0.0.0-20220903101357-530938a4b13d
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/MFAshby/stdemuxerhook v1.0.0
	github.com/Masterminds/semver/v3 v3.3.1
	github.com/blevesearch/bleve/v2 v2.4.4
	github.com/codeclysm/extract v2.2.0+incompatible
	github.com/coder/websocket v1.8.12
	github.com/cretz/bine v0.2.0
	github.com/dgraph-io/ristretto v0.2.0
	github.com/docker/docker v26.1.5+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/eyedeekay/goSam v0.32.54
	github.com/eyedeekay/onramp v0.33.8
	github.com/getsentry/sentry-go v0.14.0
	github.com/gologme/log v1.3.0
	github.com/google/go-cmp v0.6.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.5.3
	github.com/kardianos/minwinsvc v1.0.2
	github.com/lib/pq v1.10.9
	github.com/matrix-org/dugong v0.0.0-20210921133753-66e6b1c67e2e
	github.com/matrix-org/go-sqlite3-js v0.0.0-20220419092513-28aa791a1c91
	github.com/matrix-org/gomatrix v0.0.0-20220926102614-ceba4d9f7530
	github.com/matrix-org/gomatrixserverlib v0.0.0-20250116181547-c4f1e01eab0d
	github.com/matrix-org/pinecone v0.11.1-0.20230810010612-ea4c33717fd7
	github.com/matrix-org/util v0.0.0-20221111132719-399730281e66
	github.com/mattn/go-sqlite3 v1.14.24
	github.com/nats-io/nats-server/v2 v2.10.26
	github.com/nats-io/nats.go v1.39.1
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646
	github.com/opentracing/opentracing-go v1.2.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.20.5
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.10.0
	github.com/tidwall/gjson v1.18.0
	github.com/tidwall/sjson v1.2.5
	github.com/uber/jaeger-client-go v2.30.0+incompatible
	github.com/uber/jaeger-lib v2.4.1+incompatible
	github.com/yggdrasil-network/yggdrasil-go v0.5.12
	github.com/yggdrasil-network/yggquic v0.0.0-20241212194307-0d495106021f
	go.uber.org/atomic v1.11.0
	golang.org/x/crypto v0.35.0
	golang.org/x/exp v0.0.0-20250228200357-dead58393ab7
	golang.org/x/image v0.24.0
	golang.org/x/mobile v0.0.0-20240520174638-fa72addaaa1b
	golang.org/x/sync v0.11.0
	golang.org/x/term v0.29.0
	gopkg.in/yaml.v2 v2.4.0
	gotest.tools/v3 v3.5.2
	maunium.net/go/mautrix v0.23.1
	modernc.org/sqlite v1.34.5
)

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/Arceliar/ironwood v0.0.0-20241213013129-743fe2fccbd3 // indirect
	github.com/HdrHistogram/hdrhistogram-go v1.1.2 // indirect
	github.com/Microsoft/go-winio v0.5.2 // indirect
	github.com/RoaringBitmap/roaring v1.9.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.13.0 // indirect
	github.com/bits-and-blooms/bloom/v3 v3.7.0 // indirect
	github.com/blevesearch/bleve_index_api v1.1.12 // indirect
	github.com/blevesearch/geo v0.1.20 // indirect
	github.com/blevesearch/go-faiss v1.0.24 // indirect
	github.com/blevesearch/go-porterstemmer v1.0.3 // indirect
	github.com/blevesearch/gtreap v0.1.1 // indirect
	github.com/blevesearch/mmap-go v1.0.4 // indirect
	github.com/blevesearch/scorch_segment_api/v2 v2.2.16 // indirect
	github.com/blevesearch/segment v0.9.1 // indirect
	github.com/blevesearch/snowballstem v0.9.0 // indirect
	github.com/blevesearch/upsidedown_store_api v1.0.2 // indirect
	github.com/blevesearch/vellum v1.0.10 // indirect
	github.com/blevesearch/zapx/v11 v11.3.10 // indirect
	github.com/blevesearch/zapx/v12 v12.3.10 // indirect
	github.com/blevesearch/zapx/v13 v13.3.10 // indirect
	github.com/blevesearch/zapx/v14 v14.3.10 // indirect
	github.com/blevesearch/zapx/v15 v15.3.16 // indirect
	github.com/blevesearch/zapx/v16 v16.1.9-0.20241217210638-a0519e7caf3b // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/eyedeekay/i2pkeys v0.33.8 // indirect
	github.com/eyedeekay/sam3 v0.33.8 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/geo v0.0.0-20210211234256-740aa86cb551 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/pprof v0.0.0-20240409012703-83162a5b38cd // indirect
	github.com/h2non/filetype v1.1.3 // indirect
	github.com/hjson/hjson-go/v4 v4.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/juju/errors v1.0.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/highwayhash v1.0.3 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/mschoch/smat v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/nats-io/jwt/v2 v2.7.3 // indirect
	github.com/nats-io/nkeys v0.4.10 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/onsi/ginkgo/v2 v2.11.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.3-0.20211202183452-c5a74bcca799 // indirect
	github.com/petermattis/goid v0.0.0-20250211185408-f2b9d978cd7a // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/quic-go/quic-go v0.48.2 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	go.etcd.io/bbolt v1.3.7 // indirect
	go.mau.fi/util v0.8.5 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.53.0 // indirect
	go.opentelemetry.io/otel v1.32.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.32.0 // indirect
	go.opentelemetry.io/otel/metric v1.32.0 // indirect
	go.opentelemetry.io/otel/sdk v1.32.0 // indirect
	go.opentelemetry.io/otel/trace v1.32.0 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/mod v0.23.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	golang.org/x/time v0.10.0 // indirect
	golang.org/x/tools v0.30.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/macaroon.v2 v2.1.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	nhooyr.io/websocket v1.8.7 // indirect
)

go 1.24.0
