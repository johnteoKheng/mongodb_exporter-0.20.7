module github.com/johnteoKheng/mongodb_exporter

go 1.15

// Update percona-toolkit with `go get -v github.com/percona/percona-toolkit@3.0; go mod tidy` (without `-u`)
// until we have everything we need in a tagged release.

require (
	github.com/AlekSi/pointer
	github.com/alecthomas/kong
	github.com/percona/exporter_shared
	github.com/percona/percona-toolkit
	github.com/pkg/errors
	github.com/prometheus/client_golang
	github.com/prometheus/client_model
	github.com/prometheus/common
	github.com/sirupsen/logrus
	github.com/stretchr/testify
	go.mongodb.org/mongo-driver
)
