// mongodb_exporter
// Copyright (C) 2017 Percona LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package exporter implements the collectors and metrics handlers.
package exporter

import (
	"crypto/subtle"
	"io/ioutil"
	
	"bytes"
	"crypto/tls"
	_ "expvar" // register /debug/vars on http.DefaultServeMux
	"html/template"
	_ "net/http/pprof" // register /debug/pprof http.DefaultServeMux
	"os"
	"strings"
	
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/common/log"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Exporter holds Exporter methods and attributes.
type Exporter struct {
	path             string
	client           *mongo.Client
	logger           *logrus.Logger
	opts             *Opts
	webListenAddress string
	topologyInfo     labelsGetter
}

// Opts holds new exporter options.
type Opts struct {
	CompatibleMode          bool
	DiscoveringMode         bool
	GlobalConnPool          bool
	DirectConnect           bool
	URI                     string
	Path                    string
	WebListenAddress        string
	IndexStatsCollections   []string
	CollStatsCollections    []string
	Logger                  *logrus.Logger
	DisableDiagnosticData   bool
	DisableReplicasetStatus bool
        WebSslCertFile          string
	WebSslKeyFile           string
}

var (
	errCannotHandleType   = fmt.Errorf("don't know how to handle data type")
	errUnexpectedDataType = fmt.Errorf("unexpected data type")

	authFileF = kingpin.Flag("web.auth-file", "Path to YAML file with server_user, server_password keys for HTTP Basic authentication "+
		"(overrides HTTP_AUTH environment variable).").String()
	
        sslCertFileF = kingpin.Flag("web.ssl-cert-file", "Path to SSL certificate file.").String()
	sslKeyFileF  = kingpin.Flag("web.ssl-key-file", "Path to SSL key file.").String()

	landingPage = template.Must(template.New("home").Parse(strings.TrimSpace(`
<html>
<head>
	<title>{{ .name }} exporter</title>
</head>
<body>
	<h1>{{ .name }} exporter</h1>
	<p><a href="{{ .path }}">Metrics</a></p>
</body>
</html>
`)))

)

type basicAuth struct {
	Username string `yaml:"server_user,omitempty"`
	Password string `yaml:"server_password,omitempty"`
}

func DefaultMetricsHandler() http.Handler {
	h := promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
		ErrorLog:      log.NewErrorLogger(),
		ErrorHandling: promhttp.ContinueOnError,
	})
	return promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, h)
}

func readBasicAuth() *basicAuth {
	var auth basicAuth
	httpAuth := os.Getenv("HTTP_AUTH")
	switch {
	case *authFileF != "":
		bytes, err := ioutil.ReadFile(*authFileF)
		if err != nil {
			log.Fatalf("cannot read auth file %q: %s", *authFileF, err)
		}
		if err = yaml.Unmarshal(bytes, &auth); err != nil {
			log.Fatalf("cannot parse auth file %q: %s", *authFileF, err)
		}
	case httpAuth != "":
		data := strings.SplitN(httpAuth, ":", 2)
		if len(data) != 2 || data[0] == "" || data[1] == "" {
			log.Fatalf("HTTP_AUTH should be formatted as user:password")
		}
		auth.Username = data[0]
		auth.Password = data[1]
	default:
		// that's fine, return empty one below
	}

	return &auth
}

// basicAuthHandler checks username and password before invoking provided next handler.
type basicAuthHandler struct {
	basicAuth
	nextHandler http.Handler
}

// ServeHTTP implements http.Handler.
func (h *basicAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	username, password, _ := r.BasicAuth()
	usernameOk := subtle.ConstantTimeCompare([]byte(h.Username), []byte(username)) == 1
	passwordOk := subtle.ConstantTimeCompare([]byte(h.Password), []byte(password)) == 1
	if !usernameOk || !passwordOk {
		w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	h.nextHandler.ServeHTTP(w, r)
}

// authHandler wraps provided handler with basic authentication if it is configured.
func authHandler(handler http.Handler) http.Handler {
	auth := readBasicAuth()
	if auth.Username != "" && auth.Password != "" {
		log.Infoln("HTTP Basic authentication is enabled.")
		return &basicAuthHandler{basicAuth: *auth, nextHandler: handler}
	}

	return handler
}

var (
	_ http.Handler = (*basicAuthHandler)(nil)
)

// RunServer runs server for exporter with given name (it is used on landing page) on given address,
// with HTTP basic authentication (if configured)
// and with given HTTP handler (that should be created with DefaultMetricsHandler or manually).
// Function never returns.
func RunServer(name, addr, path string, handler http.Handler) {
	if (*sslCertFileF == "") != (*sslKeyFileF == "") {
		log.Fatal("One of the flags --web.ssl-cert-file or --web.ssl-key-file is missing to enable HTTPS.")
		*sslCertFileF="/mongodb/certs/cert.pem"
		*sslKeyFileF="/mongodb/certs/key.pem"
	}

	ssl := false
	if *sslCertFileF != "" && *sslKeyFileF != "" {
		if _, err := os.Stat(*sslCertFileF); os.IsNotExist(err) {
			log.Fatalf("SSL certificate file does not exist: %s", *sslCertFileF)
		}
		if _, err := os.Stat(*sslKeyFileF); os.IsNotExist(err) {
			log.Fatalf("SSL key file does not exist: %s", *sslKeyFileF)
		}
		ssl = true
	}

	var buf bytes.Buffer
	data := map[string]string{"name": name, "path": path}
	if err := landingPage.Execute(&buf, data); err != nil {
		log.Fatal(err)
	}

	h := authHandler(handler)
	if ssl {
		runHTTPS(addr, path, h, buf.Bytes())
	} else {
		runHTTP(addr, path, h, buf.Bytes())
	}
}

// TLSConfig returns a new tls.Config instance configured according to Percona's security baseline.
func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
            		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        	},
	}
}

func runHTTPS(addr, path string, handler http.Handler, landing []byte) {
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write(landing)
	})

	srv := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: TLSConfig(),
	}
	log.Infof("Starting HTTPS server for https://%s%s ...", addr, path)
	log.Fatal(srv.ListenAndServeTLS(*sslCertFileF, *sslKeyFileF))
}

func runHTTP(addr, path string, handler http.Handler, landing []byte) {
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(landing)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	log.Infof("Starting HTTP server for http://%s%s ...", addr, path)
	log.Fatal(srv.ListenAndServe())
}



// New connects to the database and returns a new Exporter instance.
func New(opts *Opts) (*Exporter, error) {
	if opts == nil {
		opts = new(Opts)
	}

	if opts.Logger == nil {
		opts.Logger = logrus.New()
	}

	ctx := context.Background()

	exp := &Exporter{
		path:             opts.Path,
		logger:           opts.Logger,
		opts:             opts,
		webListenAddress: opts.WebListenAddress,
	}
	if opts.GlobalConnPool {
		var err error
		exp.client, err = connect(ctx, opts.URI, opts.DirectConnect)
		if err != nil {
			return nil, err
		}

		exp.topologyInfo, err = newTopologyInfo(ctx, exp.client)
		if err != nil {
			return nil, err
		}
	}

	return exp, nil
}

func (e *Exporter) makeRegistry(ctx context.Context, client *mongo.Client, topologyInfo labelsGetter) *prometheus.Registry {
	// TODO: use NewPedanticRegistry when mongodb_exporter code fulfils its requirements (https://jira.percona.com/browse/PMM-6630).
	registry := prometheus.NewRegistry()

	gc := generalCollector{
		ctx:    ctx,
		client: client,
		logger: e.opts.Logger,
	}
	registry.MustRegister(&gc)

	nodeType, err := getNodeType(ctx, client)
	if err != nil {
		e.logger.Errorf("Cannot get node type to check if this is a mongos: %s", err)
	}

	if len(e.opts.CollStatsCollections) > 0 {
		cc := collstatsCollector{
			ctx:             ctx,
			client:          client,
			collections:     e.opts.CollStatsCollections,
			compatibleMode:  e.opts.CompatibleMode,
			discoveringMode: e.opts.DiscoveringMode,
			logger:          e.opts.Logger,
			topologyInfo:    topologyInfo,
		}
		registry.MustRegister(&cc)
	}

	if len(e.opts.IndexStatsCollections) > 0 {
		ic := indexstatsCollector{
			ctx:             ctx,
			client:          client,
			collections:     e.opts.IndexStatsCollections,
			discoveringMode: e.opts.DiscoveringMode,
			logger:          e.opts.Logger,
			topologyInfo:    topologyInfo,
		}
		registry.MustRegister(&ic)
	}

	if !e.opts.DisableDiagnosticData {
		ddc := diagnosticDataCollector{
			ctx:            ctx,
			client:         client,
			compatibleMode: e.opts.CompatibleMode,
			logger:         e.opts.Logger,
			topologyInfo:   topologyInfo,
		}
		registry.MustRegister(&ddc)
	}

	// replSetGetStatus is not supported through mongos
	if !e.opts.DisableReplicasetStatus && nodeType != typeMongos {
		rsgsc := replSetGetStatusCollector{
			ctx:            ctx,
			client:         client,
			compatibleMode: e.opts.CompatibleMode,
			logger:         e.opts.Logger,
			topologyInfo:   topologyInfo,
		}
		registry.MustRegister(&rsgsc)
	}

	return registry
}

func (e *Exporter) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		client := e.client
		topologyInfo := e.topologyInfo
		// Use per-request connection.
		if !e.opts.GlobalConnPool {
			var err error
			client, err = connect(ctx, e.opts.URI, e.opts.DirectConnect)
			if err != nil {
				e.logger.Errorf("Cannot connect to MongoDB: %v", err)
				http.Error(
					w,
					"An error has occurred while connecting to MongoDB:\n\n"+err.Error(),
					http.StatusInternalServerError,
				)

				return
			}

			defer func() {
				if err = client.Disconnect(ctx); err != nil {
					e.logger.Errorf("Cannot disconnect mongo client: %v", err)
				}
			}()

			topologyInfo, err = newTopologyInfo(ctx, client)
			if err != nil {
				e.logger.Errorf("Cannot get topology info: %v", err)
				http.Error(
					w,
					"An error has occurred while getting topology info:\n\n"+err.Error(),
					http.StatusInternalServerError,
				)

				return
			}
		}

		registry := e.makeRegistry(ctx, client, topologyInfo)

		gatherers := prometheus.Gatherers{}
		gatherers = append(gatherers, prometheus.DefaultGatherer)
		gatherers = append(gatherers, registry)

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
			ErrorLog:      e.logger,
		})

		h.ServeHTTP(w, r)
	})
}

// Run starts the exporter.
func (e *Exporter) Run() {
	handler := e.handler()
	RunServer("MongoDB", e.webListenAddress, e.path, handler)
}

func connect(ctx context.Context, dsn string, directConnect bool) (*mongo.Client, error) {
	clientOpts := options.Client().ApplyURI(dsn)
	clientOpts.SetDirect(directConnect)
	clientOpts.SetAppName("mongodb_exporter")

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}

	if err = client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	return client, nil
}
