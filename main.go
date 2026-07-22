// Copyright 2018 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/prometheus/snmp_exporter/collector"
	"github.com/prometheus/snmp_exporter/config"
	"github.com/prometheus/snmp_exporter/inventory"
	"github.com/prometheus/snmp_exporter/output"
	"github.com/prometheus/snmp_exporter/output/remotewrite"
	"github.com/prometheus/snmp_exporter/scheduler"
)

const namespace = "snmp"

var (
	configFile    = kingpin.Flag("config.file", "Path to an SNMP profile/auth configuration file. May be repeated.").Default("snmp.yml").Strings()
	inventoryFile = kingpin.Flag("inventory.file", "Path or glob for the device inventory. May be repeated.").Required().Strings()
	outputFile    = kingpin.Flag("output.file", "Path to the output configuration.").Required().String()
	dryRun        = kingpin.Flag("dry-run", "Only verify configuration is valid and exit.").Default("false").Bool()
	debugSNMP     = kingpin.Flag("snmp.debug-packets", "Include a full debug trace of SNMP packet traffic.").Default("false").Bool()
	expandEnvVars = kingpin.Flag("config.expand-environment-variables", "Expand environment variables used by SNMP credentials.").Default("false").Bool()
	metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose collector metrics.").Default("/metrics").String()

	schedulerWorkers           = kingpin.Flag("scheduler.workers", "Number of active polling workers.").Default("100").Int()
	schedulerQueueSize         = kingpin.Flag("scheduler.queue-size", "Maximum number of device polls waiting for a worker.").Default("500").Int()
	schedulerDeliveryQueueSize = kingpin.Flag("scheduler.delivery-queue-size", "Maximum number of completed poll batches waiting for output delivery.").Default("500").Int()
	schedulerDefaultInterval   = kingpin.Flag("scheduler.default-interval", "Default polling interval for inventory entries that omit interval.").Default("1m").Duration()
	schedulerDefaultTimeout    = kingpin.Flag("scheduler.default-timeout", "Default polling timeout for inventory entries that omit timeout.").Default("45s").Duration()
	schedulerJitter            = kingpin.Flag("scheduler.jitter", "Maximum startup and retry jitter for active polling.").Default("10s").Duration()
	schedulerQueueRetry        = kingpin.Flag("scheduler.queue-retry", "Delay before rescheduling a poll when the worker queue is full.").Default("1s").Duration()
	schedulerMaxBackoff        = kingpin.Flag("scheduler.max-backoff", "Maximum polling backoff after repeated failures.").Default("15m").Duration()
	shutdownTimeout            = kingpin.Flag("shutdown-timeout", "Maximum time to stop polling and flush the active output.").Default("30s").Duration()
	toolkitFlags               = webflag.AddFlags(kingpin.CommandLine, ":9116")

	snmpCollectionDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "collection_duration_seconds",
			Help:      "Duration of active SNMP polls.",
		},
		[]string{"module"},
	)
	reloadCh chan chan error
)

type runtimeSnapshot struct {
	profiles  *config.Config
	inventory *inventory.Snapshot
	output    *remotewrite.RuntimeConfig
}

type runtimeScheduler interface {
	Reconcile(context.Context, *inventory.Snapshot, *config.Config) error
	Stop(context.Context) error
}

type collectorRuntime struct {
	scheduler     runtimeScheduler
	output        *output.Manager
	outputMetrics output.Metrics
	logger        *slog.Logger
}

type readinessChecker interface {
	Ready() error
}

func updateConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST method expected", http.StatusBadRequest)
		return
	}
	rc := make(chan error)
	reloadCh <- rc
	if err := <-rc; err != nil {
		http.Error(w, fmt.Sprintf("failed to reload configuration: %s", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Reloaded\n"))
}

func loadRuntimeSnapshot(
	logger *slog.Logger,
	configPaths []string,
	expandEnvVars bool,
	inventoryPaths []string,
	outputPath string,
	defaultInterval time.Duration,
	defaultTimeout time.Duration,
) (*runtimeSnapshot, error) {
	if len(inventoryPaths) == 0 {
		return nil, fmt.Errorf("--inventory.file is required")
	}
	if outputPath == "" {
		return nil, fmt.Errorf("--output.file is required")
	}

	profiles, err := config.LoadFile(logger, configPaths, expandEnvVars)
	if err != nil {
		return nil, fmt.Errorf("load SNMP configuration: %w", err)
	}
	if len(profiles.Modules) == 0 {
		return nil, fmt.Errorf("SNMP configuration is missing modules")
	}
	if len(profiles.Auths) == 0 {
		return nil, fmt.Errorf("SNMP configuration is missing auths")
	}

	devices, err := inventory.NewLoader(defaultInterval, defaultTimeout).Load(inventoryPaths, profiles)
	if err != nil {
		return nil, fmt.Errorf("load device inventory: %w", err)
	}
	outputConfig, err := remotewrite.LoadConfigFile(outputPath)
	if err != nil {
		return nil, err
	}
	if outputConfig.CredentialRef != "" {
		return nil, fmt.Errorf("output credentialRef requires a SecretStore; use headerEnv until the SecretStore module is enabled")
	}

	return &runtimeSnapshot{profiles: profiles, inventory: devices, output: outputConfig}, nil
}

func newRemoteWriteOutput(ctx context.Context, config *remotewrite.RuntimeConfig, metrics output.Metrics) (output.Output, error) {
	headerProvider, err := remotewrite.NewEnvHeaderProvider(config.HeaderEnv)
	if err != nil {
		return nil, fmt.Errorf("create remote write credentials: %w", err)
	}
	if _, err := headerProvider.Headers(ctx); err != nil {
		return nil, fmt.Errorf("resolve remote write credentials: %w", err)
	}
	remoteOutput, err := remotewrite.NewOutput(config.Sender, config.Queue, nil, headerProvider, metrics)
	if err != nil {
		return nil, fmt.Errorf("create remote write output: %w", err)
	}
	return remoteOutput, nil
}

func startCollector(
	ctx context.Context,
	snapshot *runtimeSnapshot,
	logger *slog.Logger,
	pollMetrics collector.Metrics,
	registerer prometheus.Registerer,
) (*collectorRuntime, error) {
	outputMetrics := output.NewMetrics(registerer)
	remoteOutput, err := newRemoteWriteOutput(ctx, snapshot.output, outputMetrics)
	if err != nil {
		return nil, err
	}
	outputManager, err := output.NewManager(remoteOutput)
	if err != nil {
		return nil, fmt.Errorf("create output manager: %w", err)
	}
	if err := outputManager.Start(ctx); err != nil {
		return nil, fmt.Errorf("start remote write output: %w", err)
	}

	pollScheduler, err := scheduler.New(scheduler.Config{
		Workers:           *schedulerWorkers,
		QueueSize:         *schedulerQueueSize,
		DeliveryQueueSize: *schedulerDeliveryQueueSize,
		Jitter:            *schedulerJitter,
		QueueRetry:        *schedulerQueueRetry,
		MaxBackoff:        *schedulerMaxBackoff,
	}, collector.NewPoller(logger, pollMetrics, *debugSNMP), outputManager, logger, scheduler.NewMetrics(registerer))
	if err != nil {
		_ = closeOutputAfterStartupFailure(outputManager)
		return nil, fmt.Errorf("create polling scheduler: %w", err)
	}
	if err := pollScheduler.Start(ctx); err != nil {
		_ = closeOutputAfterStartupFailure(outputManager)
		return nil, fmt.Errorf("start polling scheduler: %w", err)
	}
	if err := pollScheduler.Reconcile(ctx, snapshot.inventory, snapshot.profiles); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = pollScheduler.Stop(cleanupCtx)
		_ = outputManager.Close(cleanupCtx)
		return nil, fmt.Errorf("apply device inventory: %w", err)
	}

	return &collectorRuntime{
		scheduler:     pollScheduler,
		output:        outputManager,
		outputMetrics: outputMetrics,
		logger:        logger,
	}, nil
}

func closeOutputAfterStartupFailure(manager *output.Manager) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return manager.Close(ctx)
}

func (runtime *collectorRuntime) Ready() error {
	return runtime.output.Ready()
}

// Reload prepares and readiness-checks the replacement output before applying
// the new profiles and inventory. A validation, output startup, or scheduler
// reconciliation error leaves the previous runtime active.
func (runtime *collectorRuntime) Reload(ctx context.Context, snapshot *runtimeSnapshot) error {
	nextOutput, err := newRemoteWriteOutput(ctx, snapshot.output, runtime.outputMetrics)
	if err != nil {
		return err
	}
	cleanupErr, activationErr := runtime.output.SwapWith(ctx, nextOutput, func() error {
		return runtime.scheduler.Reconcile(ctx, snapshot.inventory, snapshot.profiles)
	})
	if activationErr != nil {
		return fmt.Errorf("activate reloaded configuration: %w", activationErr)
	}
	if cleanupErr != nil {
		runtime.logger.Warn("Reload applied but the previous output did not close cleanly", "err", cleanupErr)
	}
	initializeModuleMetrics(snapshot.profiles)
	return nil
}

// Close first stops all producers, then flushes and closes the active output
// so no poll result can arrive after the final flush.
func (runtime *collectorRuntime) Close(ctx context.Context) error {
	stopErr := runtime.scheduler.Stop(ctx)
	outputErr := runtime.output.Close(ctx)
	return errors.Join(stopErr, outputErr)
}

func initializeModuleMetrics(profiles *config.Config) {
	for module := range profiles.Modules {
		snmpCollectionDuration.WithLabelValues(module)
	}
}

func newPollMetrics() collector.Metrics {
	buckets := prometheus.ExponentialBuckets(0.0001, 2, 15)
	return collector.Metrics{
		SNMPCollectionDuration: snmpCollectionDuration,
		SNMPUnexpectedPduType: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "unexpected_pdu_type_total",
			Help:      "Number of unexpected SNMP PDU value types.",
		}),
		SNMPDuration: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "packet_duration_seconds",
			Help:      "Latency of SNMP packets.",
			Buckets:   buckets,
		}),
		SNMPPackets: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packets_total",
			Help:      "Number of SNMP packets sent, including retries.",
		}),
		SNMPRetries: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "packet_retries_total",
			Help:      "Number of retried SNMP packets.",
		}),
		SNMPInflight: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      "request_in_flight",
			Help:      "Number of active SNMP polls.",
		}),
	}
}

func newHTTPHandler(telemetryPath string, ready readinessChecker) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(telemetryPath, promhttp.Handler())
	mux.HandleFunc("/-/reload", updateConfiguration)
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Healthy\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if err := ready.Ready(); err != nil {
			http.Error(w, "Not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ready\n"))
	})
	return mux
}

func main() {
	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print("snmp_collector"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promslog.New(promslogConfig)

	logger.Info("Starting snmp_collector", "version", version.Info(), "debug_snmp", *debugSNMP)
	logger.Info("operational information", "build_context", version.BuildContext())
	prometheus.MustRegister(versioncollector.NewCollector("snmp_collector"))

	snapshot, err := loadRuntimeSnapshot(
		logger,
		*configFile,
		*expandEnvVars,
		*inventoryFile,
		*outputFile,
		*schedulerDefaultInterval,
		*schedulerDefaultTimeout,
	)
	if err != nil {
		logger.Error("Error parsing collector configuration", "err", err)
		os.Exit(1)
	}
	initializeModuleMetrics(snapshot.profiles)
	if *dryRun {
		if _, err := newRemoteWriteOutput(context.Background(), snapshot.output, output.Metrics{}); err != nil {
			logger.Error("Error validating output", "err", err)
			os.Exit(1)
		}
		logger.Info("Configuration parsed successfully",
			"devices", snapshot.inventory.Len(),
			"inventory_revision", snapshot.inventory.Revision(),
			"output_revision", snapshot.output.Revision,
		)
		return
	}

	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	runtime, err := startCollector(runtimeCtx, snapshot, logger, newPollMetrics(), prometheus.DefaultRegisterer)
	if err != nil {
		logger.Error("Error starting collector", "err", err)
		os.Exit(1)
	}
	logger.Info("Active polling started",
		"devices", snapshot.inventory.Len(),
		"inventory_revision", snapshot.inventory.Revision(),
		"output_revision", snapshot.output.Revision,
	)

	hup := make(chan os.Signal, 1)
	reloadCh = make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	reload := func() error {
		next, err := loadRuntimeSnapshot(
			logger,
			*configFile,
			*expandEnvVars,
			*inventoryFile,
			*outputFile,
			*schedulerDefaultInterval,
			*schedulerDefaultTimeout,
		)
		if err != nil {
			return err
		}
		reloadCtx, cancelReload := context.WithTimeout(runtimeCtx, *shutdownTimeout)
		defer cancelReload()
		if err := runtime.Reload(reloadCtx, next); err != nil {
			return err
		}
		logger.Info("Reloaded profiles, device inventory, and output",
			"devices", next.inventory.Len(),
			"inventory_revision", next.inventory.Revision(),
			"output_revision", next.output.Revision,
		)
		return nil
	}
	go func() {
		for {
			select {
			case <-hup:
				if err := reload(); err != nil {
					logger.Error("Error reloading configuration", "err", err)
				}
			case rc := <-reloadCh:
				err := reload()
				if err != nil {
					logger.Error("Error reloading configuration", "err", err)
				}
				rc <- err
			}
		}
	}()

	srv := &http.Server{Handler: newHTTPHandler(*metricsPath, runtime)}
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- web.ListenAndServe(srv, toolkitFlags, logger)
	}()

	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(terminate)
	serverStopped := false
	select {
	case received := <-terminate:
		logger.Info("Received shutdown signal", "signal", received)
	case err := <-serverErr:
		serverStopped = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped unexpectedly", "err", err)
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), *shutdownTimeout)
	defer cancelShutdown()
	if err := runtime.Close(shutdownCtx); err != nil {
		logger.Error("Error stopping collector", "err", err)
	}
	cancelRuntime()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("Error shutting down HTTP server", "err", err)
	}
	if !serverStopped {
		select {
		case err := <-serverErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("HTTP server stopped with an error", "err", err)
			}
		case <-shutdownCtx.Done():
			logger.Error("Timed out waiting for HTTP server shutdown", "err", shutdownCtx.Err())
		}
	}
}
