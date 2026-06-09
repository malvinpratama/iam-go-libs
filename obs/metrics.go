package obs

import (
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServeMetrics starts a background HTTP server exposing Prometheus /metrics at
// addr (e.g. ":9100"). Used by the headless gRPC services; the gateway serves
// /metrics from its own HTTP server instead.
func ServeMetrics(addr string, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
			log.Error("metrics server", "err", err)
		}
	}()
	log.Info("metrics endpoint", "addr", addr)
}
