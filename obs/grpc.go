package obs

import (
	"context"
	"log/slog"
	"strings"
	"time"

	grpcprom "github.com/grpc-ecosystem/go-grpc-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-libs/grpcutil"
	"github.com/malvinpratama/iam-go-libs/interceptor"
)

// loggingUnary emits a structured access log per gRPC call, correlated by
// request id and trace id.
func loggingUnary(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		// Skip access logs for the gRPC health probes — k8s liveness/readiness
		// hit them every few seconds and would otherwise flood the log.
		if strings.HasPrefix(info.FullMethod, "/grpc.health.v1.Health/") {
			return resp, err
		}
		traceID := ""
		if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
			traceID = sc.TraceID().String()
		}
		log.Info("grpc.request",
			"method", info.FullMethod,
			"code", status.Code(err).String(),
			"ms", time.Since(start).Milliseconds(),
			"request_id", grpcutil.RequestIDFromIncoming(ctx),
			"trace_id", traceID,
		)
		return resp, err
	}
}

// ServerOptions bundles the gRPC server middleware: panic recovery,
// internal-token auth, Prometheus metrics, structured access logging, and OTel
// tracing. Replaces interceptor.Chain.
func ServerOptions(token string, log *slog.Logger) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			interceptor.Recovery(),
			interceptor.ServiceAuth(token),
			grpcprom.UnaryServerInterceptor,
			loggingUnary(log),
		),
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	}
}

// RegisterServerMetrics pre-initializes per-method Prometheus counters after the
// services are registered, so every method shows up at zero.
func RegisterServerMetrics(s *grpc.Server) { grpcprom.Register(s) }

// ClientDialOptions returns dial options that export client spans and propagate
// trace context to the internal services.
func ClientDialOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithStatsHandler(otelgrpc.NewClientHandler())}
}
