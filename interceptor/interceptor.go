// Package interceptor provides gRPC server interceptors for resilience and
// gateway↔service authentication (defense-in-depth).
package interceptor

import (
	"context"
	"os"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/malvinpratama/iam-go-libs/grpcutil"
)

// Recovery converts a panic in a handler into a gRPC Internal error instead of
// crashing the whole server process.
func Recovery() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				debug.PrintStack()
				err = status.Errorf(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// exemptMethods may be called without the internal service token (health/reflection).
var exemptMethods = map[string]bool{
	"/grpc.health.v1.Health/Check": true,
	"/grpc.health.v1.Health/Watch": true,
}

// ServiceAuth requires that callers present the shared internal token in
// metadata. It is fail-closed: an empty/unset token does NOT silently disable
// enforcement — every non-exempt call is rejected — so a misconfigured
// deployment (whatever its APP_ENV) leaves internal RPCs locked, not wide open.
// To intentionally run without the secret (local dev, tests) set
// INTERNAL_AUTH_OPTIONAL=true; that opt-out must be explicit and is never the
// default.
func ServiceAuth(token string) grpc.UnaryServerInterceptor {
	optional := token == "" && os.Getenv("INTERNAL_AUTH_OPTIONAL") == "true"
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if exemptMethods[info.FullMethod] || optional {
			return handler(ctx, req)
		}
		if token != "" {
			md, _ := metadata.FromIncomingContext(ctx)
			if vals := md.Get(grpcutil.MDInternalToken); len(vals) == 1 && vals[0] == token {
				return handler(ctx, req)
			}
		}
		return nil, status.Error(codes.Unauthenticated, "missing or invalid internal service token")
	}
}

// Chain composes interceptors into one (recovery outermost).
func Chain(token string) grpc.ServerOption {
	return grpc.ChainUnaryInterceptor(Recovery(), ServiceAuth(token))
}
