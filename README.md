# iam-go-libs

Shared Go libraries for the IAM microservices: `config`, `logger`, `grpcutil`,
`interceptor`, `db` (pgx pool), `migrate` (embedded migration runner) and
`events` (NATS JetStream helper + event contract). Imported by the auth, user
and gateway services. Part of the [iam-go](https://github.com/malvinpratama/iam-go) platform.

Tagged `vMAJOR.MINOR.PATCH`; consumers pin an exact version.
