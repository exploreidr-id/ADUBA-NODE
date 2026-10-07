# ADUBA-NODE v1.3-testnet

Development release for the ADUBA Proof-of-Stake testnet.

## v1.3-testnet hardening

- HTTP server read/write/idle timeouts and bounded request headers.
- Graceful shutdown on SIGINT/SIGTERM, allowing in-flight requests to finish.
- Constant-time comparison for the shared P2P secret.
- `/healthz` liveness endpoint and `/readyz` readiness endpoint.
- Added unit coverage for health/readiness responses.

## Run

```bash
cd node
go test ./...
go test -race ./...
go vet ./...
go build -o aduba-node .
```

A validator may run with:

```bash
./aduba-node -rpc :8080 -node-id v1 -validator-key ./validator.key -p2p-secret dev-secret
```

`POST /consensus/timeout` creates a signed timeout vote for the current height/round. Once timeout votes reach the active-validator quorum (at least 2/3 of active stake), the node advances to the next round and records a timeout certificate.

## Testnet warning

v1.3 remains testnet/devnet software. Quorum certificates are proof-carrying consensus evidence, but the protocol still requires independent security review, multi-process Byzantine fault-injection, stronger peer identity/transport, durable database storage, validator economics, and a formal specification before production use.

Do not use real funds.
