# ADUBA-NODE v1.3-testnet Status

## Implemented
- HTTP server operational hardening: bounded headers, read/write/idle timeouts, and graceful SIGINT/SIGTERM shutdown.
- Constant-time P2P shared-secret comparison.
- Liveness/readiness endpoints for testnet orchestration.
- Cryptographic precommit quorum certificates containing signed validator evidence.
- Certificate persistence, verification after reload, and authenticated `/p2p/qc` relay.
- Proof-carrying sync: finalized metadata is accepted only with a locally verified matching certificate.
- Deterministic genesis and stake-weighted proposer selection by `(height, round)`.
- Ed25519-signed block proposals.
- Explicit BFT phases: `prevote` and `precommit`.
- Per-height/per-round/per-phase vote storage and persistence.
- 2/3 active-stake prevote quorum detection.
- A validator may precommit only after its own prevote and observing a prevote quorum.
- 2/3 active-stake precommit quorum finalizes the block and persists lock/finality.
- Consensus vote P2P relay through authenticated `/p2p/consensus-vote` when a shared P2P secret is configured.
- Signed timeout votes and timeout certificates remain integrated for round/view change.
- Equivocation detection for consensus votes and timeout votes; offending validator is jailed.
- Deterministic state persistence and reload.
- Adversarial unit coverage for BFT finality and invalid consensus signatures.

## Important limitations
This is still a **testnet/devnet implementation**, not production blockchain software. It has not undergone an independent security audit.

Remaining production-grade work includes:
- complete lock/valid-round semantics across all rounds;
- [x] durable quorum certificates with proof-carrying sync;
- [x] authenticated proof-carrying sync; v1.2 sends and verifies quorum certificates over bounded `/p2p/sync`; full state-transition proofs are still future work;
- peer discovery and robust peer scoring;
- encrypted transport / stronger node identity;
- validator lifecycle, rewards, slashing and unbonding economics;
- network-partition and Byzantine fault-injection testing at multi-process scale;
- resource limits, rate limiting and operational hardening;
- formal protocol specification and independent audit.

Do not use real funds.
