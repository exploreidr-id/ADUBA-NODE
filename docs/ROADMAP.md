# Roadmap

## v0.3 — Local node
- [x] Wallet/key generation
- [x] Signed transactions
- [x] State and nonce rules
- [x] Block engine
- [x] Local RPC
- [x] Tests

## v0.4 — Devnet state engine
- [x] Persistent JSON state
- [x] Mempool
- [x] Deterministic transaction ordering
- [x] Block production
- [x] Persistence tests

## v0.5 — Devnet P2P
- [x] Multi-node HTTP peer relay
- [x] Transaction gossip
- [x] Block gossip
- [x] Chain catch-up
- [x] Deterministic genesis
- [x] Remote block validation
- [ ] Authenticated/encrypted P2P
- [ ] Fork choice

## v0.6 — PoS consensus foundation
- [x] Validator registry with bonded stake
- [x] Stake-weighted deterministic proposer selection
- [x] Signed validator votes
- [x] 2/3 stake finality threshold
- [x] Equivocation detection and validator jailing
- [x] Persistent validator/vote/finality state
- [x] Consensus RPC and vote relay
- [ ] Automatic validator voting loop
- [ ] Full fork choice and competing-chain resolution
- [ ] Unbonding/delegation/rewards
- [ ] Adversarial/network-partition tests

## v0.7 — Production-oriented consensus/networking
- [ ] Authenticated/encrypted P2P
- [ ] Automatic proposer/vote rounds and timeouts
- [ ] BFT round/lock rules
- [ ] Fork-choice proofs and state sync
- [ ] Persistent database replacing JSON state
- [ ] Metrics and observability

## Mainnet
- [ ] Security audit
- [ ] Public testnet
- [ ] Explorer
- [ ] Public RPC
- [ ] Genesis ceremony
- [ ] Mainnet launch
