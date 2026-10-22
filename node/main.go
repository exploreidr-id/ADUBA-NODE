package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const ChainID = "aduba-testnet-1"
const Version = "v1.3-testnet"
const GenesisTimestamp int64 = 0

type Account struct {
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}
type Transaction struct {
	ChainID string `json:"chain_id"`
	Nonce   uint64 `json:"nonce"`
	From    string `json:"from"`
	To      string `json:"to"`
	Amount  uint64 `json:"amount"`
	Fee     uint64 `json:"fee"`
	PubKey  string `json:"pub_key"`
	Sig     string `json:"signature"`
}

func canonical(tx Transaction) string {
	return fmt.Sprintf("%s|%d|%s|%s|%d|%d|%s", tx.ChainID, tx.Nonce, tx.From, tx.To, tx.Amount, tx.Fee, tx.PubKey)
}
func address(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ADU1" + hex.EncodeToString(h[:20])
}
func verify(tx Transaction) bool {
	if tx.ChainID != ChainID || tx.From == tx.To {
		return false
	}
	pk, e1 := hex.DecodeString(tx.PubKey)
	sig, e2 := hex.DecodeString(tx.Sig)
	if e1 != nil || e2 != nil || len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return address(ed25519.PublicKey(pk)) == tx.From && ed25519.Verify(ed25519.PublicKey(pk), []byte(canonical(tx)), sig)
}
func txID(tx Transaction) string {
	h := sha256.Sum256([]byte(canonical(tx) + "|" + tx.Sig))
	return hex.EncodeToString(h[:])
}

type Block struct {
	Height       uint64        `json:"height"`
	PrevHash     string        `json:"prev_hash"`
	TxRoot       string        `json:"tx_root"`
	Proposer     string        `json:"proposer"`
	Round        uint64        `json:"round"`
	ProposalSig  string        `json:"proposal_sig,omitempty"`
	Timestamp    int64         `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	Hash         string        `json:"hash"`
}
type Validator struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	PubKey  string `json:"pub_key"`
	Stake   uint64 `json:"stake"`
	Jailed  bool   `json:"jailed"`
	Missed  uint64 `json:"missed"`
}
type Vote struct {
	Height    uint64 `json:"height"`
	BlockHash string `json:"block_hash"`
	Validator string `json:"validator"`
	PubKey    string `json:"pub_key"`
	Sig       string `json:"signature"`
}
type Finality struct {
	Height    uint64 `json:"height"`
	BlockHash string `json:"block_hash"`
	Stake     uint64 `json:"stake"`
}
type TimeoutVote struct {
	Height    uint64 `json:"height"`
	Round     uint64 `json:"round"`
	Validator string `json:"validator"`
	PubKey    string `json:"pub_key"`
	Sig       string `json:"signature"`
}
type ConsensusVote struct {
	Height    uint64 `json:"height"`
	Round     uint64 `json:"round"`
	Phase     string `json:"phase"`
	BlockHash string `json:"block_hash"`
	Validator string `json:"validator"`
	PubKey    string `json:"pub_key"`
	Sig       string `json:"signature"`
}
type TimeoutCertificate struct {
	Height uint64 `json:"height"`
	Round  uint64 `json:"round"`
	Stake  uint64 `json:"stake"`
}
type QuorumCertificate struct {
	Height    uint64          `json:"height"`
	Round     uint64          `json:"round"`
	Phase     string          `json:"phase"`
	BlockHash string          `json:"block_hash"`
	Stake     uint64          `json:"stake"`
	Votes     []ConsensusVote `json:"votes"`
}
type diskState struct {
	Accounts     map[string]Account                                        `json:"accounts"`
	Blocks       []Block                                                   `json:"blocks"`
	Validators   map[string]Validator                                      `json:"validators"`
	Votes        map[uint64]map[string]Vote                                `json:"votes"`
	Consensus    map[uint64]map[uint64]map[string]map[string]ConsensusVote `json:"consensus_votes"`
	Finalized    Finality                                                  `json:"finalized"`
	Timeouts     map[uint64]map[uint64]map[string]TimeoutVote              `json:"timeouts"`
	Certificates map[uint64]QuorumCertificate                              `json:"certificates"`
	LockedHeight uint64                                                    `json:"locked_height"`
	LockedHash   string                                                    `json:"locked_hash"`
}
type State struct {
	mu           sync.RWMutex
	accounts     map[string]Account
	blocks       []Block
	mempool      map[string]Transaction
	dataDir      string
	nodeID       string
	peers        []string
	validators   map[string]Validator
	votes        map[uint64]map[string]Vote
	consensus    map[uint64]map[uint64]map[string]map[string]ConsensusVote
	timeouts     map[uint64]map[uint64]map[string]TimeoutVote
	certificates map[uint64]QuorumCertificate
	finalized    Finality
	lockedHeight uint64
	lockedHash   string
	currentRound uint64
	lastTimeout  TimeoutCertificate
	signingKey   ed25519.PrivateKey
	http         *http.Client
}

func hashBlock(b Block) string {
	txroot := b.TxRoot
	s := fmt.Sprintf("%d|%s|%s|%s|%d|%d", b.Height, b.PrevHash, txroot, b.Proposer, b.Timestamp, b.Round)
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func txRoot(txs []Transaction) string {
	if len(txs) == 0 {
		h := sha256.Sum256([]byte("empty"))
		return hex.EncodeToString(h[:])
	}
	var ids []string
	for _, tx := range txs {
		ids = append(ids, txID(tx))
	}
	h := sha256.Sum256([]byte(strings.Join(ids, "|")))
	return hex.EncodeToString(h[:])
}
func newState(dir string, nodeID string, peers []string) *State {
	s := &State{accounts: map[string]Account{}, blocks: nil, mempool: map[string]Transaction{}, validators: map[string]Validator{}, votes: map[uint64]map[string]Vote{}, consensus: map[uint64]map[uint64]map[string]map[string]ConsensusVote{}, timeouts: map[uint64]map[uint64]map[string]TimeoutVote{}, certificates: map[uint64]QuorumCertificate{}, dataDir: dir, nodeID: nodeID, peers: peers, http: &http.Client{Timeout: 5 * time.Second}}
	if s.load() == nil && len(s.blocks) > 0 {
		return s
	}
	gen := Block{Height: 0, TxRoot: "genesis", Proposer: "genesis", Timestamp: GenesisTimestamp}
	gen.Hash = hashBlock(gen)
	s.blocks = []Block{gen}
	_ = s.persist()
	return s
}
func (s *State) path() string { return s.dataDir + "/state.json" }
func (s *State) persist() error {
	if s.dataDir == "" {
		return nil
	}
	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		return err
	}
	d := diskState{Accounts: s.accounts, Blocks: s.blocks, Validators: s.validators, Votes: s.votes, Consensus: s.consensus, Timeouts: s.timeouts, Certificates: s.certificates, Finalized: s.finalized, LockedHeight: s.lockedHeight, LockedHash: s.lockedHash}
	b, e := json.MarshalIndent(d, "", "  ")
	if e != nil {
		return e
	}
	tmp := s.path() + ".tmp"
	if e = os.WriteFile(tmp, b, 0644); e != nil {
		return e
	}
	return os.Rename(tmp, s.path())
}
func (s *State) load() error {
	b, e := os.ReadFile(s.path())
	if e != nil {
		return e
	}
	var d diskState
	if e = json.Unmarshal(b, &d); e != nil {
		return e
	}
	if d.Accounts == nil {
		d.Accounts = map[string]Account{}
	}
	if d.Validators == nil {
		d.Validators = map[string]Validator{}
	}
	if d.Votes == nil {
		d.Votes = map[uint64]map[string]Vote{}
	}
	if d.Consensus == nil {
		d.Consensus = map[uint64]map[uint64]map[string]map[string]ConsensusVote{}
	}
	if d.Timeouts == nil {
		d.Timeouts = map[uint64]map[uint64]map[string]TimeoutVote{}
	}
	if d.Certificates == nil {
		d.Certificates = map[uint64]QuorumCertificate{}
	}
	s.accounts = d.Accounts
	s.blocks = d.Blocks
	s.validators = d.Validators
	s.votes = d.Votes
	s.consensus = d.Consensus
	s.timeouts = d.Timeouts
	s.certificates = d.Certificates
	s.finalized = d.Finalized
	s.lockedHeight = d.LockedHeight
	s.lockedHash = d.LockedHash
	return nil
}
func (s *State) status(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]any{"chain_id": ChainID, "height": s.blocks[len(s.blocks)-1].Height, "mempool": len(s.mempool), "version": Version, "node_id": s.nodeID, "peers": len(s.peers), "validators": len(s.validators), "finalized_height": s.finalized.Height, "locked_height": s.lockedHeight, "locked_hash": s.lockedHash, "round": s.currentRound, "last_timeout": s.lastTimeout, "quorum_certificates": len(s.certificates)})
}
func (s *State) latest(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(s.blocks[len(s.blocks)-1])
}
func (s *State) balance(w http.ResponseWriter, r *http.Request) {
	a := strings.TrimSpace(r.URL.Query().Get("address"))
	if a == "" {
		http.Error(w, "address required", 400)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(s.accounts[a])
}
func (s *State) mempoolJSON(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Transaction, 0, len(s.mempool))
	for _, tx := range s.mempool {
		out = append(out, tx)
	}
	json.NewEncoder(w).Encode(out)
}
func (s *State) validateTxLocked(tx Transaction) error {
	if !verify(tx) {
		return errors.New("invalid transaction")
	}
	if _, ok := s.mempool[txID(tx)]; ok {
		return errors.New("duplicate transaction")
	}
	from := s.accounts[tx.From]
	if from.Nonce != tx.Nonce {
		return fmt.Errorf("invalid nonce: expected %d", from.Nonce)
	}
	if tx.Amount > ^uint64(0)-tx.Fee {
		return errors.New("amount plus fee overflow")
	}
	if from.Balance < tx.Amount+tx.Fee {
		return errors.New("insufficient balance")
	}
	return nil
}
func (s *State) tx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var tx Transaction
	if json.NewDecoder(r.Body).Decode(&tx) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	if e := s.validateTxLocked(tx); e != nil {
		s.mu.Unlock()
		http.Error(w, e.Error(), 400)
		return
	}
	id := txID(tx)
	s.mempool[id] = tx
	mempoolSize := len(s.mempool)
	s.mu.Unlock()
	go s.broadcastTx(tx)
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "tx_id": id, "mempool": mempoolSize})
}
func (s *State) produceBlockLocked() (Block, error) {
	if len(s.mempool) == 0 {
		return Block{}, errors.New("mempool empty")
	}
	ids := make([]string, 0, len(s.mempool))
	for id := range s.mempool {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	txs := make([]Transaction, 0, len(ids))
	for _, id := range ids {
		txs = append(txs, s.mempool[id])
	}
	last := s.blocks[len(s.blocks)-1]
	round := s.currentRound
	if proposer, ok := s.proposerForHeightRoundLocked(last.Height+1, round); ok && proposer != s.nodeID {
		return Block{}, fmt.Errorf("not proposer for height %d: %s", last.Height+1, proposer)
	}
	b := Block{Height: last.Height + 1, PrevHash: last.Hash, TxRoot: txRoot(txs), Proposer: s.nodeID, Round: round, Timestamp: time.Now().Unix(), Transactions: txs}
	b.Hash = hashBlock(b)
	if val, ok := s.validators[s.nodeID]; ok {
		if len(s.signingKey) != ed25519.PrivateKeySize {
			return Block{}, errors.New("validator signing key not configured")
		}
		if val.PubKey != hex.EncodeToString(s.signingKey.Public().(ed25519.PublicKey)) {
			return Block{}, errors.New("validator signing key does not match registered pubkey")
		}
		b.ProposalSig = hex.EncodeToString(ed25519.Sign(s.signingKey, []byte(proposalCanonical(b))))
	}
	for _, tx := range txs {
		from := s.accounts[tx.From]
		to := s.accounts[tx.To]
		from.Balance -= tx.Amount + tx.Fee
		from.Nonce++
		to.Balance += tx.Amount
		s.accounts[tx.From] = from
		s.accounts[tx.To] = to
		delete(s.mempool, txID(tx))
	}
	s.blocks = append(s.blocks, b)
	if e := s.persist(); e != nil {
		return Block{}, e
	}
	return b, nil
}
func (s *State) applyBlockLocked(b Block) error {
	if len(s.blocks) == 0 {
		return errors.New("chain is empty")
	}
	last := s.blocks[len(s.blocks)-1]
	if b.Height != last.Height+1 {
		return fmt.Errorf("unexpected block height: got %d want %d", b.Height, last.Height+1)
	}
	if b.PrevHash != last.Hash {
		return errors.New("previous hash mismatch")
	}
	if proposer, ok := s.proposerForHeightRoundLocked(b.Height, b.Round); ok {
		if b.Proposer != proposer {
			return fmt.Errorf("invalid proposer: got %s want %s", b.Proposer, proposer)
		}
		val := s.validators[b.Proposer]
		if !verifyProposal(b, val) {
			return errors.New("invalid proposer signature")
		}
	}
	if s.finalized.Height > 0 && b.Height <= s.finalized.Height {
		return errors.New("block is at or below finalized height")
	}
	if s.lockedHeight > 0 && b.Height == s.lockedHeight && s.lockedHash != "" && b.Hash != s.lockedHash {
		return errors.New("locked block conflict")
	}
	if b.TxRoot != txRoot(b.Transactions) {
		return errors.New("transaction root mismatch")
	}
	if b.Hash != hashBlock(b) {
		return errors.New("block hash mismatch")
	}
	if len(b.Transactions) == 0 {
		return errors.New("empty block")
	}
	working := make(map[string]Account, len(s.accounts))
	for k, v := range s.accounts {
		working[k] = v
	}
	seen := make(map[string]struct{}, len(b.Transactions))
	for _, tx := range b.Transactions {
		id := txID(tx)
		if _, ok := seen[id]; ok {
			return errors.New("duplicate transaction in block")
		}
		seen[id] = struct{}{}
		if !verify(tx) {
			return errors.New("invalid transaction in block")
		}
		from := working[tx.From]
		if from.Nonce != tx.Nonce {
			return fmt.Errorf("invalid nonce for %s: got %d want %d", tx.From, tx.Nonce, from.Nonce)
		}
		if tx.Amount > ^uint64(0)-tx.Fee {
			return errors.New("amount plus fee overflow")
		}
		cost := tx.Amount + tx.Fee
		if from.Balance < cost {
			return errors.New("insufficient balance in block")
		}
		to := working[tx.To]
		if to.Balance > ^uint64(0)-tx.Amount {
			return errors.New("recipient balance overflow")
		}
		from.Balance -= cost
		from.Nonce++
		to.Balance += tx.Amount
		working[tx.From] = from
		working[tx.To] = to
	}
	s.accounts = working
	s.blocks = append(s.blocks, b)
	for _, tx := range b.Transactions {
		delete(s.mempool, txID(tx))
	}
	return s.persist()
}

func proposalCanonical(b Block) string {
	return fmt.Sprintf("%s|%d|%d|%s|%s|%s|%s|%d", ChainID, b.Height, b.Round, b.PrevHash, b.TxRoot, b.Proposer, b.Hash, b.Timestamp)
}

func verifyProposal(b Block, v Validator) bool {
	if b.Proposer != v.ID || v.Jailed || v.PubKey == "" || b.ProposalSig == "" {
		return false
	}
	pk, e1 := hex.DecodeString(v.PubKey)
	sig, e2 := hex.DecodeString(b.ProposalSig)
	if e1 != nil || e2 != nil || len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), []byte(proposalCanonical(b)), sig)
}

func timeoutCanonical(v TimeoutVote) string {
	return fmt.Sprintf("%s|timeout|%d|%d|%s", ChainID, v.Height, v.Round, v.Validator)
}
func verifyTimeoutVote(v TimeoutVote) bool {
	pk, e1 := hex.DecodeString(v.PubKey)
	sig, e2 := hex.DecodeString(v.Sig)
	if e1 != nil || e2 != nil || len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return address(ed25519.PublicKey(pk)) == v.Validator && ed25519.Verify(ed25519.PublicKey(pk), []byte(timeoutCanonical(v)), sig)
}

func consensusCanonical(v ConsensusVote) string {
	return fmt.Sprintf("%s|consensus|%d|%d|%s|%s|%s", ChainID, v.Height, v.Round, v.Phase, v.BlockHash, v.Validator)
}
func verifyConsensusVote(v ConsensusVote) bool {
	if v.Phase != "prevote" && v.Phase != "precommit" {
		return false
	}
	pk, e1 := hex.DecodeString(v.PubKey)
	sig, e2 := hex.DecodeString(v.Sig)
	if e1 != nil || e2 != nil || len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pk), []byte(consensusCanonical(v)), sig)
}
func (s *State) phaseStakeLocked(height, round uint64, phase, hash string) uint64 {
	var stake uint64
	if s.consensus[height] == nil || s.consensus[height][round] == nil || s.consensus[height][round][phase] == nil {
		return 0
	}
	for id, v := range s.consensus[height][round][phase] {
		if vv, ok := s.validators[id]; ok && !vv.Jailed && v.BlockHash == hash {
			stake += vv.Stake
		}
	}
	return stake
}
func (s *State) ensureConsensusBucketLocked(v ConsensusVote) {
	if s.consensus[v.Height] == nil {
		s.consensus[v.Height] = map[uint64]map[string]map[string]ConsensusVote{}
	}
	if s.consensus[v.Height][v.Round] == nil {
		s.consensus[v.Height][v.Round] = map[string]map[string]ConsensusVote{}
	}
	if s.consensus[v.Height][v.Round][v.Phase] == nil {
		s.consensus[v.Height][v.Round][v.Phase] = map[string]ConsensusVote{}
	}
}
func (s *State) buildCertificateLocked(height, round uint64, phase, blockHash string) (QuorumCertificate, bool) {
	bucket := s.consensus[height][round][phase]
	if len(bucket) == 0 {
		return QuorumCertificate{}, false
	}
	qc := QuorumCertificate{Height: height, Round: round, Phase: phase, BlockHash: blockHash}
	ids := make([]string, 0, len(bucket))
	for id := range bucket {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		v := bucket[id]
		if v.BlockHash == blockHash {
			qc.Votes = append(qc.Votes, v)
		}
	}
	qc.Stake = s.certificateStakeLocked(qc)
	return qc, qc.Stake >= s.quorumStakeLocked()
}
func (s *State) certificateStakeLocked(qc QuorumCertificate) uint64 {
	seen := map[string]bool{}
	var stake uint64
	for _, v := range qc.Votes {
		if seen[v.Validator] || v.Height != qc.Height || v.Round != qc.Round || v.Phase != qc.Phase || v.BlockHash != qc.BlockHash {
			continue
		}
		val, ok := s.validators[v.Validator]
		if !ok || val.Jailed || val.PubKey != v.PubKey || val.Address != v.PubKeyAddress() || !verifyConsensusVote(v) {
			continue
		}
		seen[v.Validator] = true
		stake += val.Stake
	}
	return stake
}
func (s *State) verifyCertificateLocked(qc QuorumCertificate) bool {
	if qc.Phase != "precommit" || qc.Height == 0 || len(qc.Votes) == 0 {
		return false
	}
	stake := s.certificateStakeLocked(qc)
	return stake >= s.quorumStakeLocked() && stake == qc.Stake
}

func (s *State) finalizeFromCommitLocked(v ConsensusVote) {
	qc, ok := s.buildCertificateLocked(v.Height, v.Round, "precommit", v.BlockHash)
	if ok && s.verifyCertificateLocked(qc) {
		s.certificates[v.Height] = qc
		s.finalized = Finality{Height: v.Height, BlockHash: v.BlockHash, Stake: qc.Stake}
		s.lockedHeight, s.lockedHash = v.Height, v.BlockHash
	}
}
func (s *State) makeConsensusVoteLocked(phase string, b Block) (ConsensusVote, error) {
	val, ok := s.validators[s.nodeID]
	if !ok || val.Jailed || len(s.signingKey) != ed25519.PrivateKeySize {
		return ConsensusVote{}, errors.New("node is not an active validator")
	}
	pub := hex.EncodeToString(s.signingKey.Public().(ed25519.PublicKey))
	if val.PubKey != pub {
		return ConsensusVote{}, errors.New("validator signing key does not match registered pubkey")
	}
	v := ConsensusVote{Height: b.Height, Round: b.Round, Phase: phase, BlockHash: b.Hash, Validator: s.nodeID, PubKey: pub}
	v.Sig = hex.EncodeToString(ed25519.Sign(s.signingKey, []byte(consensusCanonical(v))))
	return v, nil
}
func (v ConsensusVote) PubKeyAddress() string {
	pk, _ := hex.DecodeString(v.PubKey)
	return address(ed25519.PublicKey(pk))
}

func (s *State) acceptConsensusVoteLocked(v ConsensusVote) (bool, bool, error) {
	val, ok := s.validators[v.Validator]
	if !ok || val.Jailed || val.PubKey != v.PubKey || val.Address != v.PubKeyAddress() || !verifyConsensusVote(v) {
		return false, false, errors.New("invalid consensus vote")
	}
	if v.Height == 0 || v.Height > s.blocks[len(s.blocks)-1].Height {
		return false, false, errors.New("unknown height")
	}
	s.ensureConsensusBucketLocked(v)
	bucket := s.consensus[v.Height][v.Round][v.Phase]
	if old, exists := bucket[v.Validator]; exists {
		if old.BlockHash != v.BlockHash || old.Phase != v.Phase || old.Round != v.Round {
			val.Jailed = true
			s.validators[v.Validator] = val
			return false, false, errors.New("consensus equivocation: validator jailed")
		}
		return false, false, nil
	}
	if v.Height >= uint64(len(s.blocks)) {
		return false, false, errors.New("unknown height")
	}
	b := s.blocks[v.Height]
	if b.Round != v.Round || b.Hash != v.BlockHash {
		return false, false, errors.New("vote does not match block round/hash")
	}
	bucket[v.Validator] = v
	prevoteQuorum := s.phaseStakeLocked(v.Height, v.Round, "prevote", v.BlockHash) >= s.quorumStakeLocked()
	if v.Phase == "prevote" && prevoteQuorum {
		// A validator must have prevoted this block before it can precommit it.
		_, localPrevoted := s.consensus[v.Height][v.Round]["prevote"][s.nodeID]
		if localPrevoted {
			if s.consensus[v.Height][v.Round]["precommit"] == nil {
				s.consensus[v.Height][v.Round]["precommit"] = map[string]ConsensusVote{}
			}
			if _, exists := s.consensus[v.Height][v.Round]["precommit"][s.nodeID]; !exists {
				if pv, e := s.makeConsensusVoteLocked("precommit", b); e == nil {
					s.consensus[v.Height][v.Round]["precommit"][s.nodeID] = pv
				}
			}
		}
	}
	if v.Phase == "precommit" {
		s.finalizeFromCommitLocked(v)
	}
	return true, prevoteQuorum, nil
}

func (s *State) consensusVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var v ConsensusVote
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	accepted, prevoteQuorum, err := s.acceptConsensusVoteLocked(v)
	var localPrecommit ConsensusVote
	var havePrecommit bool
	if err == nil && v.Phase == "prevote" && prevoteQuorum {
		localPrecommit = s.consensus[v.Height][v.Round]["precommit"][s.nodeID]
		havePrecommit = localPrecommit.Validator != ""
	}
	if err == nil {
		err = s.persist()
	}
	var fin = s.finalized
	var commitStake uint64
	var qc QuorumCertificate
	var haveQC bool
	if err == nil {
		commitStake = s.phaseStakeLocked(v.Height, v.Round, "precommit", v.BlockHash)
		if x, ok := s.certificates[v.Height]; ok && x.BlockHash == v.BlockHash {
			qc, haveQC = x, true
		}
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if accepted {
		go s.broadcast("/p2p/consensus-vote", v, "")
	}
	if havePrecommit {
		go s.broadcast("/p2p/consensus-vote", localPrecommit, "")
	}
	if haveQC {
		go s.broadcast("/p2p/qc", qc, "")
	}
	json.NewEncoder(w).Encode(map[string]any{"accepted": accepted, "phase": v.Phase, "prevote_quorum": prevoteQuorum, "precommit_created": havePrecommit, "precommit_stake": commitStake, "finalized": fin, "quorum_certificate": qc})
}
func (s *State) receiveConsensusVote(w http.ResponseWriter, r *http.Request) { s.consensusVote(w, r) }

func voteCanonical(v Vote) string {
	return fmt.Sprintf("%s|%d|%s|%s", ChainID, v.Height, v.BlockHash, v.Validator)
}
func verifyVote(v Vote) bool {
	pk, e1 := hex.DecodeString(v.PubKey)
	sig, e2 := hex.DecodeString(v.Sig)
	if e1 != nil || e2 != nil || len(pk) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return address(ed25519.PublicKey(pk)) == v.Validator && ed25519.Verify(ed25519.PublicKey(pk), []byte(voteCanonical(v)), sig)
}
func (s *State) totalStakeLocked() uint64 {
	var n uint64
	for _, v := range s.validators {
		if !v.Jailed {
			n += v.Stake
		}
	}
	return n
}
func (s *State) quorumStakeLocked() uint64 { total := s.totalStakeLocked(); return total - total/3 }
func (s *State) proposerForHeightRoundLocked(height, round uint64) (string, bool) {
	vals := make([]Validator, 0, len(s.validators))
	for _, v := range s.validators {
		if !v.Jailed && v.Stake > 0 {
			vals = append(vals, v)
		}
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i].ID < vals[j].ID })
	if len(vals) == 0 {
		return "", false
	}
	var total uint64
	for _, v := range vals {
		total += v.Stake
	}
	if total == 0 {
		return "", false
	}
	n := (height + round) % total
	for _, v := range vals {
		if n < v.Stake {
			return v.ID, true
		}
		n -= v.Stake
	}
	return vals[len(vals)-1].ID, true
}
func (s *State) proposerForHeightLocked(height uint64) (string, bool) {
	return s.proposerForHeightRoundLocked(height, 0)
}

func (s *State) registerValidator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var v Validator
	if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID == "" || v.Address == "" || v.Stake == 0 {
		http.Error(w, "invalid validator", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.validators[v.ID]; ok {
		http.Error(w, "validator exists", 409)
		return
	}
	a := s.accounts[v.Address]
	if a.Balance < v.Stake {
		http.Error(w, "insufficient stake balance", 400)
		return
	}
	a.Balance -= v.Stake
	s.accounts[v.Address] = a
	v.Jailed = false
	s.validators[v.ID] = v
	if err := s.persist(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(v)
}
func (s *State) validatorsJSON(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Validator, 0, len(s.validators))
	for _, v := range s.validators {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	json.NewEncoder(w).Encode(out)
}
func (s *State) vote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var v Vote
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	val, ok := s.validators[v.Validator]
	if !ok || val.Jailed || val.PubKey != v.PubKey || !verifyVote(v) {
		http.Error(w, "invalid validator vote", 400)
		return
	}
	if v.Height == 0 || v.Height > s.blocks[len(s.blocks)-1].Height {
		http.Error(w, "unknown height", 400)
		return
	}
	if s.votes[v.Height] == nil {
		s.votes[v.Height] = map[string]Vote{}
	}
	if old, exists := s.votes[v.Height][v.Validator]; exists && old.BlockHash != v.BlockHash {
		val.Jailed = true
		s.validators[v.Validator] = val
		_ = s.persist()
		http.Error(w, "equivocation: validator jailed", 400)
		return
	}
	s.votes[v.Height][v.Validator] = v
	var stake uint64
	for id, vote := range s.votes[v.Height] {
		if vv, ok := s.validators[id]; ok && !vv.Jailed && vote.BlockHash == v.BlockHash {
			stake += vv.Stake
		}
	}
	if stake >= s.quorumStakeLocked() {
		s.finalized = Finality{Height: v.Height, BlockHash: v.BlockHash, Stake: stake}
		s.lockedHeight = v.Height
		s.lockedHash = v.BlockHash
	}
	if err := s.persist(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	go s.broadcastVote(v)
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "finalized": s.finalized})
}
func (s *State) broadcastVote(v Vote) { s.broadcast("/p2p/vote", v, "") }
func (s *State) receiveVote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var v Vote
	if json.NewDecoder(r.Body).Decode(&v) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	val, ok := s.validators[v.Validator]
	if !ok || val.Jailed || val.PubKey != v.PubKey || !verifyVote(v) {
		s.mu.Unlock()
		http.Error(w, "invalid vote", 400)
		return
	}
	if s.votes[v.Height] == nil {
		s.votes[v.Height] = map[string]Vote{}
	}
	if old, exists := s.votes[v.Height][v.Validator]; exists && old.BlockHash != v.BlockHash {
		val.Jailed = true
		s.validators[v.Validator] = val
		s.mu.Unlock()
		http.Error(w, "equivocation", 400)
		return
	}
	s.votes[v.Height][v.Validator] = v
	var stake uint64
	for id, x := range s.votes[v.Height] {
		if vv, ok := s.validators[id]; ok && !vv.Jailed && x.BlockHash == v.BlockHash {
			stake += vv.Stake
		}
	}
	if stake >= s.quorumStakeLocked() {
		s.finalized = Finality{Height: v.Height, BlockHash: v.BlockHash, Stake: stake}
		s.lockedHeight = v.Height
		s.lockedHash = v.BlockHash
	}
	err := s.persist()
	fin := s.finalized
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "finalized": fin})
}
func (s *State) consensusStatus(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(map[string]any{"finalized": s.finalized, "quorum_stake": s.quorumStakeLocked(), "total_stake": s.totalStakeLocked(), "round": s.currentRound, "locked_height": s.lockedHeight, "locked_hash": s.lockedHash, "timeout_certificate": s.lastTimeout, "consensus_votes": s.consensus, "quorum_certificates": s.certificates})
}

func (s *State) receiveQC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var qc QuorumCertificate
	if json.NewDecoder(r.Body).Decode(&qc) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	if qc.Height == 0 || qc.Height >= uint64(len(s.blocks)) || s.blocks[qc.Height].Hash != qc.BlockHash || !s.verifyCertificateLocked(qc) {
		s.mu.Unlock()
		http.Error(w, "invalid quorum certificate", 400)
		return
	}
	if old, ok := s.certificates[qc.Height]; ok && old.BlockHash != qc.BlockHash {
		s.mu.Unlock()
		http.Error(w, "conflicting quorum certificate", 400)
		return
	}
	s.certificates[qc.Height] = qc
	if qc.Height > s.finalized.Height {
		s.finalized = Finality{Height: qc.Height, BlockHash: qc.BlockHash, Stake: qc.Stake}
		if qc.Height > s.lockedHeight {
			s.lockedHeight, s.lockedHash = qc.Height, qc.BlockHash
		}
	}
	err := s.persist()
	fin := s.finalized
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "finalized": fin, "certificate": qc})
}

func (s *State) timeoutRound(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.signingKey) != ed25519.PrivateKeySize {
		http.Error(w, "validator signing key not configured", 400)
		return
	}
	val, ok := s.validators[s.nodeID]
	if !ok || val.Jailed || val.PubKey != hex.EncodeToString(s.signingKey.Public().(ed25519.PublicKey)) {
		http.Error(w, "node is not an active validator", 400)
		return
	}
	height := s.blocks[len(s.blocks)-1].Height + 1
	round := s.currentRound
	tv := TimeoutVote{Height: height, Round: round, Validator: s.nodeID, PubKey: val.PubKey}
	tv.Sig = hex.EncodeToString(ed25519.Sign(s.signingKey, []byte(timeoutCanonical(tv))))
	if s.timeouts[height] == nil {
		s.timeouts[height] = map[uint64]map[string]TimeoutVote{}
	}
	if s.timeouts[height][round] == nil {
		s.timeouts[height][round] = map[string]TimeoutVote{}
	}
	s.timeouts[height][round][tv.Validator] = tv
	stake := s.timeoutStakeLocked(height, round)
	advanced := false
	if stake >= s.quorumStakeLocked() {
		s.currentRound = round + 1
		s.lastTimeout = TimeoutCertificate{Height: height, Round: round, Stake: stake}
		advanced = true
	}
	if err := s.persist(); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	go s.broadcast("/p2p/timeout", tv, "")
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "height": height, "round": s.currentRound, "timeout_stake": stake, "advanced": advanced, "certificate": s.lastTimeout})
}
func (s *State) timeoutStakeLocked(height, round uint64) uint64 {
	var stake uint64
	for id := range s.timeouts[height][round] {
		if v, ok := s.validators[id]; ok && !v.Jailed {
			stake += v.Stake
		}
	}
	return stake
}
func (s *State) receiveTimeout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var tv TimeoutVote
	if json.NewDecoder(r.Body).Decode(&tv) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	val, ok := s.validators[tv.Validator]
	if !ok || val.Jailed || val.PubKey != tv.PubKey || !verifyTimeoutVote(tv) {
		s.mu.Unlock()
		http.Error(w, "invalid timeout vote", 400)
		return
	}
	if tv.Height != s.blocks[len(s.blocks)-1].Height+1 || tv.Round < s.currentRound {
		s.mu.Unlock()
		http.Error(w, "stale timeout vote", 400)
		return
	}
	if s.timeouts[tv.Height] == nil {
		s.timeouts[tv.Height] = map[uint64]map[string]TimeoutVote{}
	}
	if s.timeouts[tv.Height][tv.Round] == nil {
		s.timeouts[tv.Height][tv.Round] = map[string]TimeoutVote{}
	}
	bucket := s.timeouts[tv.Height][tv.Round]
	if old, exists := bucket[tv.Validator]; exists && old.Sig != tv.Sig {
		val.Jailed = true
		s.validators[tv.Validator] = val
		_ = s.persist()
		s.mu.Unlock()
		http.Error(w, "timeout equivocation", 400)
		return
	}
	bucket[tv.Validator] = tv
	stake := s.timeoutStakeLocked(tv.Height, tv.Round)
	advanced := false
	if stake >= s.quorumStakeLocked() && tv.Round >= s.currentRound {
		s.currentRound = tv.Round + 1
		s.lastTimeout = TimeoutCertificate{Height: tv.Height, Round: tv.Round, Stake: stake}
		advanced = true
	}
	err := s.persist()
	round := s.currentRound
	cert := s.lastTimeout
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "round": round, "timeout_stake": stake, "advanced": advanced, "certificate": cert})
}

func (s *State) receiveBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	var b Block
	if json.NewDecoder(r.Body).Decode(&b) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	err := s.applyBlockLocked(b)
	height := uint64(0)
	if len(s.blocks) > 0 {
		height = s.blocks[len(s.blocks)-1].Height
	}
	var pv ConsensusVote
	var havePV bool
	if err == nil {
		if x, e := s.makeConsensusVoteLocked("prevote", b); e == nil {
			s.ensureConsensusBucketLocked(x)
			s.consensus[x.Height][x.Round][x.Phase][x.Validator] = x
			pv, havePV = x, true
			_ = s.persist()
		}
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	go s.broadcastBlock(b)
	if havePV {
		go s.broadcast("/p2p/consensus-vote", pv, "")
	}
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "height": height, "hash": b.Hash, "prevote": havePV})
}

func (s *State) blocksJSON(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	json.NewEncoder(w).Encode(s.blocks)
}

func (s *State) broadcast(path string, payload any, skip string) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for _, peer := range s.peers {
		if peer == skip {
			continue
		}
		base := strings.TrimRight(peer, "/")
		u, err := url.Parse(base + path)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(string(body)))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if secret := os.Getenv("ADUBA_P2P_SECRET"); secret != "" {
			req.Header.Set("X-ADUBA-P2P", secret)
		}
		resp, err := s.http.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
}
func (s *State) broadcastTx(tx Transaction) { s.broadcast("/p2p/tx", tx, "") }
func (s *State) broadcastBlock(b Block)     { s.broadcast("/p2p/block", b, "") }

func (s *State) receiveTx(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var tx Transaction
	if json.NewDecoder(r.Body).Decode(&tx) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	s.mu.Lock()
	err := s.validateTxLocked(tx)
	if err == nil {
		s.mempool[txID(tx)] = tx
	}
	s.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	go s.broadcastTx(tx)
	json.NewEncoder(w).Encode(map[string]any{"accepted": true, "tx_id": txID(tx)})
}

type syncRequest struct {
	FromHeight uint64 `json:"from_height"`
	MaxBlocks  int    `json:"max_blocks"`
}
type syncResponse struct {
	ChainID      string                       `json:"chain_id"`
	Blocks       []Block                      `json:"blocks"`
	Certificates map[uint64]QuorumCertificate `json:"certificates"`
	Finalized    Finality                     `json:"finalized"`
	LockedHeight uint64                       `json:"locked_height"`
	LockedHash   string                       `json:"locked_hash"`
}

func (s *State) syncFromPeer(peer string) {
	base := strings.TrimRight(peer, "/")
	u, err := url.Parse(base + "/p2p/sync")
	if err != nil || u.Scheme == "" || u.Host == "" {
		return
	}
	s.mu.RLock()
	from := uint64(0)
	if len(s.blocks) > 0 {
		from = s.blocks[len(s.blocks)-1].Height + 1
	}
	s.mu.RUnlock()
	payload, _ := json.Marshal(syncRequest{FromHeight: from, MaxBlocks: 256})
	req, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(string(payload)))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret := os.Getenv("ADUBA_P2P_SECRET"); secret != "" {
		req.Header.Set("X-ADUBA-P2P", secret)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var out syncResponse
	if json.NewDecoder(resp.Body).Decode(&out) != nil || out.ChainID != ChainID {
		return
	}
	for _, b := range out.Blocks {
		s.mu.Lock()
		need := len(s.blocks) > 0 && b.Height == s.blocks[len(s.blocks)-1].Height+1
		var errApply error
		if need {
			errApply = s.applyBlockLocked(b)
		}
		if errApply == nil {
			if qc, ok := out.Certificates[b.Height]; ok {
				if qc.BlockHash != b.Hash || !s.verifyCertificateLocked(qc) {
					errApply = errors.New("invalid quorum certificate")
				} else {
					s.certificates[b.Height] = qc
				}
			}
		}
		s.mu.Unlock()
		if !need || errApply != nil {
			break
		}
	}
	s.mu.Lock()
	if qc, ok := out.Certificates[out.Finalized.Height]; ok && out.Finalized.Height > s.finalized.Height && qc.BlockHash == out.Finalized.BlockHash && s.verifyCertificateLocked(qc) {
		s.certificates[qc.Height] = qc
		s.finalized = Finality{Height: qc.Height, BlockHash: qc.BlockHash, Stake: qc.Stake}
		if qc.Height > s.lockedHeight {
			s.lockedHeight, s.lockedHash = qc.Height, qc.BlockHash
		}
		_ = s.persist()
	}
	s.mu.Unlock()
}

func (s *State) p2pSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var in syncRequest
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}
	if in.MaxBlocks <= 0 || in.MaxBlocks > 256 {
		in.MaxBlocks = 256
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if in.FromHeight > s.blocks[len(s.blocks)-1].Height {
		json.NewEncoder(w).Encode(syncResponse{ChainID: ChainID, Blocks: []Block{}, Certificates: map[uint64]QuorumCertificate{}, Finalized: s.finalized, LockedHeight: s.lockedHeight, LockedHash: s.lockedHash})
		return
	}
	start := int(in.FromHeight)
	if start < 0 || start >= len(s.blocks) {
		start = len(s.blocks) - 1
	}
	end := start + in.MaxBlocks
	if end > len(s.blocks) {
		end = len(s.blocks)
	}
	blocks := append([]Block(nil), s.blocks[start:end]...)
	certs := map[uint64]QuorumCertificate{}
	for h, qc := range s.certificates {
		if h >= in.FromHeight && h < uint64(end) {
			certs[h] = qc
		}
	}
	json.NewEncoder(w).Encode(syncResponse{ChainID: ChainID, Blocks: blocks, Certificates: certs, Finalized: s.finalized, LockedHeight: s.lockedHeight, LockedHash: s.lockedHash})
}

func (s *State) syncLoop(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			for _, peer := range s.peers {
				s.syncFromPeer(peer)
			}
		case <-stop:
			return
		}
	}
}

func (s *State) mine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", 405)
		return
	}
	s.mu.Lock()
	b, e := s.produceBlockLocked()
	var pv ConsensusVote
	var havePV bool
	if e == nil {
		if x, xerr := s.makeConsensusVoteLocked("prevote", b); xerr == nil {
			s.ensureConsensusBucketLocked(x)
			s.consensus[x.Height][x.Round][x.Phase][x.Validator] = x
			pv = x
			havePV = true
			_ = s.persist()
		}
	}
	s.mu.Unlock()
	if e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	go s.broadcastBlock(b)
	if havePV {
		go s.broadcast("/p2p/consensus-vote", pv, "")
	}
	json.NewEncoder(w).Encode(b)
}
func (s *State) runProducer(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.mu.Lock()
			if len(s.mempool) > 0 {
				if _, e := s.produceBlockLocked(); e != nil {
					log.Printf("block production error: %v", e)
				}
			}
			s.mu.Unlock()
		case <-stop:
			return
		}
	}
}
func main() {
	rpc := flag.String("rpc", ":8080", "HTTP RPC listen address")
	data := flag.String("data", "./data", "persistent data directory")
	interval := flag.Duration("block-interval", 0, "automatic block interval; 0 disables")
	nodeID := flag.String("node-id", "local-validator", "stable node/validator identifier")
	peerList := flag.String("peers", "", "comma-separated peer HTTP URLs, e.g. http://127.0.0.1:8081")
	p2pSecret := flag.String("p2p-secret", "", "shared secret required for /p2p/* endpoints")
	validatorKey := flag.String("validator-key", "", "path to hex-encoded Ed25519 private key")
	flag.Parse()
	var peers []string
	for _, p := range strings.Split(*peerList, ",") {
		if p = strings.TrimSpace(p); p != "" {
			peers = append(peers, strings.TrimRight(p, "/"))
		}
	}
	if *p2pSecret != "" {
		_ = os.Setenv("ADUBA_P2P_SECRET", *p2pSecret)
	}
	st := newState(*data, *nodeID, peers)
	if *validatorKey != "" {
		b, err := os.ReadFile(*validatorKey)
		if err != nil {
			log.Fatal(err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			log.Fatal("validator key must be 64-byte Ed25519 private key in hex")
		}
		st.signingKey = ed25519.PrivateKey(raw)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", st.status)
	mux.HandleFunc("/block/latest", st.latest)
	mux.HandleFunc("/balance", st.balance)
	mux.HandleFunc("/tx", st.tx)
	mux.HandleFunc("/mempool", st.mempoolJSON)
	mux.HandleFunc("/block/produce", st.mine)
	mux.HandleFunc("/blocks", st.blocksJSON)
	mux.HandleFunc("/p2p/tx", st.receiveTx)
	mux.HandleFunc("/p2p/block", st.receiveBlock)
	mux.HandleFunc("/p2p/sync", st.p2pSync)
	mux.HandleFunc("/validator/register", st.registerValidator)
	mux.HandleFunc("/validators", st.validatorsJSON)
	mux.HandleFunc("/vote", st.vote)
	mux.HandleFunc("/p2p/vote", st.receiveVote)
	mux.HandleFunc("/consensus/vote", st.consensusVote)
	mux.HandleFunc("/p2p/consensus-vote", st.receiveConsensusVote)
	mux.HandleFunc("/p2p/qc", st.receiveQC)
	mux.HandleFunc("/p2p/timeout", st.receiveTimeout)
	mux.HandleFunc("/consensus", st.consensusStatus)
	mux.HandleFunc("/consensus/timeout", st.timeoutRound)
	var handler http.Handler = mux
	if *p2pSecret != "" {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/p2p/") && r.Header.Get("X-ADUBA-P2P") != *p2pSecret {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mux.ServeHTTP(w, r)
		})
	}
	stop := make(chan struct{})
	defer close(stop)
	go st.runProducer(*interval, stop)
	go st.syncLoop(3*time.Second, stop)
	log.Printf("ADUBA %s RPC listening on %s (data=%s node=%s peers=%d)", Version, *rpc, *data, *nodeID, len(peers))
	log.Fatal(http.ListenAndServe(*rpc, handler))
}
