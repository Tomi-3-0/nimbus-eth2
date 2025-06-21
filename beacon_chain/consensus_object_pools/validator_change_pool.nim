# beacon_chain
# Copyright (c) 2020-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard libraries
  std/[deques, sets, tables],
  # Internal
  ../spec/datatypes/base,
  ../spec/[helpers, state_transition_block],
  "."/[attestation_pool, blockchain_dag]

from ../spec/beaconstate import check_bls_to_execution_change

export base, deques, blockchain_dag

const
  ATTESTER_SLASHINGS_BOUND = MAX_ATTESTER_SLASHINGS * 4
  PROPOSER_SLASHINGS_BOUND = MAX_PROPOSER_SLASHINGS * 4
  VOLUNTARY_EXITS_BOUND = MAX_VOLUNTARY_EXITS * 4

  # For Capella launch; scale back later
  BLS_TO_EXECUTION_CHANGES_BOUND = 16384'u64

  # EIP-7732 bounds
  EXECUTION_PAYLOAD_HEADERS_BOUND = MAX_PAYLOAD_ATTESTATIONS * 4  # Allow multiple headers per slot
  PAYLOAD_ATTESTATIONS_BOUND = MAX_PAYLOAD_ATTESTATIONS * 4
  EXECUTION_PAYLOAD_ENVELOPES_BOUND = 256'u64  # Reasonable bound for recent envelopes

type
  OnVoluntaryExitCallback =
    proc(data: SignedVoluntaryExit) {.gcsafe, raises: [].}
  OnBLSToExecutionChangeCallback =
    proc(data: SignedBLSToExecutionChange) {.gcsafe, raises: [].}
  OnProposerSlashingCallback =
    proc(data: ProposerSlashing) {.gcsafe, raises: [].}
  OnPhase0AttesterSlashingCallback =
    proc(data: phase0.AttesterSlashing) {.gcsafe, raises: [].}
  OnElectraAttesterSlashingCallback =
    proc(data: electra.AttesterSlashing) {.gcsafe, raises: [].}
  
  # EIP-7732 callbacks
  OnExecutionPayloadHeaderCallback =
    proc(data: SignedExecutionPayloadHeader) {.gcsafe, raises: [].}
  OnPayloadAttestationCallback =
    proc(data: PayloadAttestationMessage) {.gcsafe, raises: [].}
  OnExecutionPayloadEnvelopeCallback =
    proc(data: SignedExecutionPayloadEnvelope) {.gcsafe, raises: [].}

  ValidatorChangePool* = object
    ## The validator change pool tracks attester slashings, proposer slashings,
    ## voluntary exits, BLS to execution changes, and EIP-7732 messages that 
    ## could be added to a proposed block.

    phase0_attester_slashings*: Deque[phase0.AttesterSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    electra_attester_slashings*: Deque[electra.AttesterSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    proposer_slashings*: Deque[ProposerSlashing]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    voluntary_exits*: Deque[SignedVoluntaryExit]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    bls_to_execution_changes_gossip*: Deque[SignedBLSToExecutionChange]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    bls_to_execution_changes_api*: Deque[SignedBLSToExecutionChange]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    # EIP-7732 message pools
    execution_payload_headers*: Deque[SignedExecutionPayloadHeader]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    payload_attestation_messages*: Deque[PayloadAttestationMessage]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    execution_payload_envelopes*: Table[Eth2Digest, SignedExecutionPayloadEnvelope]  ## \
    ## Keyed by beacon_block_root for quick lookup

    prior_seen_attester_slashed_indices: HashSet[uint64] ## \
    ## Records attester-slashed indices seen. Share these across attester
    ## slashing types.

    prior_seen_proposer_slashed_indices: HashSet[uint64] ## \
    ## Records proposer-slashed indices seen.

    prior_seen_voluntary_exit_indices: HashSet[uint64] ##\
    ## Records voluntary exit indices seen.

    prior_seen_bls_to_execution_change_indices: HashSet[uint64] ##\
    ## Records BLS to execution change indices seen.

    # EIP-7732 seen tracking
    prior_seen_execution_payload_headers: Table[(Slot, ValidatorIndex), bool] ##\
    ## Records execution payload headers seen (by slot and builder index)

    prior_seen_payload_attestations: Table[(Slot, ValidatorIndex), bool] ##\
    ## Records payload attestations seen (by slot and validator index)

    prior_seen_execution_payload_envelopes: HashSet[Eth2Digest] ##\
    ## Records execution payload envelopes seen

    dag*: ChainDAGRef
    attestationPool: ref AttestationPool
    onVoluntaryExitReceived*: OnVoluntaryExitCallback
    onBLSToExecutionChangeReceived*: OnBLSToExecutionChangeCallback
    onProposerSlashingReceived*: OnProposerSlashingCallback
    onPhase0AttesterSlashingReceived*: OnPhase0AttesterSlashingCallback
    onElectraAttesterSlashingReceived*: OnElectraAttesterSlashingCallback
    
    # EIP-7732 callbacks
    onExecutionPayloadHeaderReceived*: OnExecutionPayloadHeaderCallback
    onPayloadAttestationReceived*: OnPayloadAttestationCallback
    onExecutionPayloadEnvelopeReceived*: OnExecutionPayloadEnvelopeCallback

func init*(T: type ValidatorChangePool, dag: ChainDAGRef,
           attestationPool: ref AttestationPool = nil,
           onVoluntaryExit: OnVoluntaryExitCallback = nil,
           onBLSToExecutionChange: OnBLSToExecutionChangeCallback = nil,
           onProposerSlashing: OnProposerSlashingCallback = nil,
           onPhase0AttesterSlashing: OnPhase0AttesterSlashingCallback = nil,
           onElectraAttesterSlashing: OnElectraAttesterSlashingCallback = nil,
           onExecutionPayloadHeader: OnExecutionPayloadHeaderCallback = nil,
           onPayloadAttestation: OnPayloadAttestationCallback = nil,
           onExecutionPayloadEnvelope: OnExecutionPayloadEnvelopeCallback = nil):
           T =
  ## Initialize an ValidatorChangePool from the dag `headState`
  T(
    # Allow filtering some validator change messages during block production
    phase0_attester_slashings:
      initDeque[phase0.AttesterSlashing](
        initialSize = ATTESTER_SLASHINGS_BOUND.int),
    electra_attester_slashings:
      initDeque[electra.AttesterSlashing](
        initialSize = ATTESTER_SLASHINGS_BOUND.int),
    proposer_slashings:
      initDeque[ProposerSlashing](initialSize = PROPOSER_SLASHINGS_BOUND.int),
    voluntary_exits:
      initDeque[SignedVoluntaryExit](initialSize = VOLUNTARY_EXITS_BOUND.int),
    bls_to_execution_changes_gossip:
      # TODO scale-back to BLS_TO_EXECUTION_CHANGES_BOUND post-capella, but
      # given large bound, allow to grow dynamically rather than statically
      # allocate all at once
      initDeque[SignedBLSToExecutionChange](initialSize = 1024),
    bls_to_execution_changes_api:
      # TODO scale-back to BLS_TO_EXECUTION_CHANGES_BOUND post-capella, but
      # given large bound, allow to grow dynamically rather than statically
      # allocate all at once
      initDeque[SignedBLSToExecutionChange](initialSize = 1024),
    
    execution_payload_headers:
      initDeque[SignedExecutionPayloadHeader](
        initialSize = EXECUTION_PAYLOAD_HEADERS_BOUND.int),
    payload_attestation_messages:
      initDeque[PayloadAttestationMessage](
        initialSize = PAYLOAD_ATTESTATIONS_BOUND.int),
    execution_payload_envelopes: initTable[Eth2Digest, SignedExecutionPayloadEnvelope](),
    
    dag: dag,
    attestationPool: attestationPool,
    onVoluntaryExitReceived: onVoluntaryExit,
    onBLSToExecutionChangeReceived: onBLSToExecutionChange,
    onProposerSlashingReceived: onProposerSlashing,
    onPhase0AttesterSlashingReceived: onPhase0AttesterSlashing,
    onElectraAttesterSlashingReceived: onElectraAttesterSlashing,
    onExecutionPayloadHeaderReceived: onExecutionPayloadHeader,
    onPayloadAttestationReceived: onPayloadAttestation,
    onExecutionPayloadEnvelopeReceived: onExecutionPayloadEnvelope)

func addValidatorChangeMessage(
    subpool: var auto, seenpool: var auto, validatorChangeMessage: auto,
    bound: static[uint64]) =
  # Prefer newer to older validator change messages
  while subpool.lenu64 >= bound:
    # TODO remove temporary workaround once capella happens
    when bound == BLS_TO_EXECUTION_CHANGES_BOUND:
      seenpool.excl subpool.popFirst().message.validator_index
    else:
      discard subpool.popFirst()

  subpool.addLast(validatorChangeMessage)
  doAssert subpool.lenu64 <= bound

iterator getValidatorIndices*(proposer_slashing: ProposerSlashing): uint64 =
  yield proposer_slashing.signed_header_1.message.proposer_index

iterator getValidatorIndices(voluntary_exit: SignedVoluntaryExit): uint64 =
  yield voluntary_exit.message.validator_index

iterator getValidatorIndices(
    bls_to_execution_change: SignedBLSToExecutionChange): uint64 =
  yield bls_to_execution_change.message.validator_index

# EIP-7732 seen checks
func isSeen*(
    pool: ValidatorChangePool, 
    msg: SignedExecutionPayloadHeader): bool =
  let key = (msg.message.slot, ValidatorIndex(msg.message.builder_index))
  key in pool.prior_seen_execution_payload_headers

func isSeen*(
    pool: ValidatorChangePool, 
    msg: PayloadAttestationMessage): bool =
  let key = (msg.data.slot, ValidatorIndex(msg.validatorIndex))
  key in pool.prior_seen_payload_attestations

func isSeen*(
    pool: ValidatorChangePool, 
    msg: SignedExecutionPayloadEnvelope): bool =
  let msgHash = hash_tree_root(msg)
  msgHash in pool.prior_seen_execution_payload_envelopes

func isSeen*(
    pool: ValidatorChangePool,
    msg: phase0.AttesterSlashing | electra.AttesterSlashing): bool =
  for idx in getValidatorIndices(msg):
    # One index is enough!
    if idx notin pool.prior_seen_attester_slashed_indices:
      return false
  true

func isSeen*(pool: ValidatorChangePool, msg: ProposerSlashing): bool =
  msg.signed_header_1.message.proposer_index in
    pool.prior_seen_proposer_slashed_indices

func isSeen*(pool: ValidatorChangePool, msg: SignedVoluntaryExit): bool =
  msg.message.validator_index in pool.prior_seen_voluntary_exit_indices

func isSeen*(pool: ValidatorChangePool, msg: SignedBLSToExecutionChange): bool =
  msg.message.validator_index in
    pool.prior_seen_bls_to_execution_change_indices

# EIP-7732 addMessage functions
func addMessage*(
    pool: var ValidatorChangePool, 
    msg: SignedExecutionPayloadHeader) =
  let key = (msg.message.slot, ValidatorIndex(msg.message.builder_index))
  
  pool.prior_seen_execution_payload_headers[key] = true
  
  while pool.execution_payload_headers.lenu64 >= EXECUTION_PAYLOAD_HEADERS_BOUND:
    discard pool.execution_payload_headers.popFirst()
  pool.execution_payload_headers.addLast(msg)

func addMessage*(
    pool: var ValidatorChangePool, 
    msg: PayloadAttestationMessage) =
  let key = (msg.data.slot, ValidatorIndex(msg.validatorIndex))
  
  pool.prior_seen_payload_attestations[key] = true
  
  while pool.payload_attestation_messages.lenu64 >= PAYLOAD_ATTESTATIONS_BOUND:
    discard pool.payload_attestation_messages.popFirst()
  pool.payload_attestation_messages.addLast(msg)

func addMessage*(
    pool: var ValidatorChangePool, 
    msg: SignedExecutionPayloadEnvelope) =
  let 
    msgHash = hash_tree_root(msg)
    blockRoot = msg.message.beacon_block_root
  
  # Track as seen
  pool.prior_seen_execution_payload_envelopes.incl(msgHash)
  
  pool.execution_payload_envelopes[blockRoot] = msg

func addMessage*(
    pool: var ValidatorChangePool, 
    msg: phase0.AttesterSlashing) =
  for idx in getValidatorIndices(msg):
    pool.prior_seen_attester_slashed_indices.incl idx
    if not pool.attestationPool.isNil:
      let i = ValidatorIndex.init(idx).valueOr:
        continue
      pool.attestationPool.forkChoice.process_equivocation(i)

  pool.phase0_attester_slashings.addValidatorChangeMessage(
    pool.prior_seen_attester_slashed_indices, msg, ATTESTER_SLASHINGS_BOUND)

func addMessage*(
    pool: var ValidatorChangePool,
    msg: electra.AttesterSlashing) =
  for idx in getValidatorIndices(msg):
    pool.prior_seen_attester_slashed_indices.incl idx
    if not pool.attestationPool.isNil:
      let i = ValidatorIndex.init(idx).valueOr:
        continue
      pool.attestationPool.forkChoice.process_equivocation(i)

  pool.electra_attester_slashings.addValidatorChangeMessage(
    pool.prior_seen_attester_slashed_indices, msg, ATTESTER_SLASHINGS_BOUND)

func addMessage*(
    pool: var ValidatorChangePool, 
    msg: ProposerSlashing) =
  pool.prior_seen_proposer_slashed_indices.incl(
    msg.signed_header_1.message.proposer_index)
  pool.proposer_slashings.addValidatorChangeMessage(
    pool.prior_seen_proposer_slashed_indices, msg, PROPOSER_SLASHINGS_BOUND)

func addMessage*(
    pool: var ValidatorChangePool, 
    msg: SignedVoluntaryExit) =
  pool.prior_seen_voluntary_exit_indices.incl(
    msg.message.validator_index)
  pool.voluntary_exits.addValidatorChangeMessage(
    pool.prior_seen_voluntary_exit_indices, msg, VOLUNTARY_EXITS_BOUND)

func addMessage*(
    pool: var ValidatorChangePool, msg: SignedBLSToExecutionChange,
    localPriorityMessage: bool) =
  pool.prior_seen_bls_to_execution_change_indices.incl(
    msg.message.validator_index)
  template addMessageAux(subpool) =
    addValidatorChangeMessage(
      subpool, pool.prior_seen_bls_to_execution_change_indices, msg,
      BLS_TO_EXECUTION_CHANGES_BOUND)
  if localPriorityMessage:
    addMessageAux(pool.bls_to_execution_changes_api)
  else:
    addMessageAux(pool.bls_to_execution_changes_gossip)

proc validateValidatorChangeMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState, msg: ProposerSlashing): bool =
  check_proposer_slashing(state, msg, {}).isOk
proc validateValidatorChangeMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState, msg:
    phase0.AttesterSlashing | electra.AttesterSlashing): bool =
  check_attester_slashing(state, msg, {}).isOk
proc validateValidatorChangeMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState, msg: SignedVoluntaryExit):
    bool =
  check_voluntary_exit(cfg, state, msg, {}).isOk
proc validateValidatorChangeMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState,
    msg: SignedBLSToExecutionChange): bool =
  check_bls_to_execution_change(cfg.genesisFork, state, msg, {}).isOk

# EIP-7732 validation functions 
proc validateValidatorChangeMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState,
    msg: SignedExecutionPayloadHeader): bool =
  when typeof(state).kind >= ConsensusFork.Fulu:
    if msg.message.builder_index >= state.validators.lenu64:
      return false
    let builderValidator = state.validators.asSeq[msg.message.builder_index]
    if builderValidator.slashed:
      return false
    if not is_active_validator(builderValidator, get_current_epoch(state)):
      return false
    true
  else:
    false

proc validateValidatorChangeMessage(
    cfg: RuntimeConfig, state: ForkyBeaconState,
    msg: PayloadAttestationMessage): bool =
  when typeof(state).kind >= ConsensusFork.Fulu:
    if msg.data.payload_status >= PAYLOAD_INVALID_STATUS.uint8:
      return false
    var cache = StateCache()
    let ptc = get_ptc(state, msg.data.slot, cache)
    if msg.validatorIndex notin ptc:
      return false
    true
  else:
    false

proc getValidatorChangeMessagesForBlock(
    subpool: var Deque, cfg: RuntimeConfig, state: ForkyBeaconState,
    seen: var HashSet, output: var List) =
  while subpool.len > 0 and output.len < output.maxLen:
    let validator_change_message = subpool.popLast()
    if not validateValidatorChangeMessage(cfg, state, validator_change_message):
      continue

    var skip = false
    for slashed_index in getValidatorIndices(validator_change_message):
      if seen.containsOrIncl(slashed_index):
        skip = true
        break
    if skip:
      continue

    if not output.add validator_change_message:
      break

proc getBeaconBlockValidatorChanges*(
    pool: var ValidatorChangePool, cfg: RuntimeConfig, state: ForkyBeaconState):
    BeaconBlockValidatorChanges =
  var
    indices: HashSet[uint64]
    res: BeaconBlockValidatorChanges

  getValidatorChangeMessagesForBlock(
    pool.phase0_attester_slashings, cfg, state, indices,
    res.phase0_attester_slashings)
  getValidatorChangeMessagesForBlock(
    pool.proposer_slashings, cfg, state, indices, res.proposer_slashings)
  getValidatorChangeMessagesForBlock(
    pool.voluntary_exits, cfg, state, indices, res.voluntary_exits)

  when typeof(state).kind >= ConsensusFork.Capella:
    getValidatorChangeMessagesForBlock(
      pool.bls_to_execution_changes_api, cfg, state, indices,
      res.bls_to_execution_changes)
    getValidatorChangeMessagesForBlock(
      pool.bls_to_execution_changes_gossip, cfg, state, indices,
      res.bls_to_execution_changes)

  when typeof(state).kind >= ConsensusFork.Electra:
    getValidatorChangeMessagesForBlock(
      pool.electra_attester_slashings, cfg, state, indices,
      res.electra_attester_slashings)

  when typeof(state).kind >= ConsensusFork.Fulu:
    # Get execution payload header for block
    if pool.execution_payload_headers.len > 0:
      let header = pool.execution_payload_headers.peekLast()
      if validateValidatorChangeMessage(cfg, state, header):
        when compiles(res.signed_execution_payload_header):
          res.signed_execution_payload_header = some(header)

    when compiles(res.payload_attestations):
      getValidatorChangeMessagesForBlock(
        pool.payload_attestation_messages, cfg, state, indices,
        res.payload_attestations)

  res
