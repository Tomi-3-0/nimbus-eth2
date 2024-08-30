# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Types specific to eip-7732 (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

import
  std/typetraits,
  chronicles,
  json_serialization,
  ../digest,
  "."/[base, phase0]

from kzg4844 import KzgCommitment, KzgProof
from stew/byteutils import to0xHex
from ./altair import
  EpochParticipationFlags, InactivityScores, SyncAggregate, SyncCommittee,
  TrustedSyncAggregate, num_active_participants

from ./capella import
  ExecutionBranch, HistoricalSummary, SignedBLSToExecutionChangeList,
  Withdrawal, ExecutionPayload, EXECUTION_PAYLOAD_GINDEX
from ./deneb import Blobs, BlobsBundle, KzgCommitments, KzgProofs
from ./electra import PendingBalanceDeposit, PendingPartialWithdrawal, PendingConsolidation, ElectraCommitteeValidatorsBits

export json_serialization, base, kzg4844

type

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#payloadattestationdata
  PayloadAttestationData* = object
    beacon_block_root*: Eth2Digest
    slot*: Slot
    payload_status*: uint8

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#payloadattestation
  PayloadAttestation* = object
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#payloadattestationmessage
  PayloadAttestationMessage* = object
    validatorIndex*: ValidatorIndex
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#indexedpayloadattestation
  IndexedPayloadAttestation* = object
    attesting_indices*: List[ValidatorIndex, Limit PTC_SIZE]
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#executionpayloadheader
  ExecutionPayloadHeader* = object
    # Execution block header fields
    parent_block_hash*: Eth2Digest 
    parent_block_root*: Eth2Digest
    gas_limit*: uint64
    builder_index*: uint64
    slot*: Slot
    value*: Gwei
    blob_kzg_commitments_root*: KzgCommitments

    # Extra payload fields
    block_hash*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#signedexecutionpayloadheader
  SignedExecutionPayloadHeader* = object
    message*: ExecutionPayloadHeader
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#signedexecutionpayloadenvelope
  ExecutionPayloadEnvelope* = object
    payload*: ExecutionPayload
    builder_index*: uint64
    beacon_block_root*: Eth2Digest
    blob_kzg_commitments*: List[KzgCommitment, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK]
    payload_withheld*: bool
    state_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#signedexecutionpayloadenvelope
  SignedExecutionPayloadEnvelope* = object
    message*: ExecutionPayloadEnvelope
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#beaconstate
  BeaconState* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork
    latest_block_header*: BeaconBlockHeader
    block_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    state_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    historical_roots*: HashList[Eth2Digest, Limit HISTORICAL_ROOTS_LIMIT]
    eth1_data*: Eth1Data
    eth1_data_votes*:
      HashList[Eth1Data, Limit(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)]
    eth1_deposit_index*: uint64
    validators*: HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT]
    balances*: HashList[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]
    randao_mixes*: HashArray[Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]
    slashings*: HashArray[Limit EPOCHS_PER_SLASHINGS_VECTOR, Gwei]
    previous_epoch_participation*: EpochParticipationFlags
    current_epoch_participation*: EpochParticipationFlags
    justification_bits*: JustificationBits
    previous_justified_checkpoint*: Checkpoint
    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint
    inactivity_scores*: InactivityScores
    current_sync_committee*: SyncCommittee
    next_sync_committee*: SyncCommittee
    latest_execution_payload_header*: ExecutionPayloadHeader
    next_withdrawal_index*: WithdrawalIndex
    next_withdrawal_validator_index*: uint64
    historical_summaries*:
      HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]

    deposit_requests_start_index*: uint64
    deposit_balance_to_consume*: Gwei
    exit_balance_to_consume*: Gwei
    earliest_exit_epoch*: Epoch
    consolidation_balance_to_consume*: Gwei
    earliest_consolidation_epoch*: Epoch 
    pending_balance_deposits*:
      HashList[PendingBalanceDeposit, Limit PENDING_BALANCE_DEPOSITS_LIMIT]
    pending_partial_withdrawals*:
      HashList[PendingPartialWithdrawal, Limit PENDING_PARTIAL_WITHDRAWALS_LIMIT]
    pending_consolidations*:
      HashList[PendingConsolidation, Limit PENDING_CONSOLIDATIONS_LIMIT]
    
    # [New in PBS]
    latest_block_hash*: Eth2Digest
    latest_full_slot*: Slot
    latest_withdrawals_root: Eth2Digest

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  # TODO: There should be only a single generic HashedBeaconState definition
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/phase0/beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

  SigVerifiedBeaconBlock* = object
    ## A BeaconBlock that contains verified signatures
    ## but that has not been verified for state transition

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: SigVerifiedBeaconBlockBody

  TrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: TrustedBeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[electra.Attestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: SyncAggregate
    bls_to_execution_changes*: SignedBLSToExecutionChangeList

    signed_execution_payload_header*: SignedExecutionPayloadHeader
    payload_attestations*: List[PayloadAttestation, Limit MAX_PAYLOAD_ATTESTATIONS]

    # Execution
    # execution_payload*: electra.ExecutionPayload   # [Removed in epbs]
    # blob_kzg_commitments*: KzgCommitments # [Removed in epbs]

  SigVerifiedBeaconBlockBody* = object
    ## An BeaconBlock body with signatures verified
    ## including:
    ## - Randao reveal
    ## - Attestations
    ## - ProposerSlashing (SignedBeaconBlockHeader)
    ## - AttesterSlashing (IndexedAttestation)
    ## - SignedVoluntaryExits
    ## - SyncAggregate
    ##
    ## However:
    ## - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*:
      List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: ExecutionPayload   # [Modified in Electra:EIP6110:EIP7002]
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments

  TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*:
      List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*:
      List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS_ELECTRA]
      ## [Modified in Electra:EIP7549]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: ExecutionPayload   # [Modified in Electra:EIP6110:EIP7002]
    bls_to_execution_changes*: SignedBLSToExecutionChangeList
    blob_kzg_commitments*: KzgCommitments

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/specs/phase0/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SigVerifiedSignedBeaconBlock* = object
    ## A SignedBeaconBlock with signatures verified
    ## including:
    ## - Block signature
    ## - BeaconBlockBody
    ##   - Randao reveal
    ##   - Attestations
    ##   - ProposerSlashing (SignedBeaconBlockHeader)
    ##   - AttesterSlashing (IndexedAttestation)
    ##   - SignedVoluntaryExits
    ##
    ##   - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    message*: SigVerifiedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  MsgTrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  AttestationCommitteeBits* = BitArray[MAX_COMMITTEES_PER_SLOT.int]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.3/specs/electra/beacon-chain.md#attestation
  Attestation* = object
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: AttestationData
    signature*: ValidatorSig
    committee_bits*: AttestationCommitteeBits  # [New in Electra:EIP7549]

  TrustedAttestation* = object
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: AttestationData
    signature*: TrustedSig
    committee_bits*: AttestationCommitteeBits  # [New in Electra:EIP7549]

  SomeSignedBeaconBlock* =
    SignedBeaconBlock |
    SigVerifiedSignedBeaconBlock |
    MsgTrustedSignedBeaconBlock |
    TrustedSignedBeaconBlock
  SomeBeaconBlock* =
    BeaconBlock |
    SigVerifiedBeaconBlock |
    TrustedBeaconBlock
  SomeBeaconBlockBody* =
    BeaconBlockBody |
    SigVerifiedBeaconBlockBody |
    TrustedBeaconBlockBody

  BlockContents* = object
    `block`*: BeaconBlock
    kzg_proofs*: KzgProofs
    blobs*: Blobs

# TODO: There should be only a single generic HashedBeaconState definition
func initHashedBeaconState*(s: BeaconState): HashedBeaconState =
  HashedBeaconState(data: s)

func shortLog*(v: SomeBeaconBlock): auto =
  (
    slot: shortLog(v.slot),
    proposer_index: v.proposer_index,
    parent_root: shortLog(v.parent_root),
    state_root: shortLog(v.state_root),
    eth1data: v.body.eth1_data,
    graffiti: $v.body.graffiti,
    proposer_slashings_len: v.body.proposer_slashings.len(),
    attester_slashings_len: v.body.attester_slashings.len(),
    attestations_len: v.body.attestations.len(),
    deposits_len: v.body.deposits.len(),
    voluntary_exits_len: v.body.voluntary_exits.len(),
    sync_committee_participants: v.body.sync_aggregate.num_active_participants,
    block_number: v.body.execution_payload.block_number,
    # TODO checksum hex? shortlog?
    block_hash: to0xHex(v.body.execution_payload.block_hash.data),
    parent_hash: to0xHex(v.body.execution_payload.parent_hash.data),
    fee_recipient: to0xHex(v.body.execution_payload.fee_recipient.data),
    bls_to_execution_changes_len: v.body.bls_to_execution_changes.len(),
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: ExecutionPayload): auto =
  (
    parent_hash: shortLog(v.parent_hash),
    fee_recipient: $v.fee_recipient,
    state_root: shortLog(v.state_root),
    receipts_root: shortLog(v.receipts_root),
    prev_randao: shortLog(v.prev_randao),
    block_number: v.block_number,
    gas_limit: v.gas_limit,
    gas_used: v.gas_used,
    timestamp: v.timestamp,
    extra_data: toPrettyString(distinctBase v.extra_data),
    base_fee_per_gas: $(v.base_fee_per_gas),
    block_hash: shortLog(v.block_hash),
    num_transactions: len(v.transactions),
    num_withdrawals: len(v.withdrawals),
    # blob_gas_used: $(v.blob_gas_used),
    # excess_blob_gas: $(v.excess_blob_gas)
  )

template asSigned*(
    x: SigVerifiedSignedBeaconBlock |
       MsgTrustedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigVerified*(
    x: SignedBeaconBlock |
       MsgTrustedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SigVerifiedSignedBeaconBlock =
  isomorphicCast[SigVerifiedSignedBeaconBlock](x)

template asSigVerified*(
    x: BeaconBlock | TrustedBeaconBlock): SigVerifiedBeaconBlock =
  isomorphicCast[SigVerifiedBeaconBlock](x)

template asMsgTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock |
       TrustedSignedBeaconBlock): MsgTrustedSignedBeaconBlock =
  isomorphicCast[MsgTrustedSignedBeaconBlock](x)

template asTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock |
       MsgTrustedSignedBeaconBlock): TrustedSignedBeaconBlock =
  isomorphicCast[TrustedSignedBeaconBlock](x)