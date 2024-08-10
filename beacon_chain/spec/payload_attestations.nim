# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  sequtils, sets,
  "."/[forks, ptc_status, validator],
  ./helpers,
  ./datatypes/epbs

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#predicates
proc is_valid_indexed_payload_attestation(
    state: epbs.BeaconState,
    indexed_payload_attestation: IndexedPayloadAttestation): bool =

  # Verify that data is valid
  if indexed_payload_attestation.data.payload_status >=
      uint8(PAYLOAD_INVALID_STATUS):
    return false
    ## Check if ``indexed_attestation`` is not empty, has sorted and unique
    ## indices and has a valid aggregate signature.

  template is_sorted_and_unique(s: untyped): bool =
    var res = true
    for i in 1 ..< s.len:
      if s[i - 1].uint64 >= s[i].uint64:
        res = false
        break
    res

  if len(indexed_payload_attestation.attesting_indices) == 0:
    return false

  # Check if ``indexed_payload_attestation`` is has sorted and unique
  if not is_sorted_and_unique(indexed_payload_attestation.attesting_indices):
    return false

  # Verify aggregate signature
  let pubkeys = mapIt(
      indexed_payload_attestation.attesting_indices, state.validators[it].pubkey)

  let domain = get_domain(
    state.fork, DOMAIN_PTC_ATTESTER, GENESIS_EPOCH,
    state.genesis_validators_root)

  let signing_root = compute_signing_root(
    indexed_payload_attestation.data, domain)

  blsFastAggregateVerify(pubkeys, signing_root.data,
      indexed_payload_attestation.signature)

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#is_parent_block_full
func is_parent_block_full(state: epbs.BeaconState): bool =
  state.latest_execution_payload_header.block_hash == state.latest_block_hash

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#get_ptc
proc get_ptc(state: var ForkyBeaconState, slot: Slot): List[
    ValidatorIndex, Limit PTC_SIZE] =
  let
    epoch = epoch(slot)
    committees_per_slot = bit_floor(min(get_committee_count_per_slot(
        state, epoch), PTC_SIZE))
    members_per_committee = (PTC_SIZE div committees_per_slot)

  var validator_indices: seq[ValidatorIndex] = @[]

  for committee_idx in 0..<committees_per_slot:
    let beacon_committee = get_beacon_committee(state, slot, committee_idx)
    validator_indices.add(beacon_committee[0..<min(members_per_committee,
        beacon_committee.len)])

  return validator_indices

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#modified-get_attesting_indices
proc get_attesting_indices(state: var ForkyBeaconState,
    attestation: epbs.Attestation): HashSet[ValidatorIndex] =
  var
    output = initHashSet[ValidatorIndex]()
    committee_offset = 0

  for index in get_committee_indices(attestation.committee_bits):
    let
      committee = get_beacon_committee(state, attestation.data.slot, index)
      committee_attesters = initHashSet[ValidatorIndex]()

    for i, validator_index in committee.pairs:
      if attestation.aggregation_bits[committee_offset + i]:
        committee_attesters.incl(validator_index)

    output.incl(committee_attesters)
    committee_offset += len(committee)

  let
    ptc = get_ptc(state, attestation.data.slot)

  result = output.filterIt(it notin ptc)

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#get_payload_attesting_indices
proc get_payload_attesting_indices(state: var ForkyBeaconState, slot: Slot,
    payload_attestation: PayloadAttestation): HashSet[
        ValidatorIndex] =

  let
    ptc = get_ptc(state, slot)
    output = initHashSet[ValidatorIndex]()

  for i, index in ptc.pairs:
    if payload_attestation.aggregation_bits[i]:
      output.incl(index)

  result = output

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#get_indexed_payload_attestation
proc get_indexed_payload_attestation(state: var ForkyBeaconState, slot: Slot,
    payload_attestation: PayloadAttestation): IndexedPayloadAttestation =

  let attesting_indices = get_payload_attesting_indices(
    state, slot, payload_attestation)

  result = IndexedPayloadAttestation(
    attesting_indices: attesting_indices.toSeq().sorted(),
    data: payload_attestation.data,
    signature: payload_attestation.signature
  )