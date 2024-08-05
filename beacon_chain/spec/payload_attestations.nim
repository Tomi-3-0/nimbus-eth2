# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/algorithm,
  sets,
  sequtils,
  "."/[forks, ptc_status],
  ./datatypes/[phase0, altair, bellatrix], ./helpers

type

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#payloadattestationdata
  PayloadAttestationData* = object
    beaconBlockRoot*: Eth2Digest
    slot*: Slot
    payload_Status*: uint8

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#payloadattestation
  PayloadAttestation* = object
    aggregation_bits*: ElectraCommitteeValidatorsBits
    data*: PayloadAttestationData
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#payloadattestationmessage
  PayloadAttestationMessage* = object
    validatorIndex: ValidatorIndex
    data: PayloadAttestationData
    signature: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#indexedpayloadattestation
  IndexedPayloadAttestation* = object
    attestingIndices: List[ValidatorIndex, Limit PTC_SIZE]
    data: PayloadAttestationData
    signature: ValidatorSig

# https://github.com/ethereum/consensus-specs/blob/1508f51b80df5488a515bfedf486f98435200e02/specs/_features/eipxxxx/beacon-chain.md#predicates
proc is_valid_indexed_payload_attestation(
    state: capella.BeaconState, # [TODO] to be replaced with epbs.BeaconState
    indexed_payload_attestation: IndexedPayloadAttestation): bool =
  # Check if ``indexed_payload_attestation`` is not empty, has sorted and unique indices, and has a valid aggregate signature.

  # Verify that data is valid
  if indexed_payload_attestation.data.payload_Status >= uint8(PAYLOAD_INVALID_STATUS):
    return false

  # Verify indices are sorted and unique
  let indices = indexed_payload_attestation.attestingIndices

  if indices.len == 0:
    return false

  let indicesSeq = indices.toSeq()
  let indicesSet = toHashSet(indicesSeq)

  # Check if all indices are sorted and unique
  if indicesSet.len != indicesSeq.len or indicesSeq != indicesSeq.sorted:
    return false

  # Check if the indices are sorted
  if indicesSeq != indicesSeq.sorted:
    return false

  # Verify aggregate signature
  let pubkeys = mapIt(
      indexed_payload_attestation.attestingIndices, state.validators[it].pubkey)

  let domain = get_domain(
    state.fork, DOMAIN_PTC_ATTESTER, GENESIS_EPOCH, state.genesis_validators_root)

  let signing_root = compute_signing_root(indexed_payload_attestation.data, domain)

  return blsFastAggregateVerify(pubkeys, signing_root.data, indexed_payload_attestation.signature)
