# beacon_chain
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  "."/[forks, validator],
  ./datatypes/fulu,
  "."/[
  beaconstate, eth2_merkleization, helpers, signatures,
  state_transition_epoch],
  bitops
import std/[lists, sequtils]

func bit_length(n: SomeInteger): SomeInteger =
  # Returns the number of bits required to represent `n`.
  if n == 0:
    return 1
  else:
    return uint64(fastLog2(n) + 1)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#bit_floor
func bit_floor*(n: uint64): uint64 =
  if n == 0:
    return 0'u64
  return 1'u64 shl (n.bit_length() - 1)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#remove_flag
func remove_flag*(flags: ParticipationFlags,
    flag_index: TimelyFlag): ParticipationFlags =
  let flag = ParticipationFlags(1'u8 shl ord(flag_index))
  flags and not flag

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#is_valid_indexed_payload_attestation
proc is_valid_indexed_payload_attestation*(
    state: fulu.BeaconState,
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

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#get_ptc
proc get_ptc*(state: fulu.BeaconState, slot: Slot, cache: var StateCache): seq[ValidatorIndex] =
  let
    epoch = epoch(slot)
    committees_per_slot = bit_floor(min(get_committee_count_per_slot(
        state, epoch, cache), PTC_SIZE))
    members_per_committee = (PTC_SIZE div committees_per_slot)

  var validator_indices = newSeq[ValidatorIndex](PTC_SIZE)

  for committee_index in get_committee_indices(committees_per_slot):
    let beacon_committee = get_beacon_committee(state, slot, committee_index, cache)
    validator_indices.add(beacon_committee[0 ..< members_per_committee])

  validator_indices

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-get_attesting_indices
proc get_attesting_indices*(state: fulu.BeaconState,
    attestation: fulu.Attestation, cache: var StateCache, 
    cfg: RuntimeConfig): HashSet[ValidatorIndex] =

  var
    output: HashSet[ValidatorIndex]
    committee_offset = 0

  for committee_index in get_committee_indices(attestation.committee_bits):
    let committee = get_beacon_committee(state, attestation.data.slot, committee_index, cache)

    var committee_attesters: HashSet[ValidatorIndex]
    for i, validator_index in committee:
      if attestation.aggregation_bits[committee_offset + i]:
        committee_attesters.incl(validator_index)

    # Merge the current committee_attesters set with 
    # the overall output set of attesting validators
    output.incl(committee_attesters)

    committee_offset += len(committee)

  if epoch(attestation.data.slot) < cfg.FULU_FORK_EPOCH:
    return output

  let ptc = get_ptc(state, attestation.data.slot, cache)
  return output - ptc.toHashSet()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#get_payload_attesting_indices
proc get_payload_attesting_indices*(state: fulu.BeaconState, slot: Slot,
    payload_attestation: fulu.PayloadAttestation, 
    cache: var StateCache): List[ValidatorIndex, Limit PTC_SIZE] =

  let ptc = get_ptc(state, slot, cache)
  var output: List[ValidatorIndex, Limit PTC_SIZE]

  for i, index in ptc.pairs:
    if payload_attestation.aggregation_bits[i]:
      discard output.add(index)

  output

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#get_indexed_payload_attestation
proc get_indexed_payload_attestation*(state: var fulu.BeaconState, slot: Slot,
    payload_attestation: PayloadAttestation, 
    cache: var StateCache): IndexedPayloadAttestation =

  let attesting_indices = get_payload_attesting_indices(
    state, slot, payload_attestation, cache)

template sort_and_unique(s: var List[ValidatorIndex, Limit PTC_SIZE]
    ): List[ValidatorIndex, Limit PTC_SIZE] =
  s.sort()
  
  var unique_list: List[ValidatorIndex]
  
  for index in s:
    # Check last added element for uniqueness
    if unique_list.len == 0 or unique_list[^1] != index:
      discard uniqueList.add(index)
  unique_list

  IndexedPayloadAttestation(
    attesting_indices: sort_and_unique(attesting_indices),
    data: payload_attestation.data,
    signature: payload_attestation.signature
  )

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/validator.md#validator-assignment
proc get_ptc_assignment*(state: fulu.BeaconState, epoch: Epoch, cache: var StateCache,
    validator_index: ValidatorIndex): Opt[Slot] =
  
  let 
    start_slot = start_slot(epoch)
    next_epoch = get_current_epoch(state) + 1
  doAssert epoch <= next_epoch
  
  for slot in start_slot .. start_slot + SLOTS_PER_EPOCH - 1:
    if validator_index in get_ptc(state, slot, cache):
        return Opt.some slot 
  return Opt.none(Slot) 

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#is_parent_block_full
func is_parent_block_full*(state: fulu.BeaconState): bool =
#   return state.latest_execution_payload_header.block_hash ==
#       state.latest_block_hash
  return true # this is a placeholder

func get_payload_proposer_reward*(reward_numerator: Gwei): Gwei =
  const proposer_reward_denominator = 
    (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR div PROPOSER_WEIGHT
  Gwei(reward_numerator.uint64 div proposer_reward_denominator)

func get_payload_proposer_penalty*(penalty_numerator: Gwei): Gwei =
  const proposer_reward_denominator = 
    (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR div PROPOSER_WEIGHT
  Gwei(2 * penalty_numerator.uint64 div proposer_reward_denominator)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#process_payload_attestation
proc process_payload_attestation*(
   state: var fulu.BeaconState,
   payload_attestation: PayloadAttestation,
   cache: var StateCache): Result[void, cstring] =
 
 # Check that the attestation is for the parent beacon block
 let data = payload_attestation.data
 if not (data.beacon_block_root == state.latest_block_header.parent_root):
   return err("process_payload_attestation: beacon block and latest block mismatch")
 
 # Check that the attestation is for the previous slot
 if data.slot + 1 != state.slot:
   return err("process_payload_attestation: slot mismatch")

 info "Processing payload attestation", 
  slot = data.slot,
  current_slot = state.slot,
  payload_status = data.payload_status,
  beacon_block_root = shortLog(data.beacon_block_root)
 
 
 # Verify signature
 let indexed_payload_attestation = 
   get_indexed_payload_attestation(
    state, data.slot, payload_attestation, cache)
 if not is_valid_indexed_payload_attestation(
  state, indexed_payload_attestation):
   return err("process_payload_attestation: signature verification failed")
 
 # Determine epoch participation
 let epoch_participation =
   if state.slot mod SLOTS_PER_EPOCH == 0:
     addr state.previous_epoch_participation
   else:
     addr state.current_epoch_participation
 
 # Check payload status
 let 
   payload_was_present = data.slot == state.latest_full_slot
   voted_present = data.payload_status == uint8(PAYLOAD_PRESENT)

 info "Payload attestation status check",
  payload_was_present = payload_was_present,
  voted_present = voted_present,
  latest_full_slot = state.latest_full_slot,
  matches = (voted_present == payload_was_present)
 
 let 
   proposer_index = get_beacon_proposer_index(state, cache).valueOr:
     return err("process_payload_attestation: no proposer")
   total_active_balance = get_total_active_balance(state, cache)
   base_reward_per_increment = get_base_reward_per_increment(total_active_balance)
 
 if voted_present != payload_was_present:
   # Unset flags and calculate penalties for incorrect attestation
   var proposer_penalty_numerator = 0.Gwei
   for index in indexed_payload_attestation.attesting_indices:
     for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
       if has_flag(epoch_participation[][index], flag_index):
         asList(epoch_participation[])[index] = 
           remove_flag(epoch_participation[][index], flag_index)
         proposer_penalty_numerator += 
           get_base_reward(state, index, base_reward_per_increment) * weight.uint64
   
   # Penalize proposer
   let proposer_penalty = get_payload_proposer_penalty(proposer_penalty_numerator)
   decrease_balance(state, proposer_index, proposer_penalty)
   return ok()
 
 # Set flags and calculate rewards for correct attestation
 var proposer_reward_numerator = 0.Gwei
 for index in indexed_payload_attestation.attesting_indices:
   for flag_index, weight in PARTICIPATION_FLAG_WEIGHTS:
     if not has_flag(epoch_participation[][index], flag_index):
       asList(epoch_participation[])[index] = 
         add_flag(epoch_participation[][index], flag_index)
       proposer_reward_numerator += 
         get_base_reward(state, index, base_reward_per_increment) * weight.uint64
 
 # Reward proposer
 let proposer_reward = get_payload_proposer_reward(proposer_reward_numerator)
 increase_balance(state, proposer_index, proposer_reward)
 
 ok()