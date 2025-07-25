# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos,
  chronicles,
  ../spec/[
    eth2_merkleization, forks, helpers, signatures, 
    state_transition, validator],
  ../consensus_object_pools/[
    spec_cache, blockchain_dag, validator_change_pool],
  ./validator_pool,
  ../beacon_node

logScope: topics = "builder"

proc gatherBuilderBids*(
    node: BeaconNode,
    slot: Slot,
    parentBlockRoot: Eth2Digest
): Future[seq[SignedExecutionPayloadHeader]] {.async: (raises: [CancelledError]).} =
  # Get all bids from the pool for this slot
  var validBids: seq[SignedExecutionPayloadHeader]
 
  # The bids should already be in the pool from gossip
  for bid in node.validatorChangePool[].execution_payload_headers:
    if bid.message.slot == slot and
       bid.message.parent_block_root == parentBlockRoot:
      validBids.add(bid)
 
  # Remove old bids from pool (cleanup)
  var newDeque = initDeque[SignedExecutionPayloadHeader]()
  for bid in node.validatorChangePool[].execution_payload_headers:
    if bid.message.slot >= slot:
      newDeque.addLast(bid)
  node.validatorChangePool[].execution_payload_headers = newDeque
 
  info "Gathered builder bids",
    slot = slot,
    parent_block_root = shortLog(parentBlockRoot),
    bid_count = validBids.len
 
  return validBids

proc broadcastLocalPayloadEnvelope*(
    node: BeaconNode,
    slot: Slot,
    beaconBlockRoot: Eth2Digest,
    builderIndex: ValidatorIndex
) {.async.} =
  # Wait for interval at T_2 (4s) - builder honest reveal deadline
  let
    slotStart = slot.start_beacon_time()
    builderRevealTime = slotStart + seconds(4)
  
  await sleepAsync(nanoseconds(
    int64(builderRevealTime.ns_since_genesis - now(
      node.beaconClock).ns_since_genesis)))

  debug "Broadcasting envelope at T_2 (builder reveal time)",
    slot = slot,
    builderIndex = builderIndex,
    currentTime = now(node.beaconClock),
    targetTime = builderRevealTime,
    blockRoot = shortLog(beaconBlockRoot)
  
  # Get cached payload
  let cachedPayload = node.payloadCache.getOrDefault(slot)
  if cachedPayload.executionPayload.block_hash == default(Eth2Digest):
    warn "No payload cached for slot", slot
    return
  
  # Get state at beacon block
  let blockRef = node.dag.getBlockRef(beaconBlockRoot).valueOr:
    warn "Beacon block not found", blockRoot = shortLog(beaconBlockRoot)
    return
  
  var tmpState = assignClone(node.dag.headState)
  var cache = StateCache()
  
  if not node.dag.updateState(
      tmpState[], blockRef.atSlot(slot).toBlockSlotId().expect("not nil"), 
      false, cache, node.dag.updateFlags):
    warn "Failed to update state for envelope", slot, builder_index
    return
  
  let
    stateRoot = withState(tmpState[]):
      hash_tree_root(forkyState.data)
    
    envelope = fulu.ExecutionPayloadEnvelope(
      payload: cachedPayload.executionPayload,
      execution_requests: 
        node.executionRequestsCache.getOrDefault(slot, default(ExecutionRequests)),
      builder_index: builderIndex.uint64,
      beacon_block_root: beaconBlockRoot,
      blob_kzg_commitments: cachedPayload.blobsBundle.commitments,
      payload_withheld: false,
      state_root: stateRoot,
      slot: slot
    )
  
  # Sign envelope
  let envelopeSignature = withState(tmpState[]):
    when consensusFork >= ConsensusFork.Fulu:
      let
        fork = forkyState.data.fork
        genesis_validators_root = forkyState.data.genesis_validators_root
        domain = get_domain(fork, DOMAIN_BEACON_BUILDER, slot.epoch, 
                          genesis_validators_root)
        signing_root = compute_signing_root(envelope, domain)
        validator = node.attachedValidators[].getValidator(
          forkyState.data.validators.asSeq[builderIndex].pubkey).valueOr:
            warn "Validator not found for envelope signing"
            return
      
      if validator.kind == ValidatorKind.Local:
        let sig = blsSign(validator.data.privateKey, signing_root.data)
        sig.toValidatorSig()
      else:
        warn "Remote validator signing not implemented for envelopes"
        return
    else:
      return
  
  let signedEnvelope = fulu.SignedExecutionPayloadEnvelope(
    message: envelope,
    signature: envelopeSignature
  )
  
  # Broadcast envelope
  let sendResult = await node.network.broadcastExecutionPayloadEnvelope(
    signedEnvelope)
  
  if sendResult.isOk:
    notice "Execution payload envelope broadcasted",
      slot, builder_index = builderIndex,
      blockRoot = shortLog(beaconBlockRoot),
      payloadHash = shortLog(envelope.payload.block_hash),
      stateRoot = shortLog(stateRoot)
  else:
    warn "Failed to broadcast execution payload envelope",
      slot, builder_index = builderIndex, error = sendResult.error
  
  # Clean up cache
  node.payloadCache.del(slot)
  node.executionRequestsCache.del(slot)