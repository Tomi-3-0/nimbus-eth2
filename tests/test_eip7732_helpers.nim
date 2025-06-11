# beacon_chain
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[forks, signatures, state_transition, validator,
    beaconstate, eth2_merkleization],
  ../beacon_chain/spec/[helpers, eip7732_helpers],
  ../beacon_chain/spec/datatypes/fulu

from stew/bitops2 import log2trunc, nextPow2

suite "EIP-7732 Unit Tests":

  test "bit_floor calculations":
    check:
      bit_floor(0'u64) == 0'u64
      bit_floor(1'u64) == 1'u64
      bit_floor(2'u64) == 2'u64
      bit_floor(3'u64) == 2'u64
      bit_floor(4'u64) == 4'u64
      bit_floor(5'u64) == 4'u64
      bit_floor(6'u64) == 4'u64
      bit_floor(7'u64) == 4'u64
      bit_floor(9'u64) == 8'u64

  test "remove_flag operations":
    let flags = ParticipationFlags(0b111)
    check:
      remove_flag(flags, TimelyFlag(0)) == ParticipationFlags(0b110)
      remove_flag(flags, TimelyFlag(1)) == ParticipationFlags(0b101)
      remove_flag(flags, TimelyFlag(2)) == ParticipationFlags(0b011)
      
  test "EIP-7732 blob sidecar gindex calculation":

    const
      EXPECTED_SIGNED_HEADER_GINDEX = GeneralizedIndex(26)  # 2^4 + 10
      EXPECTED_MESSAGE_GINDEX = GeneralizedIndex(2)  # 2^1 + 0
      EXPECTED_BLOB_ROOT_GINDEX = GeneralizedIndex(15)  # 2^3 + 7
  
    let 
      step1 = GeneralizedIndex(1 * 16 + 10)
      
      step2 = GeneralizedIndex(26 * 2 + 0)
      
      step3 = GeneralizedIndex(52 * 8 + 7)
    
    let
      blob_list_depth = log2trunc(nextPow2(MAX_BLOB_COMMITMENTS_PER_BLOCK))
      blob_0_in_list = GeneralizedIndex(1'u64 shl blob_list_depth)  # 2^depth + 0
      
      expected_final = GeneralizedIndex(423) * blob_0_in_list

    for index in 0'u64..3'u64:
      let gindex = kzg_commitment_inclusion_proof_gindex_eip7732(index)
      
      if index > 0:
        let prev_gindex = kzg_commitment_inclusion_proof_gindex_eip7732(index - 1)
        check gindex == prev_gindex + 1
    
    let gindex_0 = kzg_commitment_inclusion_proof_gindex_eip7732(0)
    let calculated_depth = log2trunc(gindex_0)
    
    check:
      calculated_depth == KZG_COMMITMENT_INCLUSION_PROOF_DEPTH_EIP7732
      
      gindex_0 > 0.GeneralizedIndex
      gindex_0 < (1.GeneralizedIndex shl 32)
      
      kzg_commitment_inclusion_proof_gindex_eip7732(1) == gindex_0 + 1
      kzg_commitment_inclusion_proof_gindex_eip7732(2) == gindex_0 + 2
      
      gindex_0 == expected_final

  test "EIP-7732 blob sidecar verification mock":
    var blob_sidecar = fulu.BlobSidecar(
      index: 0,
      blob: default(Blob),
      kzg_commitment: default(KzgCommitment),
      kzg_proof: default(KzgProof),
      signed_block_header: default(SignedBeaconBlockHeader)
    )
    
    blob_sidecar.kzg_commitment_inclusion_proof = 
      default(array[KZG_COMMITMENT_INCLUSION_PROOF_DEPTH_EIP7732, Eth2Digest])
    let expected_gindex = kzg_commitment_inclusion_proof_gindex_eip7732(0)  
    
    check:
      expected_gindex == 
        kzg_commitment_inclusion_proof_gindex_eip7732(blob_sidecar.index)
      
      kzg_commitment_inclusion_proof_gindex_eip7732(1) != expected_gindex
      kzg_commitment_inclusion_proof_gindex_eip7732(2) != expected_gindex