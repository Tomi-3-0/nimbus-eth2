# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Mainnet preset - eIP7732
# https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7732/p2p-interface.md#preset
const
  KZG_COMMITMENT_INCLUSION_PROOF_DEPTH_EIP7732* = 21
