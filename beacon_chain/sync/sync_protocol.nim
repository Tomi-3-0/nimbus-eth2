import
  chronicles, chronos, snappy, snappy/codec,
  ../spec/datatypes/[phase0, altair, bellatrix, capella, deneb],
  ../spec/[helpers, forks, network],
  ".."/[beacon_clock],
  ../networking/eth2_network

type
  BeaconSyncNetworkState* {.final.} = ref object of RootObj
    cfg: RuntimeConfig
    genesisBlockRoot: Eth2Digest

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type (ref uint64)):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} = discard

p2pProtocol BeaconSync(version = 1,
                       networkState = BeaconSyncNetworkState):
  proc beaconBlocksByRange_v2(
      peer: Peer,
      startSlot: Slot,
      reqCount: uint64,
      reqStep: uint64,
      response: MultipleChunksResponse[
        ref uint64, Limit MAX_REQUEST_BLOCKS])
      {.async, libp2pProtocol("beacon_blocks_by_range", 2).} = discard
