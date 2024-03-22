import
  std/os,
  chronos,
  stew/io2,
  ./validators/beacon_validators,
  "."/[
    beacon_node,
    nimbus_binary_common]

proc init(T: type BeaconNode,
          config: BeaconNodeConf,
          cfg: RuntimeConfig): Future[BeaconNode]
         {.async.} =
  let node = BeaconNode(
    cfg: cfg)

  node

from "."/consensus_object_pools/block_dag import BlockRef, init
import "."/spec/digest

func getBlockRef2(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0.Slot)
  return ok(newRef)

import "."/el/el_manager

proc start(node: BeaconNode) {.raises: [CatchableError].} =
  echo "foo"
  let elManager = default(ELManager)
  elManager.start()
  let
    wallTime = node.beaconClock.now()

  asyncSpawn runSlotLoop(node, wallTime)

  while true:
    poll()

when isMainModule:
  import
    confutils,
    ../beacon_chain/conf
  const
    dataDir = "./test_keymanager_api"
    nodeDataDir = dataDir / "node-0"
    nodeValidatorsDir = nodeDataDir / "validators"
    nodeSecretsDir = nodeDataDir / "secrets"

  proc startBeaconNode() {.raises: [CatchableError].} =
    #copyHalfValidators(nodeDataDir, true)
  
    let runNodeConf = try: BeaconNodeConf.load(cmdLine = @[
      "--network=" & dataDir,
      "--data-dir=" & nodeDataDir,
      "--validators-dir=" & nodeValidatorsDir,
      "--secrets-dir=" & nodeSecretsDir,
      "--no-el"])
    except Exception as exc: # TODO fix confutils exceptions
      raiseAssert exc.msg
  
    let
      cfg = RuntimeConfig(ALTAIR_FORK_EPOCH: 0.Epoch, BELLATRIX_FORK_EPOCH: 0.Epoch, CAPELLA_FORK_EPOCH: FAR_FUTURE_EPOCH)
      node = waitFor BeaconNode.init(runNodeConf, cfg)
  
    node.start()
  
  startBeaconNode()
