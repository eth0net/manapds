// Regenerates tests/fixtures/sequencer/account.json: the four log entries the
// reference writes when an account is created, encoded by the reference itself.
//
// The commit is not signed here. It is read from the commit fixture, so the
// two describe the same repository and moving one moves the other.
//
//     npm install @atproto/repo @atproto/common multiformats @ipld/dag-cbor
//     node tools/sequencer-fixture.mjs > tests/fixtures/sequencer/account.json

import { readFileSync } from 'node:fs'
import * as dagCbor from '@ipld/dag-cbor'
import { cborEncode } from '@atproto/common'
import { BlockMap, blocksToCarFile } from '@atproto/repo'
import * as Block from 'multiformats/block'
import { CID } from 'multiformats/cid'
import { sha256 } from 'multiformats/hashes/sha2'

const COMMIT = 'tests/fixtures/commit/golden.json'
const HANDLE = 'alice.test'

const golden = JSON.parse(readFileSync(process.argv[2] ?? COMMIT, 'utf8'))
const hex = (bytes) => Buffer.from(bytes).toString('hex')

const commitBytes = Buffer.from(golden.block, 'hex')
const { cid: commit } = await Block.decode({
  bytes: commitBytes,
  codec: dagCbor,
  hasher: sha256,
})

// The tree a first commit points at, which holds nothing.
const mstBytes = dagCbor.encode({ e: [], l: null })
const mst = CID.createV1(dagCbor.code, await sha256.digest(mstBytes))
if (mst.toString() !== golden.data) {
  throw new Error(`empty tree hashes to ${mst}, commit fixture says ${golden.data}`)
}

// formatInitCommit leaves newBlocks and relevantBlocks the same map, and a
// signup writes no records, so both hold the tree root and the commit.
const written = new BlockMap()
written.set(mst, mstBytes)
written.set(commit, commitBytes)

// syncEvtDataFromCommit takes the commit block back out on its own.
const only = new BlockMap()
only.set(commit, commitBytes)

const { did, rev } = golden
console.log(
  JSON.stringify(
    {
      did,
      handle: HANDLE,
      rev,
      commit: commit.toString(),
      commitBlock: golden.block,
      tree: mst.toString(),
      treeBlock: hex(mstBytes),
      identity: hex(cborEncode({ did, handle: HANDLE })),
      account: hex(cborEncode({ did, active: true })),
      append: hex(
        cborEncode({
          repo: did,
          commit,
          rev,
          since: null,
          blocks: await blocksToCarFile(commit, written),
          ops: [],
          prevData: undefined,
          rebase: false,
          tooBig: false,
          blobs: [],
        }),
      ),
      sync: hex(
        cborEncode({ did, rev, blocks: await blocksToCarFile(commit, only) }),
      ),
    },
    null,
    2,
  ),
)
