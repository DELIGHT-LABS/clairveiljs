import test from "node:test";
import assert from "node:assert/strict";
import { computeNoteTreeNodeV1, fieldHexV1 } from "clairveiljs/protocol-v1";
import { normalizeCommitmentPathsAtRootResponse } from "clairveiljs/merkle-path";

function validSnapshot({ leafIndex = 5n, leafCount = 6n } = {}) {
  const commitmentHex = fieldHexV1(73n);
  const path = [];
  const pathHelper = [];
  let current = 73n;
  for (let level = 0; level < 32; level += 1) {
    const sibling = BigInt(level + 101);
    const helper = Number((leafIndex >> BigInt(level)) & 1n);
    path.push(fieldHexV1(sibling));
    pathHelper.push(helper);
    current = helper === 0
      ? computeNoteTreeNodeV1(level, current, sibling)
      : computeNoteTreeNodeV1(level, sibling, current);
  }
  const rootHex = fieldHexV1(current);
  return {
    request: { commitmentHexes: [commitmentHex], rootHex },
    response: {
      rootHex,
      snapshotHeight: 22,
      leafCount,
      paths: [{ commitmentHex, leafIndex, path, pathHelper }]
    }
  };
}

test("commitment path snapshots bind path helpers to the reported leaf index", () => {
  const { request, response } = validSnapshot();
  assert.equal(normalizeCommitmentPathsAtRootResponse(response, request).paths[0].leaf_index, 5);

  const mismatchedIndex = structuredClone(response);
  mismatchedIndex.paths[0].leafIndex = 4;
  assert.throws(
    () => normalizeCommitmentPathsAtRootResponse(mismatchedIndex, request),
    /does not match leaf index/
  );

  const oversizedLeafCount = structuredClone(response);
  oversizedLeafCount.leafCount = (1n << 32n) + 1n;
  assert.throws(
    () => normalizeCommitmentPathsAtRootResponse(oversizedLeafCount, request),
    /exceeds the depth-32 tree capacity/
  );
});
