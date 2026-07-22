import { bytesToBigIntBE, decodeCanonicalFieldHex } from "../core/crypto.js";
import { computeNoteTreeNodeV1, fieldHexV1 } from "./protocol-v1.js";

export const commitmentPathSnapshotDepthV1 = 32;
export const commitmentPathSnapshotMaxCommitmentsV1 = 16;

function sameValues(left, right) {
  if (left instanceof Uint8Array && right instanceof Uint8Array) {
    return left.length === right.length && left.every((value, index) => value === right[index]);
  }
  return JSON.stringify(left) === JSON.stringify(right);
}

function aliasedValue(input, keys, label, { required = true } = {}) {
  const values = keys
    .filter(key => Object.prototype.hasOwnProperty.call(input || {}, key))
    .map(key => input[key])
    .filter(value => value !== undefined && value !== null);
  if (!values.length) {
    if (required) throw new Error(`${label} is required`);
    return undefined;
  }
  if (values.some(value => !sameValues(values[0], value))) {
    throw new Error(`${label} aliases do not match`);
  }
  return values[0];
}

function uint64(value, label) {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a non-negative safe integer, bigint, or canonical uint64 string`);
    return BigInt(value);
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > ((1n << 64n) - 1n)) throw new Error(`${label} must be within uint64 range`);
    return value;
  }
  const text = String(value ?? "");
  if (!/^(0|[1-9][0-9]*)$/.test(text)) throw new Error(`${label} must be a canonical uint64 decimal string`);
  const parsed = BigInt(text);
  if (parsed > ((1n << 64n) - 1n)) throw new Error(`${label} must be within uint64 range`);
  return parsed;
}

function uint64Value(value, label) {
  const parsed = uint64(value, label);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function nonNegativeInt64Value(value, label) {
  const parsed = uint64(value, label);
  if (parsed > ((1n << 63n) - 1n)) throw new Error(`${label} exceeds int64`);
  return parsed <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(parsed) : parsed.toString();
}

function canonicalFieldHex(value, label, { nonZero = false } = {}) {
  const hex = String(value ?? "");
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`${label} must be canonical lowercase 32-byte hex`);
  const bytes = decodeCanonicalFieldHex(hex, label);
  const field = bytesToBigIntBE(bytes);
  if (nonZero && field === 0n) throw new Error(`${label} must be a non-zero canonical field`);
  return { hex, field };
}

function helperBit(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (parsed !== 0 && parsed !== 1)) {
    throw new Error(`${label} must be 0 or 1`);
  }
  return parsed;
}

function aliasedArray(input, keys, label) {
  const value = aliasedValue(input, keys, label);
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function requestedCommitments(input = {}) {
  const values = aliasedArray(input, ["commitmentHexes", "commitment_hexes"], "commitment path commitments");
  if (!values.length || values.length > commitmentPathSnapshotMaxCommitmentsV1) {
    throw new Error(`commitment path request must contain 1..${commitmentPathSnapshotMaxCommitmentsV1} commitments`);
  }
  const commitments = values.map((value, index) => canonicalFieldHex(value, `commitment ${index}`, { nonZero: true }).hex);
  if (new Set(commitments).size !== commitments.length) throw new Error("commitment path request commitments must be distinct");
  return commitments;
}

/** Normalize the exact-root, optionally height-pinned snapshot request accepted by Clairveil. */
export function normalizeCommitmentPathsAtRootRequest(input = {}) {
  const commitmentHexes = requestedCommitments(input);
  const rootHex = canonicalFieldHex(
    aliasedValue(input, ["rootHex", "root_hex"], "commitment path root"),
    "commitment path root"
  ).hex;
  const requestedSnapshotHeight = aliasedValue(
    input,
    ["snapshotHeight", "snapshot_height"],
    "commitment path snapshot height",
    { required: false }
  );
  const snapshotHeight = requestedSnapshotHeight === undefined
    ? undefined
    : nonNegativeInt64Value(requestedSnapshotHeight, "commitment path snapshot height");
  return Object.freeze({
    commitmentHexes: Object.freeze(commitmentHexes),
    rootHex,
    ...(snapshotHeight === undefined ? {} : { snapshotHeight })
  });
}

/**
 * Validate a batched path response against the requested exact snapshot and
 * recompute every depth-32 path. The returned order is request order.
 */
export function normalizeCommitmentPathsAtRootResponse(response, request) {
  const normalizedRequest = normalizeCommitmentPathsAtRootRequest(request);
  if (!response || typeof response !== "object" || Array.isArray(response)) {
    throw new Error("commitment path snapshot response is required");
  }
  const rootHex = canonicalFieldHex(
    aliasedValue(response, ["rootHex", "root_hex"], "commitment path response root"),
    "commitment path response root"
  ).hex;
  const snapshotHeight = nonNegativeInt64Value(
    aliasedValue(response, ["snapshotHeight", "snapshot_height"], "commitment path response snapshot height"),
    "commitment path response snapshot height"
  );
  const leafCount = uint64Value(
    aliasedValue(response, ["leafCount", "leaf_count"], "commitment path response leaf count"),
    "commitment path response leaf count"
  );
  if (rootHex !== normalizedRequest.rootHex ||
      (normalizedRequest.snapshotHeight !== undefined && String(snapshotHeight) !== String(normalizedRequest.snapshotHeight))) {
    throw new Error("commitment path snapshot identity does not match the request");
  }
  if (uint64(leafCount, "commitment path response leaf count") === 0n) {
    throw new Error("commitment path response leaf count must be positive");
  }
  const responsePaths = aliasedArray(response, ["paths"], "commitment path response paths");
  if (responsePaths.length !== normalizedRequest.commitmentHexes.length) {
    throw new Error("commitment path response count does not match the request");
  }
  const leafCountBigInt = uint64(leafCount, "commitment path response leaf count");
  const paths = responsePaths.map((path, index) => {
    if (!path || typeof path !== "object" || Array.isArray(path)) {
      throw new Error(`commitment path ${index} is required`);
    }
    const commitmentHex = canonicalFieldHex(
      aliasedValue(path, ["commitmentHex", "commitment_hex"], `commitment path ${index} commitment`),
      `commitment path ${index} commitment`,
      { nonZero: true }
    ).hex;
    if (commitmentHex !== normalizedRequest.commitmentHexes[index]) {
      throw new Error(`commitment path ${index} does not preserve request order`);
    }
    const leafIndex = uint64Value(
      aliasedValue(path, ["leafIndex", "leaf_index"], `commitment path ${index} leaf index`),
      `commitment path ${index} leaf index`
    );
    if (uint64(leafIndex, `commitment path ${index} leaf index`) >= leafCountBigInt) {
      throw new Error(`commitment path ${index} leaf index is outside the snapshot`);
    }
    const siblings = aliasedArray(path, ["path"], `commitment path ${index} siblings`);
    const helpers = aliasedArray(path, ["pathHelper", "path_helper"], `commitment path ${index} helpers`);
    if (siblings.length !== commitmentPathSnapshotDepthV1 || helpers.length !== commitmentPathSnapshotDepthV1) {
      throw new Error(`commitment path ${index} must be ${commitmentPathSnapshotDepthV1} levels`);
    }
    let current = canonicalFieldHex(commitmentHex, `commitment path ${index} commitment`, { nonZero: true }).field;
    const normalizedPath = siblings.map((value, level) => {
      const sibling = canonicalFieldHex(value, `commitment path ${index} sibling ${level}`).field;
      const helper = helperBit(helpers[level], `commitment path ${index} helper ${level}`);
      current = helper === 0
        ? computeNoteTreeNodeV1(level, current, sibling)
        : computeNoteTreeNodeV1(level, sibling, current);
      return fieldHexV1(sibling);
    });
    const normalizedHelpers = helpers.map((value, level) => helperBit(value, `commitment path ${index} helper ${level}`));
    if (fieldHexV1(current) !== rootHex) {
      throw new Error(`commitment path ${index} does not reconstruct the requested snapshot root`);
    }
    return Object.freeze({
      commitment_hex: commitmentHex,
      leaf_index: leafIndex,
      path: Object.freeze(normalizedPath),
      path_helper: Object.freeze(normalizedHelpers)
    });
  });
  return Object.freeze({
    root_hex: rootHex,
    snapshot_height: snapshotHeight,
    leaf_count: leafCount,
    paths: Object.freeze(paths)
  });
}

/** Create a lookupMerklePath-compatible provider pinned to one verified snapshot. */
export function createCommitmentPathSnapshotProvider(snapshot) {
  if (!snapshot || typeof snapshot !== "object") throw new Error("verified commitment path snapshot is required");
  const paths = new Map((snapshot.paths || []).map(path => [String(path.commitment_hex || "").toLowerCase(), path]));
  if (!paths.size) throw new Error("verified commitment path snapshot must include paths");
  const root = String(snapshot.root_hex || "").toLowerCase();
  const snapshotHeight = snapshot.snapshot_height;
  return Object.freeze({
    async lookupMerklePath(commitmentHex) {
      const key = canonicalFieldHex(commitmentHex, "requested commitment", { nonZero: true }).hex;
      const path = paths.get(key);
      if (!path) throw new Error("requested commitment is not in the verified path snapshot");
      return Object.freeze({
        root,
        path: [...path.path],
        path_helper: [...path.path_helper],
        leaf_index: path.leaf_index,
        snapshot_height: snapshotHeight
      });
    }
  });
}
