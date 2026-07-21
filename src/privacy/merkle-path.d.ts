import type { Hex } from "../core/crypto.js";

export const commitmentPathSnapshotDepthV1: 32;
export const commitmentPathSnapshotMaxCommitmentsV1: 16;

export interface CommitmentPathsAtRootRequest {
  commitmentHexes?: readonly Hex[];
  commitment_hexes?: readonly Hex[];
  rootHex?: Hex;
  root_hex?: Hex;
  snapshotHeight?: number | bigint | string;
  snapshot_height?: number | bigint | string;
}

export interface VerifiedCommitmentPath {
  commitment_hex: Hex;
  leaf_index: number | string;
  path: readonly Hex[];
  path_helper: readonly (0 | 1)[];
}

export interface VerifiedCommitmentPathSnapshot {
  root_hex: Hex;
  snapshot_height: number | string;
  leaf_count: number | string;
  paths: readonly VerifiedCommitmentPath[];
}

export function normalizeCommitmentPathsAtRootRequest(input: CommitmentPathsAtRootRequest): Readonly<{
  commitmentHexes: readonly Hex[];
  rootHex: Hex;
  snapshotHeight: number | string;
}>;
export function normalizeCommitmentPathsAtRootResponse(response: object, request: CommitmentPathsAtRootRequest): VerifiedCommitmentPathSnapshot;
export function createCommitmentPathSnapshotProvider(snapshot: VerifiedCommitmentPathSnapshot): {
  lookupMerklePath(commitmentHex: Hex): Promise<{
    root: Hex;
    path: Hex[];
    path_helper: (0 | 1)[];
    leaf_index: number | string;
    snapshot_height: number | string;
  }>;
};
