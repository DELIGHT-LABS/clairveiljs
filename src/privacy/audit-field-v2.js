// Public-data verification only. Secret audit arithmetic belongs to Core's native backend.
import { FIELD_MODULUS, bytesToBigIntBE, mimcHash } from "../core/crypto.js";
import {
  concatBytes,
  sha256,
  utf8Bytes,
  hexFromBytes,
} from "../core/browser-crypto.js";
import { integerBytes, equalBytes } from "../core/encoding.js";
import { canonicalField, canonicalPoint } from "../core/curve-validation.js";
import { domainField } from "./protocol-domain.js";
import {
  auditRoundConstants,
  auditStaticTags,
} from "./audit-field-constants.js";
export const auditShapes = Object.freeze({
  1: Object.freeze([0, 1, 6, 336]),
  2: Object.freeze([1, 0, 2, 208]),
  3: Object.freeze([2, 2, 13, 560]),
  4: Object.freeze([16, 32, 177, 5808]),
});
export function shape(kind) {
  if (!Number.isInteger(kind) || !auditShapes[kind])
    throw new Error("unsupported audit kind");
  return auditShapes[kind];
}
export function counts(kind, inputs, outputs) {
  const s = shape(kind);
  if (
    !Number.isInteger(inputs) ||
    !Number.isInteger(outputs) ||
    (kind === 4
      ? inputs < 1 || inputs > 16 || outputs < 1 || outputs > 32
      : inputs !== s[0] || outputs !== s[1])
  )
    throw new Error("invalid audit active counts");
}
export function exactBytes(value, size, label) {
  if (
    !(value instanceof Uint8Array) ||
    (size !== undefined && value.length !== size)
  )
    throw new Error(`${label} has invalid byte length`);
  return Uint8Array.from(value);
}
export function fieldBytes(value, label, nonzero = false) {
  const b = exactBytes(value, 32, label);
  canonicalField(bytesToBigIntBE(b), label, nonzero);
  return b;
}
export function fieldValue(value, label, nonzero = false) {
  return bytesToBigIntBE(fieldBytes(value, label, nonzero));
}
export function digestFields(value) {
  return [
    bytesToBigIntBE(value.subarray(0, 16)),
    bytesToBigIntBE(value.subarray(16, 32)),
  ];
}
export function contextFields(kind, inputs) {
  shape(kind);
  if (!Array.isArray(inputs) || inputs.length !== 21)
    throw new Error("audit context requires PI21");
  const pi = inputs.map((v, i) => canonicalField(v, `PI[${i}]`));
  for (const i of [0, 1, 2, 3, 15, 17, 18, 19, 20])
    if (pi[i] >= 1n << 128n) throw new Error("PI limb exceeds uint128");
  for (const i of [4, 7])
    if (pi[i] === 0n || pi[i] >= 1n << 64n)
      throw new Error("PI epoch/expiry must be positive uint64");
  counts(kind, Number(pi[9]), Number(pi[10]));
  canonicalPoint(pi[5], pi[6], "audit key");
  const id = sha256(
    concatBytes(
      utf8Bytes("clairveil.audit.key.v1"),
      integerBytes(2, 2),
      integerBytes(pi[5], 32),
      integerBytes(pi[6], 32),
    ),
  );
  if (digestFields(id).some((v, i) => v !== pi[2 + i]))
    throw new Error("audit key ID mismatch");
  return pi;
}
export function parseAuditEnvelopeV2(kind, inputs, outputs, value) {
  counts(kind, inputs, outputs);
  const wire = exactBytes(value, shape(kind)[3], "audit envelope");
  const header = concatBytes(
    sha256(utf8Bytes("clairveil.audit.envelope.v1")).subarray(0, 16),
    integerBytes(2, 2),
    integerBytes(2, 2),
    Uint8Array.of(kind, inputs, outputs),
    new Uint8Array(9),
  );
  if (!equalBytes(header, wire.subarray(0, 32)))
    throw new Error("audit envelope header mismatch");
  const x = fieldValue(wire.subarray(48, 80), "ephemeral x"),
    y = fieldValue(wire.subarray(80, 112), "ephemeral y");
  canonicalPoint(x, y, "audit ephemeral");
  const ciphertext = [];
  for (let i = 112; i < wire.length - 32; i += 32)
    ciphertext.push(fieldValue(wire.subarray(i, i + 32), "ciphertext"));
  const tag = fieldValue(wire.subarray(-32), "authentication tag");
  return {
    kind,
    inputCount: inputs,
    outputCount: outputs,
    nonce: wire.slice(32, 48),
    ephemeral: { x, y },
    ciphertext,
    tag,
  };
}
function transcript(kind, inputs, envelope) {
  const pi = contextFields(kind, inputs);
  const frame = parseAuditEnvelopeV2(
    kind,
    Number(pi[9]),
    Number(pi[10]),
    envelope,
  );
  return {
    frame,
    t: [2n, 2n, BigInt(kind), ...pi, bytesToBigIntBE(frame.nonce)],
  };
}
const mod = (x) => x % FIELD_MODULUS;
const fifth = (x) => {
  const x2 = mod(x * x);
  return mod(mod(x2 * x2) * x);
};
const rc = auditRoundConstants.map((x) => BigInt(`0x${x}`));
const tags = auditStaticTags.map((row) => row.map((x) => BigInt(`0x${x}`)));
function permute(s) {
  const external = () => {
    const sum = mod(s[0] + s[1] + s[2]);
    s = s.map((x) => mod(x + sum));
  };
  external();
  let j = 0;
  for (let i = 0; i < 64; i++) {
    if (i < 4 || i >= 60) {
      s = s.map((x) => fifth(mod(x + rc[j++])));
      external();
    } else {
      s[0] = fifth(mod(s[0] + rc[j++]));
      const sum = mod(s[0] + s[1] + s[2]);
      s = [mod(s[0] + sum), mod(s[1] + sum), mod(2n * s[2] + sum)];
    }
  }
  return s;
}
function hash2(tag, values) {
  let s = [0n, ...tags[tag]];
  for (let i = 0; i < values.length; i++) {
    if (i > 0) s = permute(s);
    s[0] = mod(s[0] + values[i]);
  }
  s = permute(s);
  const left = s[0];
  s = permute(s);
  return [left, s[0]];
}
export function computeAuditCipherRootV2(kind, publicInputs, envelope) {
  const { frame, t } = transcript(kind, publicInputs, envelope);
  return hash2(4 + kind, [
    ...t,
    frame.ephemeral.x,
    frame.ephemeral.y,
    ...frame.ciphertext,
    frame.tag,
  ]);
}
export function computeAuditContextHashV2(kind, publicInputs, envelope) {
  const { t } = transcript(kind, publicInputs, envelope);
  return sha256(
    concatBytes(
      utf8Bytes("clairveil.audit.context.v2"),
      ...t.map((v) => integerBytes(v, 32)),
    ),
  );
}
export function computeAuditOwnerIntentV2(kind, publicInputs, envelope) {
  if (!Array.isArray(publicInputs) || publicInputs.length !== 23)
    throw new Error("owner intent requires PI23");
  const { t } = transcript(kind, publicInputs.slice(0, 21), envelope);
  const roots = computeAuditCipherRootV2(
    kind,
    publicInputs.slice(0, 21),
    envelope,
  );
  if (
    roots.some(
      (v, i) => v !== canonicalField(publicInputs[21 + i], "cipher root"),
    )
  )
    throw new Error("cipher root binding mismatch");
  return kind === 1
    ? new Uint8Array()
    : integerBytes(
        mimcHash(domainField("clairveil.audit.field.owner.v1"), ...t, ...roots),
        32,
      );
}
export function publicVectorRoot(kind, label, values) {
  if (values.length === 0) return 0n;
  const capacity =
    kind === 4 ? (label === "nullifier" ? 16 : 32) : values.length;
  if (![1, 2, 16, 32].includes(capacity) || values.length > capacity)
    throw new Error("invalid vector capacity");
  const leaf = domainField(`clairveil.batch-vector.${label}.leaf.v1`),
    node = domainField(`clairveil.batch-vector.${label}.node.v1`),
    root = domainField(`clairveil.batch-vector.${label}.root.v1`);
  let layer = Array.from({ length: capacity }, (_, i) => {
    const v =
      i < values.length
        ? canonicalField(values[i], "active vector value", true)
        : 0n;
    return mimcHash(leaf, BigInt(i), i < values.length ? 1n : 0n, v);
  });
  for (let level = 0; layer.length > 1; level++) {
    const next = [];
    for (let i = 0; i < layer.length; i += 2)
      next.push(mimcHash(node, BigInt(level), layer[i], layer[i + 1]));
    layer = next;
  }
  return mimcHash(root, BigInt(capacity), BigInt(values.length), layer[0]);
}
export function uniqueFields(values, label) {
  const seen = new Set();
  return values.map((v) => {
    const f = fieldValue(v, label, true),
      h = hexFromBytes(v);
    if (seen.has(h)) throw new Error(`duplicate ${label}`);
    seen.add(h);
    return f;
  });
}
