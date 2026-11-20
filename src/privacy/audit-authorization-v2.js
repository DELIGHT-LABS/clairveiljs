import { fromBech32, toBech32 } from "@cosmjs/encoding";
import {
  mimcHash,
  unpackPoint,
  packPoint,
  CURVE_ORDER,
  bytesToBigIntBE,
} from "../core/crypto.js";
import {
  concatBytes,
  sha256,
  utf8Bytes,
  bytesFromHex,
} from "../core/browser-crypto.js";
import {
  integerBytes,
  unsignedInteger,
  equalBytes,
  requireObject,
} from "../core/encoding.js";
import { domainField, computeAssetId } from "./protocol-domain.js";
import {
  unwrapEncryptedEnvelopeV2,
  unmarshalDisclosurePlaintextV2,
  verifyDisclosureDigestV2,
} from "./protocol-v2.js";
import { assertAuditSnapshotCurrentV2 } from "./audit-config-v2.js";
import {
  counts,
  shape,
  exactBytes,
  fieldBytes,
  fieldValue,
  digestFields,
  contextFields,
  publicVectorRoot,
  uniqueFields,
  computeAuditCipherRootV2,
  computeAuditOwnerIntentV2,
} from "./audit-field-v2.js";
export {
  parseAuditEnvelopeV2,
  computeAuditCipherRootV2,
  computeAuditContextHashV2,
  computeAuditOwnerIntentV2,
} from "./audit-field-v2.js";
const outputBytes = [
  "commitment",
  "ciphertext",
  "viewTag",
  "userDisclosureDigest",
  "userDisclosureTargetPubkey",
  "userDisclosurePayload",
  "selfFullDisclosureDigest",
  "selfViewDisclosurePayload",
];
const empty = () => new Uint8Array();
function keys(value, allowed, label) {
  requireObject(value, label);
  if (Object.keys(value).some((k) => !allowed.includes(k)))
    throw new Error(`${label} contains unsupported fields`);
}
function address(value, accountPrefix) {
  if (typeof value !== "string")
    throw new Error("canonical creator/recipient required");
  // Core permits at most 255 address bytes. The host pins its SDK address codec.
  const limit = accountPrefix.length + 1 + 408 + 6;
  const a = fromBech32(value, limit);
  if (
    a.prefix !== accountPrefix ||
    a.data.length === 0 ||
    a.data.length > 255 ||
    toBech32(a.prefix, a.data, limit) !== value
  )
    throw new Error("noncanonical audit address");
  return a.data;
}
export function createAuditOutputEffectV2(kind, index, input) {
  const s = shape(kind);
  if (!Number.isInteger(index) || index < 0 || index >= s[1])
    throw new Error("output index out of range");
  keys(
    input,
    [...outputBytes, "userPrivacyPolicy", "userDisclosureMode"],
    "output effect",
  );
  const limits = [32, 438, 2, 32, 32, 480, 32, 480];
  const o = Object.fromEntries(
    outputBytes.map((k, i) => {
      const v = input[k] ?? empty();
      if (!(v instanceof Uint8Array) || v.length > limits[i])
        throw new Error(`invalid ${k} size`);
      return [k, exactBytes(v, undefined, k)];
    }),
  );
  o.userPrivacyPolicy = input.userPrivacyPolicy ?? 0;
  o.userDisclosureMode = input.userDisclosureMode ?? 0;
  for (const [k, max] of [
    ["userPrivacyPolicy", 7],
    ["userDisclosureMode", 2],
  ])
    if (!Number.isInteger(o[k]) || o[k] < 0 || o[k] > max)
      throw new Error(`invalid ${k}`);
  fieldBytes(o.commitment, "commitment", true);
  unwrapEncryptedEnvelopeV2(o.ciphertext, kind === 1 ? 1 : 2);
  exactBytes(o.viewTag, kind === 1 ? 0 : 2, "view tag");
  const unused = kind === 1 || (kind === 3 && index === 1);
  if (unused) {
    if (
      o.userPrivacyPolicy !== 0 ||
      o.userDisclosureMode !== 0 ||
      outputBytes.slice(3).some((k) => o[k].length !== 0)
    )
      throw new Error("unused output disclosure fields must be omitted");
    return o;
  }
  fieldBytes(o.selfFullDisclosureDigest, "self full disclosure digest", true);
  if (o.selfViewDisclosurePayload.length)
    unwrapEncryptedEnvelopeV2(o.selfViewDisclosurePayload, 5);
  if (o.userPrivacyPolicy === 0) {
    if (
      o.userDisclosureMode !== 0 ||
      [
        "userDisclosureDigest",
        "userDisclosureTargetPubkey",
        "userDisclosurePayload",
      ].some((k) => o[k].length)
    )
      throw new Error("all-private disclosure fields must be omitted");
    return o;
  }
  fieldBytes(o.userDisclosureDigest, "user disclosure digest", kind === 4);
  if (o.userDisclosureMode === 1) {
    if (o.userDisclosureTargetPubkey.length)
      throw new Error("public disclosure target must be empty");
    const p = unmarshalDisclosurePlaintextV2(o.userDisclosurePayload);
    if (
      p.plane !== 1 ||
      p.outputIndex !== index ||
      p.policy !== o.userPrivacyPolicy ||
      p.commitment !== fieldValue(o.commitment, "commitment")
    )
      throw new Error("disclosure metadata binding mismatch");
    verifyDisclosureDigestV2(
      p,
      o.userDisclosureDigest,
      kind === 4 ? "batch" : "transfer",
    );
  } else if (o.userDisclosureMode === 2) {
    const raw = exactBytes(
      o.userDisclosureTargetPubkey,
      32,
      "disclosure target",
    );
    const point = unpackPoint(raw);
    if (
      (point.x === 0n && point.y === 1n) ||
      !equalBytes(packPoint(point), raw)
    )
      throw new Error("noncanonical disclosure target");
    unwrapEncryptedEnvelopeV2(o.userDisclosurePayload, 3);
  } else throw new Error("disclosed output requires public/encrypted mode");
  return o;
}
function effects(kind, outputs) {
  if (
    !Array.isArray(outputs) ||
    (kind === 4
      ? outputs.length < 1 || outputs.length > 32
      : outputs.length !== shape(kind)[1])
  )
    throw new Error("invalid output capacity");
  const result = outputs.map((o, i) => createAuditOutputEffectV2(kind, i, o));
  uniqueFields(
    result.map((o) => o.commitment),
    "commitment",
  );
  return result;
}
const lp = (b) => concatBytes(integerBytes(b.length, 4), b);
function auxFrame(kind, outputs) {
  return concatBytes(
    integerBytes(1, 2),
    Uint8Array.of(kind, outputs.length),
    ...outputs.map((o) =>
      concatBytes(
        lp(o.ciphertext),
        lp(o.viewTag),
        integerBytes(o.userPrivacyPolicy, 4),
        Uint8Array.of(o.userDisclosureMode),
        o.userDisclosureDigest.length
          ? o.userDisclosureDigest
          : new Uint8Array(32),
        lp(o.userDisclosureTargetPubkey),
        lp(o.userDisclosurePayload),
        o.selfFullDisclosureDigest.length
          ? o.selfFullDisclosureDigest
          : new Uint8Array(32),
        lp(o.selfViewDisclosurePayload),
      ),
    ),
  );
}
export function encodeAuditAuxV2(kind, outputs) {
  return auxFrame(kind, effects(kind, outputs));
}
function normalize(kind, message, accountPrefix) {
  shape(kind);
  const allowed = [
    "creator",
    "expiresAtUnix",
    "audit",
    "proof",
    ...(kind === 1
      ? ["amount", "output"]
      : kind === 2
        ? ["amount", "recipient", "root", "nullifier"]
        : ["root", "nullifiers", "outputs"]),
  ];
  keys(message, allowed, "audit message");
  address(message.creator, accountPrefix);
  const expiresAtUnix = unsignedInteger(
    message.expiresAtUnix,
    "expiry",
    (1n << 63n) - 1n,
    1n,
  );
  const nullifiers =
    kind === 1 ? [] : kind === 2 ? [message.nullifier] : message.nullifiers;
  if (!Array.isArray(nullifiers) || nullifiers.length > 16)
    throw new Error("invalid nullifiers");
  const outputs = effects(
    kind,
    kind === 1 ? [message.output] : kind === 2 ? [] : message.outputs,
  );
  counts(kind, nullifiers.length, outputs.length);
  const nf = uniqueFields(nullifiers, "nullifier");
  const root = kind === 1 ? 0n : fieldValue(message.root, "merkle root", true);
  const result = { creator: message.creator, expiresAtUnix };
  let amount = 0n,
    asset = 0n,
    principal;
  if (kind === 1 || kind === 2) {
    const m =
      typeof message.amount === "string" &&
      /^(0|[1-9][0-9]*)([a-zA-Z][a-zA-Z0-9/:._-]{2,127})$/.exec(message.amount);
    if (!m) throw new Error("canonical uint128 coin required");
    amount = unsignedInteger(
      m[1],
      "public amount",
      (1n << 128n) - 1n,
      kind === 2 ? 1n : 0n,
    );
    asset = computeAssetId(m[2]);
    result.amount = message.amount;
    principal = address(kind === 1 ? message.creator : message.recipient, accountPrefix);
    if (kind === 2) result.recipient = message.recipient;
  }
  if (kind === 1) result.output = outputs[0];
  else {
    result.root = integerBytes(root, 32);
    if (kind === 2) result.nullifier = integerBytes(nf[0], 32);
    else {
      result.nullifiers = nf.map((v) => integerBytes(v, 32));
      result.outputs = outputs;
    }
  }
  return { message: result, outputs, nf, root, amount, asset, principal };
}
export function buildAuditPublicInputsV2({ kind, snapshot, message }) {
  assertAuditSnapshotCurrentV2(snapshot, snapshot);
  const n = normalize(kind, message, snapshot.accountPrefix);
  const pk = bytesFromHex(snapshot.publicKey);
  const pi = [
    ...digestFields(bytesFromHex(snapshot.networkDigest)),
    ...digestFields(bytesFromHex(snapshot.keyId)),
    BigInt(snapshot.epoch),
    fieldValue(pk.subarray(0, 32), "key x"),
    fieldValue(pk.subarray(32), "key y"),
    n.message.expiresAtUnix,
    n.root,
    BigInt(n.nf.length),
    BigInt(n.outputs.length),
    publicVectorRoot(kind, "nullifier", n.nf),
    publicVectorRoot(
      kind,
      "commitment",
      n.outputs.map((o) => fieldValue(o.commitment, "commitment")),
    ),
    0n,
    0n,
    n.amount,
    n.asset,
    0n,
    0n,
    0n,
    0n,
  ];
  if (kind === 3) {
    const o = n.outputs[0];
    pi[13] = mimcHash(
      domainField("clairveil.audit.user-2x2.v1"),
      BigInt(o.userPrivacyPolicy),
      o.userDisclosureDigest.length
        ? fieldValue(o.userDisclosureDigest, "user digest")
        : 0n,
    );
    pi[14] = fieldValue(o.selfFullDisclosureDigest, "self digest");
  }
  if (kind === 4) {
    pi[13] = publicVectorRoot(
      kind,
      "user_disclosure",
      n.outputs.map((o, i) =>
        mimcHash(
          domainField("clairveil.user-disclosure-leaf.v1"),
          BigInt(i),
          1n,
          BigInt(o.userPrivacyPolicy),
          o.userDisclosureDigest.length
            ? fieldValue(o.userDisclosureDigest, "user digest")
            : 0n,
        ),
      ),
    );
    pi[14] = publicVectorRoot(
      kind,
      "full_disclosure",
      n.outputs.map((o) =>
        fieldValue(o.selfFullDisclosureDigest, "self digest"),
      ),
    );
  }
  if (n.principal)
    [pi[17], pi[18]] = digestFields(
      sha256(
        concatBytes(
          utf8Bytes("clairveil.audit.public-target.v1"),
          Uint8Array.of(kind),
          lp(n.principal),
        ),
      ),
    );
  [pi[19], pi[20]] = digestFields(
    sha256(
      concatBytes(
        utf8Bytes("clairveil.audit.aux.v1"),
        auxFrame(kind, n.outputs),
      ),
    ),
  );
  contextFields(kind, pi);
  if (message.audit !== undefined) {
    keys(message.audit, ["keyId", "epoch", "envelope"], "audit authorization");
    if (
      !equalBytes(
        exactBytes(message.audit.keyId, 32, "key ID"),
        bytesFromHex(snapshot.keyId),
      ) ||
      unsignedInteger(
        message.audit.epoch,
        "audit epoch",
        (1n << 64n) - 1n,
        1n,
      ) !== BigInt(snapshot.epoch)
    )
      throw new Error("audit authorization snapshot mismatch");
    pi.push(...computeAuditCipherRootV2(kind, pi, message.audit.envelope));
  }
  return pi;
}
/** Public binding only; this neither decrypts the audit nor verifies a Groth16 proof. */
export function verifyAuditMessageBindingV2({
  kind,
  snapshot,
  message,
  publicInputs,
}) {
  if (
    !message.audit ||
    !Array.isArray(publicInputs) ||
    publicInputs.length !== 23
  )
    throw new Error("audit binding requires authorization and PI23");
  const want = buildAuditPublicInputsV2({ kind, snapshot, message });
  if (want.some((v, i) => v !== publicInputs[i]))
    throw new Error("audit message/public input binding mismatch");
  return true;
}
function abort(signal) {
  if (signal?.aborted) throw new Error("audit preparation aborted");
}
const inspectSymbol = Symbol.for("nodejs.util.inspect.custom");
/** Wallet-only, in-memory preparation. Proving and broadcast are separate operations. */
import { registerAuditPreparation } from "./audit-prepared-state.js";

export async function prepareAuditAuthorizationV2({
  kind,
  snapshot,
  message,
  plaintext,
  backend,
  getCurrentSnapshot,
  signal,
  now = () => BigInt(Math.floor(Date.now() / 1000)),
}) {
  if (message?.audit !== undefined || message?.proof !== undefined)
    throw new Error(
      "preparation requires proofless message data without authorization",
    );
  if (
    typeof backend?.encrypt !== "function" ||
    typeof getCurrentSnapshot !== "function"
  )
    throw new Error(
      "trusted native backend and fresh snapshot provider required",
    );
  assertAuditSnapshotCurrentV2(snapshot, snapshot);
  const data = normalize(kind, message, snapshot.accountPrefix).message,
    pi = buildAuditPublicInputsV2({ kind, snapshot, message: data });
  if (!Array.isArray(plaintext) || plaintext.length !== shape(kind)[2])
    throw new Error("incorrect audit plaintext field count");
  const plain = concatBytes(
    ...plaintext.map((v) => fieldBytes(v, "audit plaintext")),
  );
  let reply;
  let secret;
  const valid = () => {
    abort(signal);
    if (
      unsignedInteger(now(), "current time", (1n << 63n) - 1n) >=
      data.expiresAtUnix
    )
      throw new Error("audit preparation expired");
  };
  try {
    valid();
    assertAuditSnapshotCurrentV2(snapshot, await getCurrentSnapshot());
    valid();
    reply = await backend.encrypt({
      kind,
      publicInputs: concatBytes(...pi.map((v) => integerBytes(v, 32))),
      plaintext: plain,
      signal,
    });
    valid();
    assertAuditSnapshotCurrentV2(snapshot, await getCurrentSnapshot());
    valid();
    const envelope = exactBytes(
      reply.envelope,
      shape(kind)[3],
      "native envelope",
    );
    secret = exactBytes(reply.witness, 32, "native encryption witness");
    const scalar = bytesToBigIntBE(secret);
    if (scalar === 0n || scalar >= CURVE_ORDER)
      throw new Error("invalid native encryption witness");
    data.audit = {
      keyId: bytesFromHex(snapshot.keyId),
      epoch: BigInt(snapshot.epoch),
      envelope,
    };
    const final = buildAuditPublicInputsV2({ kind, snapshot, message: data });
    let cleared = false;
    const clear = () => {
      if (cleared) return;
      cleared = true;
      secret.fill(0);
      const wipe = (v) => {
        if (v instanceof Uint8Array) v.fill(0);
        else if (v && typeof v === "object")
          for (const item of Object.values(v)) wipe(item);
      };
      wipe(data);
      final.fill(0n);
    };
    const live = () => {
      if (cleared) throw new Error("audit preparation cleared");
      try {
        valid();
      } catch (error) {
        clear();
        throw error;
      }
    };
    const prepared = {
      messageData() {
        live();
        return structuredClone(data);
      },
      publicInputs() {
        live();
        return final.slice();
      },
      ownerIntent() {
        live();
        return computeAuditOwnerIntentV2(kind, final, data.audit.envelope);
      },
      exportEncryptionWitness() {
        live();
        return secret.slice();
      },
      assertMessageBinding(candidate) {
        live();
        if (candidate.creator !== data.creator)
          throw new Error("creator binding mismatch");
        return verifyAuditMessageBindingV2({
          kind,
          snapshot,
          message: candidate,
          publicInputs: final,
        });
      },
      async assertCurrent() {
        try {
          live();
          assertAuditSnapshotCurrentV2(snapshot, await getCurrentSnapshot());
          live();
          return true;
        } catch (error) {
          clear();
          throw error;
        }
      },
      clear,
      toJSON() {
        throw new Error("audit preparation serialization is disabled");
      },
      [inspectSymbol]() {
        return "AuditPreparationV2(<redacted>)";
      },
    };
    registerAuditPreparation(prepared, kind, snapshot);
    return Object.freeze(prepared);
  } catch (error) {
    secret?.fill(0);
    throw error;
  } finally {
    plain.fill(0);
    reply?.witness?.fill?.(0);
  }
}
