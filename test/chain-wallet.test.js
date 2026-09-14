import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";
import { toBech32 } from "@cosmjs/encoding";
import * as chainWallet from "clairveiljs/chain-wallet";
import { createPrivacyIdentity } from "clairveiljs/wallet-kernel";

const cosmosAddress = index => toBech32("clair", new Uint8Array(20).fill(index));
const evmAddress = index => "0x" + index.toString(16).padStart(2, "0").repeat(20);
const chainId = "synthetic-chain-1";
const signDoc = () => ({ bodyBytes: new Uint8Array([1, 2]), authInfoBytes: new Uint8Array([3]), chainId, accountNumber: 1n });
const transaction = () => ({ to: evmAddress(3), data: "0x1234", value: "0x1" });
const signResponse = signed => ({ signed, signature: { pub_key: { type: "tendermint/PubKeySecp256k1", value: "Ag==" }, signature: "AQ==" } });

function cosmosFixture(kind, options = {}) {
  const state = { index: 1, pubkey: new Uint8Array(33).fill(2), beforeRead: undefined, failSigning: false };
  const calls = [];
  const read = async () => {
    await state.beforeRead?.();
    return { address: cosmosAddress(state.index), pubkey: state.pubkey };
  };
  const sign = async (...args) => {
    calls.push({ method: "signDirect", args });
    if (state.failSigning) throw new Error("SIGNING_REJECTED");
    return signResponse(args[kind === "keplr" ? 2 : 1]);
  };
  const adapter = kind === "keplr"
    ? chainWallet.createKeplrChainWalletAdapter({ chainId, ...options, keplr: {
      async enable(value) { calls.push({ method: "enable", value }); },
      async getKey() { const value = await read(); return { bech32Address: value.address, pubKey: value.pubkey }; },
      signDirect: sign
    } })
    : chainWallet.createOfflineSignerChainWalletAdapter({ chainId, ...options, signer: {
      async getAccounts() { return [await read()]; }, signDirect: sign
    } });
  return { adapter, state, calls };
}

function evmFixture(options = {}) {
  const calls = [];
  const state = { accounts: [evmAddress(1)], network: "0x539", onRead: undefined, rejectSend: false, hash: "0x" + "ab".repeat(32) };
  const provider = { async request(input) {
    calls.push(input);
    if (input.method === "eth_requestAccounts") return state.accounts;
    if (input.method === "eth_chainId") { await state.onRead?.(input.method); return state.network; }
    if (input.method === "eth_accounts") { await state.onRead?.(input.method); return state.accounts; }
    if (input.method === "eth_sendTransaction") {
      if (state.rejectSend) throw new Error("PROVIDER_REJECTED");
      return state.hash;
    }
    throw new Error("UNEXPECTED_WALLET_METHOD");
  } };
  return { state, calls, adapter: chainWallet.createEip1193ChainWalletAdapter({ provider, chainId: "0x539", ...options }) };
}

for (const kind of ["keplr", "offline"]) {
  test(`${kind} chain signing works without a root signer and preserves public signDoc fields`, async () => {
    const { adapter, calls } = cosmosFixture(kind);
    assert.deepEqual(calls, []);
    const actor = await adapter.connect();
    assert.equal(Object.isFrozen(actor), true);
    const document = { ...signDoc(), rootSeed: new Uint8Array(32), privatePayload: "synthetic-only" };
    const response = await adapter.signDirect(document, actor);
    const signed = calls.find(call => call.method === "signDirect").args;
    assert.deepEqual(response.signed, signDoc());
    assert.notEqual(response.signed.bodyBytes, document.bodyBytes);
    assert.equal(signed[kind === "keplr" ? 1 : 0], actor.address);
    if (kind === "keplr") {
      assert.equal(signed[0], chainId);
      assert.deepEqual(signed[3], { preferNoSetFee: true, preferNoSetMemo: true });
      assert.equal(calls.filter(call => call.method === "enable").length, 1);
    }
    assert.equal(adapter.signPrivacyRoot, undefined);
    assert.equal(adapter.signPrivacyRootBase64, undefined);
  });

  test(`${kind} rejects stale actor, changed key and wrong document network before signing`, async () => {
    const { adapter, state, calls } = cosmosFixture(kind);
    const actor = await adapter.getActor();
    await assert.rejects(adapter.signDirect(signDoc()), /actor network mismatch/);
    await assert.rejects(adapter.signDirect({ ...signDoc(), chainId: "other-chain" }, actor), /chain ID mismatch/);
    state.index = 2;
    await assert.rejects(adapter.signDirect(signDoc(), actor), /account or network changed/);
    state.index = 1; state.pubkey.fill(3);
    await assert.rejects(adapter.signDirect(signDoc(), actor), /account or network changed/);
    assert.equal(calls.filter(call => call.method === "signDirect").length, 0);
  });

  test(`${kind} snapshots the caller document and actor before asynchronous account discovery`, async () => {
    const { adapter, state, calls } = cosmosFixture(kind);
    const actor = { ...await adapter.getActor() };
    const document = signDoc();
    state.beforeRead = async () => { document.bodyBytes.fill(9); document.accountNumber = 99n; actor.address = cosmosAddress(2); };
    await adapter.signDirect(document, actor);
    const args = calls.find(call => call.method === "signDirect").args;
    assert.equal(args[kind === "keplr" ? 1 : 0], cosmosAddress(1));
    assert.deepEqual(args[kind === "keplr" ? 2 : 1], signDoc());
  });

  test(`${kind} keeps a configured actor pinned and does not retry rejected signing`, async () => {
    const { adapter, state, calls } = cosmosFixture(kind, { address: cosmosAddress(1) });
    const actor = await adapter.getActor();
    state.index = 2;
    await assert.rejects(adapter.getActor(), /account mismatch/);
    state.index = 1; state.failSigning = true;
    await assert.rejects(adapter.signDirect(signDoc(), actor), /SIGNING_REJECTED/);
    assert.equal(calls.filter(call => call.method === "signDirect").length, 1);
  });
}

test("Cosmos adapters reject unavailable signing, wrong address profiles, empty keys and invalid documents", async () => {
  assert.throws(() => chainWallet.createKeplrChainWalletAdapter({ keplr: {}, chainId }), /required/);
  assert.throws(() => chainWallet.createOfflineSignerChainWalletAdapter({ signer: {}, chainId }), /required/);
  await assert.rejects(cosmosFixture("keplr", { accountPrefix: "cosmos" }).adapter.getActor(), /prefix/);
  const { adapter, state, calls } = cosmosFixture("offline");
  const actor = await adapter.getActor();
  for (const patch of [{ accountNumber: -1n }, { accountNumber: 1 }, { accountNumber: 1n << 64n }, { bodyBytes: [] }, { authInfoBytes: "" }]) {
    await assert.rejects(adapter.signDirect({ ...signDoc(), ...patch }, actor), /invalid Cosmos/);
  }
  state.pubkey = new Uint8Array();
  await assert.rejects(adapter.getActor(), /public key/);
  assert.equal(calls.length, 0);
});

test("EIP-1193 separates explicit connection from lookup and dispatches only public transaction fields", async () => {
  const { adapter, calls } = evmFixture();
  assert.deepEqual(calls, []);
  const actor = await adapter.getActor();
  assert.equal(calls.some(call => call.method === "eth_requestAccounts"), false);
  await adapter.connect();
  const hash = await adapter.sendTransaction({ ...transaction(), rootSeed: new Uint8Array(32), __clairveilEvmTransaction: { private: "fixture" } }, actor);
  assert.equal(hash, "0x" + "ab".repeat(32));
  assert.equal(calls.filter(call => call.method === "eth_requestAccounts").length, 1);
  assert.deepEqual(calls.find(call => call.method === "eth_sendTransaction").params, [
    { ...transaction(), from: evmAddress(1), chainId: "0x539" }
  ]);
  assert.equal(adapter.signPrivacyRoot, undefined);
  assert.equal(adapter.signTypedData, undefined);
});

test("EIP-1193 rejects stale and unavailable actors, wrong networks and substituted transactions", async () => {
  const { adapter, calls, state } = evmFixture();
  const actor = await adapter.getActor();
  await assert.rejects(adapter.sendTransaction(transaction()), /actor network mismatch/);
  for (const patch of [{ from: evmAddress(2) }, { chainId: "0x1" }, { to: "bad" }, { data: {} }, { value: { private: "fixture" } }, { value: "0x01" }]) {
    await assert.rejects(adapter.sendTransaction({ ...transaction(), ...patch }, actor));
  }
  state.accounts = [evmAddress(2)];
  await assert.rejects(adapter.sendTransaction(transaction(), actor), /account or network changed/);
  state.accounts = [];
  await assert.rejects(adapter.getActor(), /no connected accounts/);
  state.accounts = [evmAddress(1)]; state.network = "0x1";
  await assert.rejects(adapter.sendTransaction(transaction(), actor), /network mismatch/);
  assert.equal(calls.some(call => call.method === "eth_sendTransaction"), false);
  const pinned = evmFixture({ account: evmAddress(2) });
  await assert.rejects(pinned.adapter.getActor(), /account mismatch/);
});

test("EIP-1193 snapshots transaction and actor while rejecting a network switch during discovery", async () => {
  const { adapter, state, calls } = evmFixture();
  const actor = { ...await adapter.getActor() };
  const input = transaction();
  state.onRead = async () => { input.value = "0xff"; actor.address = evmAddress(2); };
  await adapter.sendTransaction(input, actor);
  assert.deepEqual(calls.find(call => call.method === "eth_sendTransaction").params, [
    { ...transaction(), from: evmAddress(1), chainId: "0x539" }
  ]);
  const switched = evmFixture();
  const original = await switched.adapter.getActor();
  switched.state.onRead = async method => { if (method === "eth_accounts") switched.state.network = "0x1"; };
  await assert.rejects(switched.adapter.sendTransaction(transaction(), original), /network changed/);
  assert.equal(switched.calls.some(call => call.method === "eth_sendTransaction"), false);
});

test("EIP-1193 reports send rejection or malformed replies without replay or root-signature fallback", async () => {
  for (const rejectSend of [true, false]) {
    const { adapter, state, calls } = evmFixture();
    const actor = await adapter.getActor(); state.rejectSend = rejectSend; state.hash = "malformed";
    await assert.rejects(adapter.sendTransaction(transaction(), actor), rejectSend ? /PROVIDER_REJECTED/ : /invalid transaction hash/);
    assert.equal(calls.filter(call => call.method === "eth_sendTransaction").length, 1);
    assert.equal(calls.some(call => ["personal_sign", "eth_sign", "eth_signTypedData_v4"].includes(call.method)), false);
  }
});

test("ordinary Cosmos/EVM account and network selection leaves the independent privacy identity unchanged", async () => {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const identity = createPrivacyIdentity({ rootSeed: seed });
  const expected = { ...identity.publicIdentity };
  const cosmos = cosmosFixture("keplr"); const evm = evmFixture();
  const actors = [await cosmos.adapter.connect(), await evm.adapter.connect()];
  cosmos.state.index = 2; evm.state.accounts = [evmAddress(2)];
  actors.push(await cosmos.adapter.getActor(), await evm.adapter.getActor());
  const otherNetwork = evmFixture({ chainId: "0x53a" });
  otherNetwork.state.network = "0x53a";
  actors.push(await otherNetwork.adapter.getActor());
  assert.notEqual(actors[0].address, actors[2].address);
  assert.notEqual(actors[1].address, actors[3].address);
  assert.notEqual(actors[1].chainId, actors[4].chainId);
  for (const actor of actors) {
    assert.equal(Object.isFrozen(actor), true);
    assert.equal("rootSeed" in actor, false);
    assert.equal("signatureBase64" in actor, false);
  }
  assert.deepEqual(identity.publicIdentity, expected);
  assert.deepEqual(identity.rootSeed, seed);
});

test("chain-wallet entrypoint has a closed public-only import graph", () => {
  const visited = new Set();
  const base = new URL("../src/chain-wallet/", import.meta.url);
  function inspect(url) {
    if (visited.has(url.href)) return;
    visited.add(url.href);
    assert.ok(url.href.startsWith(base.href), "chain-wallet must not import legacy, kernel or privacy modules");
    const source = ts.createSourceFile(url.pathname, readFileSync(url, "utf8"), ts.ScriptTarget.Latest, true);
    function visit(node) {
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
        const specifier = node.moduleSpecifier.text;
        if (specifier.startsWith(".")) inspect(new URL(specifier, url));
        else assert.equal(specifier, "@cosmjs/encoding");
      }
      if (ts.isCallExpression(node)) {
        assert.notEqual(node.expression.kind, ts.SyntaxKind.ImportKeyword, "dynamic imports require a new boundary review");
        assert.notEqual(node.expression.getText(source), "require", "CommonJS imports require a new boundary review");
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
  inspect(new URL("index.js", base));
  assert.deepEqual(Object.keys(chainWallet).sort(), ["createEip1193ChainWalletAdapter", "createKeplrChainWalletAdapter", "createOfflineSignerChainWalletAdapter"]);
});
