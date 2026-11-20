// Run in an unmodified extracted Core v0.6.1 module. Synthetic values only.
// Deterministic entropy is confined to this fixture generator, never the bridge.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	pa "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/audit"
	pc "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto"
	af "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/auditfield"
	pt "github.com/DELIGHT-LABS/clairveil/x/privacy/types"
	v2 "github.com/DELIGHT-LABS/clairveil/x/privacy/types/v2"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"math/big"
	"os"
)

func must[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}
func hx(b []byte) string       { return hex.EncodeToString(b) }
func be(n int64) []byte        { return big.NewInt(n).FillBytes(make([]byte, 32)) }
func field(n int64) af.Field32 { return must(af.ParseField32(be(n))) }
func hash(b []byte) string     { h := sha256.Sum256(b); return hx(h[:]) }
func env(k pt.EncryptedEnvelopeKindV1) []byte {
	n := must(pt.EncryptedEnvelopeV1Size(k))
	return must(pt.WrapEncryptedEnvelopeV1(k, make([]byte, n-pt.EncryptedEnvelopeV1HeaderSize)))
}
func main() {
	sdk.GetConfig().SetBech32PrefixForAccount("clair", "clairpub")
	var config struct {
		Network  string `json:"network_digest_hex"`
		Artifact string `json:"artifact_hash"`
		Records  []struct {
			Epoch string `json:"epoch"`
			Key   string `json:"public_key_hex"`
		} `json:"records"`
	}
	if err := json.Unmarshal(must(os.ReadFile(os.Args[1])), &config); err != nil {
		panic(err)
	}
	key := must(af.NewAuditKeyFromPoint64(must(hex.DecodeString(config.Records[1].Key))))
	var network, artifact [32]byte
	copy(network[:], must(hex.DecodeString(config.Network)))
	copy(artifact[:], must(hex.DecodeString(config.Artifact)))
	snapshot := pa.Snapshot{Network: network, Epoch: 2, Key: key, StateHeight: 21, ArtifactHash: artifact}
	creator := sdk.AccAddress(bytes.Repeat([]byte{2}, 20)).String()
	recipient := sdk.AccAddress(bytes.Repeat([]byte{3}, 20)).String()
	asset := pt.ComputeAssetIDV1("uclair")
	ax, ay, coordErr := key.Point().Coordinates()
	if coordErr != nil {
		panic(coordErr)
	}
	cases := []struct {
		name            string
		kind            af.Kind
		inputs, outputs int
		amount          string
		mode            int
	}{
		{"deposit-zero", 1, 0, 1, "0uclair", 0}, {"deposit-max", 1, 0, 1, "340282366920938463463374607431768211455uclair", 0},
		{"withdraw-u128", 2, 1, 0, "18446744073709551616uclair", 0},
		{"transfer-private", 3, 2, 2, "", 0}, {"transfer-public", 3, 2, 2, "", 1}, {"transfer-encrypted", 3, 2, 2, "", 2},
		{"batch-min", 4, 1, 1, "", 0}, {"batch-max", 4, 16, 32, "", 0}, {"batch-public", 4, 2, 3, "", 1}, {"batch-encrypted", 4, 2, 3, "", 2}}
	rows := []any{}
	for ix, c := range cases {
		in := pa.PrepareInput{Snapshot: snapshot, Kind: c.kind, Creator: creator, Amount: c.amount, ExpiresAtUnix: 2000000000}
		if c.inputs > 0 {
			in.Root = be(99)
		}
		for i := 0; i < c.inputs; i++ {
			in.Inputs = append(in.Inputs, be(int64(100+i)))
		}
		outputs := []any{}
		for i := 0; i < c.outputs; i++ {
			k := pt.EnvelopeTransferNoteV1
			if c.kind == 1 {
				k = pt.EnvelopeDepositNoteV1
			}
			o := &v2.OutputEffect{Commitment: be(int64(200 + i)), Ciphertext: env(k)}
			if c.kind != 1 {
				o.ViewTag = []byte{1, byte(i)}
			}
			if c.kind == 4 || c.kind == 3 && i == 0 {
				o.SelfFullDisclosureDigest = be(int64(300 + i))
				o.SelfViewDisclosurePayload = env(pt.EnvelopeSelfViewDisclosureV1)
				if c.mode > 0 {
					o.UserPrivacyPolicy = 1
					o.UserDisclosureMode = uint32(c.mode)
					p := &pt.DisclosurePlaintextV1{Plane: 1, OutputIndex: uint32(i), Policy: 1, DisclosedFieldBitmap: 1, Commitment: big.NewInt(int64(200 + i)), Amount: big.NewInt(7), AssetID: asset,
						SenderSpendKeyX: big.NewInt(0), SenderSpendKeyY: big.NewInt(0), SenderViewKeyX: big.NewInt(0), SenderViewKeyY: big.NewInt(0), RecipientSpendKeyX: big.NewInt(0), RecipientSpendKeyY: big.NewInt(0), RecipientViewKeyX: big.NewInt(0), RecipientViewKeyY: big.NewInt(0), DisclosureBlinding: big.NewInt(9)}
					if c.kind == 3 {
						o.UserDisclosureDigest = must(pt.ComputeTransferDisclosureDigestBytes(p.Policy, p.OutputIndex, o.Commitment, p.Amount, p.AssetID, p.SenderSpendKeyX, p.SenderSpendKeyY, p.SenderViewKeyX, p.SenderViewKeyY, p.RecipientSpendKeyX, p.RecipientSpendKeyY, p.RecipientViewKeyX, p.RecipientViewKeyY, p.DisclosureBlinding))
					} else {
						d := must(pt.ComputeBatchUserDisclosureDigestV1(pt.BatchUserDisclosureV1Input{OutputIndex: p.OutputIndex, Commitment: p.Commitment, Policy: p.Policy, DisclosedFieldBitmap: p.DisclosedFieldBitmap, SelectedAmount: p.Amount, AssetID: p.AssetID, UserDisclosureBlinding: p.DisclosureBlinding, SelectedFromSpendKeyX: p.SenderSpendKeyX, SelectedFromSpendKeyY: p.SenderSpendKeyY, SelectedFromViewKeyX: p.SenderViewKeyX, SelectedFromViewKeyY: p.SenderViewKeyY, SelectedToSpendKeyX: p.RecipientSpendKeyX, SelectedToSpendKeyY: p.RecipientSpendKeyY, SelectedToViewKeyX: p.RecipientViewKeyX, SelectedToViewKeyY: p.RecipientViewKeyY}))
						o.UserDisclosureDigest = d.FillBytes(make([]byte, 32))
					}
					o.UserDisclosurePayload = must(pt.MarshalDisclosurePlaintextV1(p))
					if c.mode == 2 {
						o.UserDisclosurePayload = env(pt.EnvelopeUserDisclosureV1)
						sk := must(pc.ImportNonzeroScalarBE32(be(4)))
						point := must(pc.PublicKey(sk))
						b := point.Bytes()
						o.UserDisclosureTargetPubkey = b[:]
					}
				}
			}
			in.Outputs = append(in.Outputs, o)
			outputs = append(outputs, map[string]any{"commitment": hx(o.Commitment), "ciphertext": hx(o.Ciphertext), "viewTag": hx(o.ViewTag), "userPrivacyPolicy": o.UserPrivacyPolicy, "userDisclosureMode": o.UserDisclosureMode, "userDisclosureDigest": hx(o.UserDisclosureDigest), "userDisclosureTargetPubkey": hx(o.UserDisclosureTargetPubkey), "userDisclosurePayload": hx(o.UserDisclosurePayload), "selfFullDisclosureDigest": hx(o.SelfFullDisclosureDigest), "selfViewDisclosurePayload": hx(o.SelfViewDisclosurePayload)})
		}
		in.Plaintext = append(in.Plaintext, must(af.ParseField32(asset.FillBytes(make([]byte, 32)))))
		if c.kind == 1 {
			amount := must(sdk.ParseCoinNormalized(c.amount))
			in.Plaintext = append(in.Plaintext, must(af.ParseField32(amount.Amount.BigInt().FillBytes(make([]byte, 32)))), ax, ay, ax, ay)
		} else {
			cap := c.inputs
			if c.kind == 4 {
				cap = 16
			}
			for i := 0; i < cap; i++ {
				f := field(0)
				if i < c.inputs {
					f = field(int64(400 + i))
				}
				in.Plaintext = append(in.Plaintext, f)
			}
			cap = c.outputs
			if c.kind == 4 {
				cap = 32
			}
			for i := 0; i < cap; i++ {
				v := []af.Field32{field(0), field(0), field(0), field(0), field(0)}
				if i < c.outputs {
					v = []af.Field32{field(7), ax, ay, ax, ay}
				}
				in.Plaintext = append(in.Plaintext, v...)
			}
		}
		if c.kind == 1 || c.kind == 2 {
			in.PublicAsset = asset.FillBytes(make([]byte, 32))
			in.Principal = bytes.Repeat([]byte{2}, 20)
			if c.kind == 2 {
				in.Principal = bytes.Repeat([]byte{3}, 20)
				in.Recipient = recipient
			}
		}
		entropy := append(be(int64(1000+ix)), bytes.Repeat([]byte{byte(ix + 1)}, 16)...)
		rand.Reader = bytes.NewReader(entropy)
		p := must(pa.Prepare(in))
		pi := p.PublicInputs()
		wire := must(p.EnvelopeBytes())
		frame := must(af.ParseEnvelopeFrame(c.kind, uint8(c.inputs), uint8(c.outputs), wire))
		ctx := must(af.NewAuditContext(c.kind, pi[:21]))
		h := must(ctx.ContextHash(frame.Nonce()))
		_, aux, e := pt.AuditOutputsToAux(c.kind, in.Outputs)
		if e != nil {
			panic(e)
		}
		strings := []string{}
		for _, v := range pi {
			strings = append(strings, new(big.Int).SetBytes(v[:]).String())
		}
		plain := []string{}
		for _, v := range in.Plaintext {
			plain = append(plain, hx(v[:]))
		}
		nullifiers := []string{}
		for _, v := range in.Inputs {
			nullifiers = append(nullifiers, hx(v))
		}
		owner := ""
		if c.kind != 1 {
			v := must(p.OwnerIntent())
			owner = hx(v[:])
		}
		r := must(p.ProverScalarBE32())
		rows = append(rows, map[string]any{"name": c.name, "kind": c.kind, "creator": creator, "recipient": in.Recipient, "amount": c.amount, "expiresAtUnix": "2000000000", "root": hx(in.Root), "nullifiers": nullifiers, "outputs": outputs, "plaintext": plain, "publicInputs": strings, "aux": hx(aux), "envelope": hx(wire), "contextHash": hx(h[:]), "ownerIntent": owner, "syntheticWitness": hx(r[:])})
		p.Clear()
	}
	files := map[string]string{}
	for _, path := range []string{"x/privacy/client/sdk/audit/prepared.go", "x/privacy/client/sdk/audit/public_witness.go", "x/privacy/types/audit_adapter.go", "x/privacy/types/batch_contract.go", "x/privacy/types/batch_payload.go", "x/privacy/types/msg.go", "x/privacy/crypto/auditfield/audit.go", "x/privacy/crypto/auditfield/context.go", "x/privacy/crypto/auditfield/schema.go", "x/privacy/crypto/auditfield/wire.go", "x/privacy/crypto/auditfield/audit_aux.go", "x/privacy/crypto/auditfield/root.go", "x/privacy/crypto/auditfield/sponge.go", "x/privacy/crypto/auditfield/params_literals.go"} {
		files[path] = hash(must(os.ReadFile(path)))
	}
	constants := []string{}
	for _, v := range af.Poseidon2RoundConstants() {
		constants = append(constants, hx(v[:]))
	}
	tags := [][]string{}
	for _, v := range af.StaticTags() {
		tags = append(tags, []string{hx(v[0][:]), hx(v[1][:])})
	}
	out := map[string]any{"synthetic": true, "source": map[string]any{"release": "v0.6.1", "commit": "fad307abddd0daa1c880f2e423668f5c58a0e578", "files": files}, "cases": rows, "roundConstants": constants, "tags": tags}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(out); err != nil {
		panic(fmt.Sprint(err))
	}
}
