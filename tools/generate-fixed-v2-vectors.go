// Run in an extracted, unmodified Core v0.6.1 module. All keys/entropy below
// are public synthetic test values. Never use this deterministic reader in a wallet.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"

	pc "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto"
	pt "github.com/DELIGHT-LABS/clairveil/x/privacy/types"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func decimal(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid synthetic decimal")
	}
	return v
}
func fixed(v *big.Int) []byte                   { return v.FillBytes(make([]byte, 32)) }
func hx(b []byte) string                        { return hex.EncodeToString(b) }
func scalar(n int64) pc.SecretScalar            { return must(pc.ImportNonzeroScalarBE32(fixed(big.NewInt(n)))) }
func point(n int64) *twistededwards.PointAffine { return must(pc.PublicKey(scalar(n))) }
func xy(p *twistededwards.PointAffine) (*big.Int, *big.Int) {
	return p.X.BigInt(new(big.Int)), p.Y.BigInt(new(big.Int))
}
func entropy(index int, asymmetric bool) []byte {
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(index + i)
	}
	if asymmetric {
		return append(fixed(big.NewInt(int64(100+index))), nonce...)
	}
	return nonce
}
func noteJSON(n *pt.Note) map[string]any {
	return map[string]any{
		"receiverSpendPubKeyX": n.ReceiverSpendPubKeyX.String(), "receiverSpendPubKeyY": n.ReceiverSpendPubKeyY.String(),
		"receiverViewPubKeyX": n.ReceiverViewPubKeyX.String(), "receiverViewPubKeyY": n.ReceiverViewPubKeyY.String(),
		"amount": n.Amount.String(), "assetID": n.AssetID.String(), "randomness": n.Randomness.String(), "memo": n.Memo,
	}
}
func disclosureJSON(d *pt.DisclosurePlaintextV1) map[string]any {
	return map[string]any{
		"plane": d.Plane, "outputIndex": d.OutputIndex, "policy": d.Policy, "disclosedFieldBitmap": d.DisclosedFieldBitmap,
		"commitment": d.Commitment.String(), "amount": d.Amount.String(), "assetID": d.AssetID.String(),
		"senderSpendKeyX": d.SenderSpendKeyX.String(), "senderSpendKeyY": d.SenderSpendKeyY.String(),
		"senderViewKeyX": d.SenderViewKeyX.String(), "senderViewKeyY": d.SenderViewKeyY.String(),
		"recipientSpendKeyX": d.RecipientSpendKeyX.String(), "recipientSpendKeyY": d.RecipientSpendKeyY.String(),
		"recipientViewKeyX": d.RecipientViewKeyX.String(), "recipientViewKeyY": d.RecipientViewKeyY.String(),
		"disclosureBlinding": d.DisclosureBlinding.String(),
	}
}
func digests(d *pt.DisclosurePlaintextV1) (string, string) {
	if d.Plane == pt.DisclosurePlaneUserV1 {
		transfer := must(pt.ComputeTransferDisclosureDigestBytes(d.Policy, d.OutputIndex, fixed(d.Commitment), d.Amount, d.AssetID,
			d.SenderSpendKeyX, d.SenderSpendKeyY, d.SenderViewKeyX, d.SenderViewKeyY,
			d.RecipientSpendKeyX, d.RecipientSpendKeyY, d.RecipientViewKeyX, d.RecipientViewKeyY, d.DisclosureBlinding))
		batch := must(pt.ComputeBatchUserDisclosureDigestV1(pt.BatchUserDisclosureV1Input{
			OutputIndex: d.OutputIndex, Commitment: d.Commitment, Policy: d.Policy, DisclosedFieldBitmap: d.DisclosedFieldBitmap,
			SelectedAmount: d.Amount, AssetID: d.AssetID, UserDisclosureBlinding: d.DisclosureBlinding,
			SelectedFromSpendKeyX: d.SenderSpendKeyX, SelectedFromSpendKeyY: d.SenderSpendKeyY,
			SelectedFromViewKeyX: d.SenderViewKeyX, SelectedFromViewKeyY: d.SenderViewKeyY,
			SelectedToSpendKeyX: d.RecipientSpendKeyX, SelectedToSpendKeyY: d.RecipientSpendKeyY,
			SelectedToViewKeyX: d.RecipientViewKeyX, SelectedToViewKeyY: d.RecipientViewKeyY,
		}))
		return hx(transfer), hx(fixed(batch))
	}
	transfer := must(pt.ComputeFullTransferDisclosureDigestBytes(d.OutputIndex, fixed(d.Commitment), d.Amount, d.AssetID,
		d.SenderSpendKeyX, d.SenderSpendKeyY, d.SenderViewKeyX, d.SenderViewKeyY,
		d.RecipientSpendKeyX, d.RecipientSpendKeyY, d.RecipientViewKeyX, d.RecipientViewKeyY, d.DisclosureBlinding))
	batch := must(pt.ComputeBatchFullDisclosureDigestV1(pt.BatchFullDisclosureV1Input{
		OutputIndex: d.OutputIndex, Commitment: d.Commitment, Amount: d.Amount, AssetID: d.AssetID,
		SenderSpendKeyX: d.SenderSpendKeyX, SenderSpendKeyY: d.SenderSpendKeyY,
		SenderViewKeyX: d.SenderViewKeyX, SenderViewKeyY: d.SenderViewKeyY,
		RecipientSpendKeyX: d.RecipientSpendKeyX, RecipientSpendKeyY: d.RecipientSpendKeyY,
		RecipientViewKeyX: d.RecipientViewKeyX, RecipientViewKeyY: d.RecipientViewKeyY, FullDisclosureBlinding: d.DisclosureBlinding,
	}))
	return hx(transfer), hx(fixed(batch))
}

func main() {
	originalReader := rand.Reader
	defer func() { rand.Reader = originalReader }()
	files := map[string]string{}
	for _, path := range []string{
		"x/privacy/types/fixed_payload.go", "x/privacy/types/note.go", "x/privacy/types/note_v1.go",
		"x/privacy/types/transfer_disclosure.go", "x/privacy/types/batch_contract.go", "x/privacy/types/amount.go",
		"x/privacy/amount/amount.go", "x/privacy/crypto/crypto.go", "x/privacy/crypto/ecies.go",
		"x/privacy/crypto/secret_point.go", "x/privacy/crypto/secret_scalar.go", "x/privacy/crypto/internal/ctbn254/scalarct/sample.go",
	} {
		data := must(os.ReadFile(path))
		digest := sha256.Sum256(data)
		files[path] = hx(digest[:])
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	sx, sy := xy(point(17))
	vx, vy := xy(point(19))
	tsx, tsy := xy(point(23))
	tvx, tvy := xy(point(29))
	targetX, targetY := xy(point(31))
	asset := pt.ComputeAssetIDV1("uclair")
	var notes, disclosures []map[string]any
	for i, amount := range []string{"0", "18446744073709551615", "18446744073709551616", "340282366920938463463374607431768211455"} {
		n := &pt.Note{ReceiverSpendPubKeyX: sx, ReceiverSpendPubKeyY: sy, ReceiverViewPubKeyX: vx, ReceiverViewPubKeyY: vy,
			Amount: decimal(amount), AssetID: asset, Randomness: big.NewInt(int64(13 + i)), Memo: "합성 codec 🧪"}
		plain := must(pt.MarshalNotePlaintextV1(n))
		must(pt.UnmarshalNotePlaintextV1(plain))
		rand.Reader = bytes.NewReader(entropy(i+1, false))
		rawDeposit := must(pc.Encrypt(plain, seed))
		if !bytes.Equal(must(pc.Decrypt(rawDeposit, seed)), plain) {
			panic("deposit round trip")
		}
		deposit := must(pt.WrapEncryptedEnvelopeV1(pt.EnvelopeDepositNoteV1, rawDeposit))
		rand.Reader = bytes.NewReader(entropy(i+11, true))
		rawTransfer, tag, err := pc.AsymEncryptWithViewTag(plain, *point(19), fixed(n.ComputeCommitment()), uint32(i))
		if err != nil {
			panic(err)
		}
		if !bytes.Equal(must(pc.AsymDecryptWithViewTag(rawTransfer, scalar(19), fixed(n.ComputeCommitment()), uint32(i), tag)), plain) {
			panic("transfer round trip")
		}
		transfer := must(pt.WrapEncryptedEnvelopeV1(pt.EnvelopeTransferNoteV1, rawTransfer))
		notes = append(notes, map[string]any{"note": noteJSON(n), "plaintext_hex": hx(plain), "commitment_hex": hx(fixed(n.ComputeCommitment())),
			"nullifier_hex": hx(fixed(n.ComputeNullifier())), "deposit_hex": hx(deposit), "deposit_entropy_hex": hx(entropy(i+1, false)),
			"transfer_hex": hx(transfer), "transfer_entropy_hex": hx(entropy(i+11, true)), "output_index": i, "view_tag_hex": hx(tag)})
	}
	for policy := uint32(1); policy <= 8; policy++ {
		d := &pt.DisclosurePlaintextV1{Plane: pt.DisclosurePlaneUserV1, OutputIndex: 31, Policy: policy, DisclosedFieldBitmap: policy,
			Commitment: big.NewInt(123), Amount: big.NewInt(0), AssetID: asset,
			SenderSpendKeyX: big.NewInt(0), SenderSpendKeyY: big.NewInt(0), SenderViewKeyX: big.NewInt(0), SenderViewKeyY: big.NewInt(0),
			RecipientSpendKeyX: big.NewInt(0), RecipientSpendKeyY: big.NewInt(0), RecipientViewKeyX: big.NewInt(0), RecipientViewKeyY: big.NewInt(0), DisclosureBlinding: big.NewInt(41)}
		if policy == 8 {
			d.Plane = pt.DisclosurePlaneFullV1
			d.Policy = pt.DisclosureFullMarkerV1
			d.DisclosedFieldBitmap = 7
		}
		if d.DisclosedFieldBitmap&1 != 0 {
			d.Amount = decimal("340282366920938463463374607431768211455")
		}
		if d.DisclosedFieldBitmap&4 != 0 {
			d.SenderSpendKeyX = sx
			d.SenderSpendKeyY = sy
			d.SenderViewKeyX = vx
			d.SenderViewKeyY = vy
		}
		if d.DisclosedFieldBitmap&2 != 0 {
			d.RecipientSpendKeyX = tsx
			d.RecipientSpendKeyY = tsy
			d.RecipientViewKeyX = tvx
			d.RecipientViewKeyY = tvy
		}
		plain := must(pt.MarshalDisclosurePlaintextV1(d))
		must(pt.UnmarshalDisclosurePlaintextV1(plain))
		transferDigest, batchDigest := digests(d)
		kinds := []pt.EncryptedEnvelopeKindV1{pt.EnvelopeUserDisclosureV1}
		if policy == 8 {
			kinds = []pt.EncryptedEnvelopeKindV1{pt.EnvelopeAuditDisclosureV1, pt.EnvelopeSelfViewDisclosureV1}
		}
		var envelopes []map[string]any
		for _, kind := range kinds {
			index := int(policy)*8 + int(kind)
			rand.Reader = bytes.NewReader(entropy(index, true))
			raw := must(pc.AsymEncrypt(plain, *point(31)))
			if !bytes.Equal(must(pc.AsymDecrypt(raw, scalar(31))), plain) {
				panic("disclosure round trip")
			}
			envelopes = append(envelopes, map[string]any{"kind": kind, "ciphertext_hex": hx(must(pt.WrapEncryptedEnvelopeV1(kind, raw))), "entropy_hex": hx(entropy(index, true))})
		}
		disclosures = append(disclosures, map[string]any{"disclosure": disclosureJSON(d), "plaintext_hex": hx(plain), "transfer_digest_hex": transferDigest, "batch_digest_hex": batchDigest, "envelopes": envelopes})
	}
	fixture := map[string]any{
		"source":    map[string]any{"release": "v0.6.1", "commit": "fad307abddd0daa1c880f2e423668f5c58a0e578", "files": files},
		"synthetic": map[string]any{"root_seed_hex": hx(seed), "note_view_scalar": "19", "disclosure_scalar": "31", "disclosure_target": map[string]string{"x": targetX.String(), "y": targetY.String()}},
		"notes":     notes, "disclosures": disclosures,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fixture); err != nil {
		panic(err)
	}
}
