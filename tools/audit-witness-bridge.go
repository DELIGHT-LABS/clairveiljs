// Build inside pinned Core's x/privacy/crypto/cmd. This adapter owns framing,
// not cryptography. Private input/output use bounded pipes; errors are silent.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"regexp"
	"strconv"

	audit "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/audit"
	deposit "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/deposit"
	transport "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/provertransport"
	scan "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/scan"
	transfer "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/transfer"
	withdraw "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/withdraw"
	privacycrypto "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto"
	af "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/auditfield"
	"github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/internal/ctbn254/secretmem"
	types "github.com/DELIGHT-LABS/clairveil/x/privacy/types"
	v2 "github.com/DELIGHT-LABS/clairveil/x/privacy/types/v2"
	fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/logger"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/gogoproto/proto"
)

var invalid = errors.New("invalid native witness request")

type snapshotWire struct {
	Network  []byte
	Artifact []byte
	Epoch    string
	Height   string
	Key      []byte
}
type pathWire struct {
	Commitment string
	Root       []byte
	Path       []string
	Helper     []uint32
}
type disclosureWire struct {
	Policy          uint32
	Mode            uint32
	Target          []byte
	SelfView        []byte
	DisableSelfView bool
}
type request struct {
	Version        string
	Kind           uint8
	AccountPrefix  string
	ChainID        string
	Creator        string
	Recipient      string
	Amount         string
	ExpiresAtUnix  string
	Snapshot       snapshotWire
	Notes          [][]byte
	Output         []byte
	SpendScalar    []byte
	RecipientSpend []byte
	RecipientView  []byte
	Paths          []pathWire
	Disclosure     disclosureWire
}

func integer(s string, bits int) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, bits)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return 0, invalid
	}
	return n, nil
}
func (r *request) clear() {
	for _, n := range r.Notes {
		clear(n)
	}
	clear(r.SpendScalar)
}
func snapshot(s snapshotWire) (audit.Snapshot, error) {
	var out audit.Snapshot
	if len(s.Network) != 32 || len(s.Artifact) != 32 || len(s.Key) != 64 {
		return out, invalid
	}
	copy(out.Network[:], s.Network)
	copy(out.ArtifactHash[:], s.Artifact)
	e, e1 := integer(s.Epoch, 64)
	h, e2 := integer(s.Height, 63)
	key, e3 := af.NewAuditKeyFromPoint64(s.Key)
	if e1 != nil || e2 != nil || e3 != nil || h == 0 {
		return out, invalid
	}
	out.Epoch = e
	out.StateHeight = int64(h)
	out.Key = key
	return out, out.Validate()
}

type paths map[string]pathWire

func (p paths) LookupMerklePath(_ context.Context, commitment string) (*transfer.MerklePathResult, error) {
	v, ok := p[commitment]
	if !ok {
		return nil, invalid
	}
	return &transfer.MerklePathResult{Root: bytes.Clone(v.Root), Path: append([]string(nil), v.Path...), PathHelper: append([]uint32(nil), v.Helper...)}, nil
}

type withdrawPaths struct{ p paths }

func (p withdrawPaths) LookupMerklePath(ctx context.Context, commitment string) (*withdraw.MerklePathResult, error) {
	v, e := p.p.LookupMerklePath(ctx, commitment)
	if e != nil {
		return nil, e
	}
	return &withdraw.MerklePathResult{Root: v.Root, Path: v.Path, PathHelper: v.PathHelper}, nil
}

type signer struct{ key privacycrypto.SecretScalar }

func (s signer) SignSpendIntent(v *big.Int) ([]byte, error) {
	var m [32]byte
	v.FillBytes(m[:])
	return privacycrypto.SignOwnerIntent(m, s.key, nil)
}
func point(note types.SecretNoteV1, spend bool) (*tedwards.PointAffine, error) {
	x, y := note.ReceiverViewPubKeyX, note.ReceiverViewPubKeyY
	if spend {
		x, y = note.ReceiverSpendPubKeyX, note.ReceiverSpendPubKeyY
	}
	p, e := privacycrypto.LegacyCompressedPointFromFieldValues(x, y)
	if e != nil {
		return nil, e
	}
	return privacycrypto.DecodeCanonicalPoint(p[:])
}
func prepare(raw []byte) ([]byte, error) {
	var r request
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil {
		r.clear()
		return nil, invalid
	}
	defer r.clear()
	if d.Decode(&struct{}{}) != io.EOF || r.Version != "audit-witness-v2" || r.Kind < 1 || r.Kind > 3 ||
		!regexp.MustCompile(`^[a-z][a-z02-9]{0,15}$`).MatchString(r.AccountPrefix) || len(r.ChainID) == 0 || len(r.ChainID) > 128 {
		return nil, invalid
	}
	sdk.GetConfig().SetBech32PrefixForAccount(r.AccountPrefix, r.AccountPrefix+"pub")
	s, e := snapshot(r.Snapshot)
	if e != nil {
		return nil, invalid
	}
	expires, e := integer(r.ExpiresAtUnix, 63)
	if e != nil || expires == 0 {
		return nil, invalid
	}
	creator, e := sdk.AccAddressFromBech32(r.Creator)
	if e != nil || creator.String() != r.Creator {
		return nil, invalid
	}
	coin, e := sdk.ParseCoinNormalized(r.Amount)
	if e != nil || coin.String() != r.Amount || types.ValidateShieldedAmount("amount", coin.Amount.BigInt()) != nil {
		return nil, invalid
	}
	noteCount := 1
	if r.Kind == 3 {
		noteCount = 2
	}
	if len(r.Notes) != noteCount {
		return nil, invalid
	}
	notes := make([]scan.SecretFoundNote, noteCount)
	for i, raw := range r.Notes {
		n, e := types.UnmarshalSecretNotePlaintextV1(raw)
		if e != nil {
			return nil, invalid
		}
		notes[i] = scan.SecretFoundNote{Note: *n}
	}
	var prepared *audit.Prepared
	var full witness.Witness
	if r.Kind == 1 {
		if len(r.SpendScalar) != 0 || len(r.Paths) != 0 || r.Recipient != "" {
			return nil, invalid
		}
		var out v2.OutputEffect
		if out.Unmarshal(r.Output) != nil {
			return nil, invalid
		}
		canonical, e := out.Marshal()
		if e != nil || !bytes.Equal(canonical, r.Output) {
			return nil, invalid
		}
		prepared, e = deposit.PrepareAuditV2FromNormalNote(s, r.Creator, r.Amount, notes[0].Note, &out, int64(expires))
		if e != nil {
			return nil, invalid
		}
		defer prepared.Clear()
		full, e = deposit.BuildAuditV2Witness(prepared, notes[0].Note)
	} else {
		if len(r.Output) != 0 || len(r.Paths) != noteCount || !coin.IsPositive() {
			return nil, invalid
		}
		key, e1 := privacycrypto.ImportNonzeroScalarBE32(r.SpendScalar)
		if e1 != nil {
			return nil, invalid
		}
		defer secretmem.Clear(&key)
		pub, e1 := privacycrypto.PublicKey(key)
		if e1 != nil {
			return nil, invalid
		}
		owned, e1 := point(notes[0].Note, true)
		if e1 != nil || !pub.Equal(owned) {
			return nil, invalid
		}
		p := paths{}
		for _, v := range r.Paths {
			if len(v.Path) != 32 || len(v.Helper) != 32 || len(v.Root) != 32 || len(v.Commitment) != 64 {
				return nil, invalid
			}
			if _, exists := p[v.Commitment]; exists {
				return nil, invalid
			}
			if _, e := privacycrypto.ParseFieldValueBE32(v.Root); e != nil {
				return nil, invalid
			}
			for i, h := range v.Path {
				b, e := hex.DecodeString(h)
				if e != nil || hex.EncodeToString(b) != h || v.Helper[i] > 1 {
					return nil, invalid
				}
				if _, e = privacycrypto.ParseFieldValueBE32(b); e != nil {
					return nil, invalid
				}
			}
			p[v.Commitment] = v
		}
		signer := signer{key}
		if r.Kind == 2 {
			recipient, e1 := sdk.AccAddressFromBech32(r.Recipient)
			if e1 != nil || recipient.String() != r.Recipient {
				return nil, invalid
			}
			normal, e1 := withdraw.PrepareSpendWithdraw(context.Background(), withdrawPaths{p}, signer, withdraw.PrepareSpendWithdrawInput{Note: notes[0], RecipientBytes: recipient, ChainID: r.ChainID, ExpiresAtUnix: int64(expires)})
			if e1 != nil {
				return nil, invalid
			}
			prepared, e = withdraw.PrepareAuditV2FromSpend(s, normal, r.Creator, r.Recipient, r.Amount)
			if e != nil {
				return nil, invalid
			}
			defer prepared.Clear()
			full, e = withdraw.BuildAuditV2Witness(prepared, normal, signer.SignSpendIntent)
		} else {
			if r.Recipient != "" {
				return nil, invalid
			}
			rs, e1 := privacycrypto.DecodeCanonicalPoint(r.RecipientSpend)
			rv, e2 := privacycrypto.DecodeCanonicalPoint(r.RecipientView)
			sv, e3 := point(notes[0].Note, false)
			if e1 != nil || e2 != nil || e3 != nil {
				return nil, invalid
			}
			dc := transfer.AuditV2DisclosureConfig{UserPrivacyPolicy: r.Disclosure.Policy, UserDisclosureMode: types.UserDisclosureMode(r.Disclosure.Mode), DisableSelfViewDisclosure: r.Disclosure.DisableSelfView}
			if len(r.Disclosure.Target) > 0 {
				dc.UserDisclosureTargetPubKey, e = privacycrypto.DecodeCanonicalPoint(r.Disclosure.Target)
				if e != nil {
					return nil, invalid
				}
				dc.UserDisclosureTargetPubKeyBz = bytes.Clone(r.Disclosure.Target)
			}
			if !r.Disclosure.DisableSelfView {
				dc.SelfViewDisclosureTargetPubKey, e = privacycrypto.DecodeCanonicalPoint(r.Disclosure.SelfView)
				if e != nil {
					return nil, invalid
				}
			}
			prepared, full, e = transfer.PrepareAuditV2Transfer(context.Background(), p, s, r.Creator, int64(expires), transfer.PrepareJoinSplitInput{Inputs: [2]scan.SecretFoundNote{notes[0], notes[1]}, RecipientSpendPubKey: rs, RecipientViewPubKey: rv, TransferAmount: coin.Amount.BigInt(), SenderSpendPubKey: owned, SenderViewPubKey: sv}, coin.Denom, dc, signer.SignSpendIntent)
			if prepared != nil {
				defer prepared.Clear()
			}
		}
	}
	if e != nil || full == nil || prepared == nil {
		return nil, invalid
	}
	defer clear(full.Vector().(fr.Vector))
	proofRequest, e := transport.NewAuditFieldProofRequest(prepared, full)
	if e != nil {
		return nil, invalid
	}
	defer clear(proofRequest.Witness)
	envelope, e := prepared.EnvelopeBytes()
	if e != nil {
		return nil, invalid
	}
	scalar, e := prepared.ProverScalarBE32()
	if e != nil {
		return nil, invalid
	}
	defer clear(scalar[:])
	au := &v2.AuditAuthorization{KeyId: s.Key.IDBytes(), Epoch: s.Epoch, Envelope: envelope}
	pi := prepared.PublicInputs()
	outputs := prepared.OutputEffects()
	var message proto.Message
	switch r.Kind {
	case 1:
		message = &v2.MsgDeposit{Creator: r.Creator, Amount: r.Amount, Output: outputs[0], ExpiresAtUnix: int64(expires), Audit: au}
	case 2:
		n, e := notes[0].Note.NullifierV1()
		if e != nil {
			return nil, invalid
		}
		b := n.Bytes()
		message = &v2.MsgWithdraw{Creator: r.Creator, Recipient: r.Recipient, Amount: r.Amount, Root: pi[8].Bytes(), Nullifier: b[:], ExpiresAtUnix: int64(expires), Audit: au}
	case 3:
		ns := make([][]byte, 2)
		for i, n := range notes {
			v, e := n.Note.NullifierV1()
			if e != nil {
				return nil, invalid
			}
			b := v.Bytes()
			ns[i] = bytes.Clone(b[:])
		}
		message = &v2.MsgTransfer{Creator: r.Creator, Root: pi[8].Bytes(), Nullifiers: ns, Outputs: outputs, ExpiresAtUnix: int64(expires), Audit: au}
	}
	m, e := proto.Marshal(message)
	if e != nil {
		return nil, invalid
	}
	var response bytes.Buffer
	response.WriteString("CVW2")
	response.WriteByte(r.Kind)
	binary.Write(&response, binary.BigEndian, uint32(len(m)))
	response.Write(m)
	response.Write(scalar[:])
	binary.Write(&response, binary.BigEndian, uint32(len(proofRequest.Witness)))
	response.Write(proofRequest.Witness)
	return response.Bytes(), nil
}
func run() error {
	logger.Disable()
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 32769))
	if e != nil || len(raw) > 32768 {
		clear(raw)
		return invalid
	}
	defer clear(raw)
	response, e := prepare(raw)
	if e != nil {
		return invalid
	}
	defer clear(response)
	_, e = os.Stdout.Write(response)
	return e
}
func main() {
	if run() != nil {
		os.Exit(1)
	}
}
