// Run from the pinned Maroo module. Synthetic ABI bytes, not executable proofs.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type audit struct { KeyId []byte; Epoch uint64; Envelope []byte }
type output struct {
	Commitment []byte; Ciphertext []byte; ViewTag []byte
	UserPrivacyPolicy uint32; UserDisclosureMode uint32
	UserDisclosureDigest []byte; UserDisclosureTargetPubkey []byte
	UserDisclosurePayload []byte; SelfFullDisclosureDigest []byte; SelfViewDisclosurePayload []byte
}
type deposit struct { Output output; Proof []byte; ExpiresAtUnix uint64; Audit audit }
type transfer struct { Proof []byte; Root []byte; Nullifiers [][]byte; Outputs []output; ExpiresAtUnix uint64; Audit audit }
type withdraw struct { Proof []byte; Root []byte; Nullifier []byte; Amount string; Recipient common.Address; ExpiresAtUnix uint64; Audit audit }

func main() {
	raw, err := os.ReadFile("precompiles/privacy/IPrivacy.json"); if err != nil { panic(err) }
	a, err := abi.JSON(bytes.NewReader(raw)); if err != nil { panic(err) }
	o := output{[]byte{6,7}, []byte{8,9}, []byte{10,11}, 7, 2, []byte{12}, []byte{13}, []byte{14}, []byte{15}, []byte{16}}
	au := audit{[]byte{1,2}, math.MaxUint64, []byte{3,4,5}}
	cases := map[string]interface{}{
		"deposit": deposit{o, []byte{17,18}, math.MaxInt64, au},
		"transfer": transfer{[]byte{25}, []byte{22}, [][]byte{{23},{24}}, []output{o,o}, math.MaxInt64, au},
		"withdraw": withdraw{[]byte{21}, []byte{19}, []byte{20}, "340282366920938463463374607431768211455uclair", common.HexToAddress("0x0123456789012345678901234567890123456789"), math.MaxInt64, au},
	}
	vectors := make(map[string]interface{})
	for name, value := range cases {
		encoded, err := a.Pack(name, value); if err != nil { panic(err) }
		vectors[name] = map[string]interface{}{"signature": a.Methods[name].Sig, "hex": "0x"+hex.EncodeToString(encoded)}
	}
	sum := sha256.Sum256(raw)
	fixture := map[string]interface{}{"source": map[string]string{"repository":"https://github.com/Hashed-Open-Finance/maroo", "commit":"823f6752e89a8d7157bd90973e7b1f9093e0ec10", "core":"v0.6.1", "abiSha256":hex.EncodeToString(sum[:])}, "scope":"synthetic direct transaction ABI encoding only", "vectors":vectors}
	e := json.NewEncoder(os.Stdout); e.SetIndent("", "  "); if err := e.Encode(fixture); err != nil { panic(err) }
}
