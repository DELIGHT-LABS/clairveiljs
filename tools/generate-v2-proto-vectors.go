// Run from an extracted Core v0.6.1 module, never against the JS codecs.
// These synthetic values exercise wire fields and integer boundaries only.
package main

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"os"

	privacyv2 "github.com/DELIGHT-LABS/clairveil/x/privacy/types/v2"
	"github.com/cosmos/gogoproto/proto"
)

func main() {
	audit := &privacyv2.AuditAuthorization{KeyId: []byte{1, 2}, Epoch: math.MaxUint64, Envelope: []byte{3, 4, 5}}
	output := &privacyv2.OutputEffect{
		Commitment: []byte{6, 7}, Ciphertext: []byte{8, 9}, ViewTag: []byte{10, 11},
		UserPrivacyPolicy: 7, UserDisclosureMode: 2, UserDisclosureDigest: []byte{12},
		UserDisclosureTargetPubkey: []byte{13}, UserDisclosurePayload: []byte{14},
		SelfFullDisclosureDigest: []byte{15}, SelfViewDisclosurePayload: []byte{16},
	}
	messages := []proto.Message{
		audit, output,
		&privacyv2.MsgDeposit{Creator: "actor", Amount: "340282366920938463463374607431768211455uclair", Output: output, Proof: []byte{17, 18}, ExpiresAtUnix: math.MaxInt64, Audit: audit},
		&privacyv2.MsgWithdraw{Creator: "actor", Amount: "1uclair", Recipient: "recipient", Root: []byte{19}, Nullifier: []byte{20}, Proof: []byte{21}, ExpiresAtUnix: math.MaxInt64, Audit: audit},
		&privacyv2.MsgTransfer{Creator: "actor", Root: []byte{22}, Nullifiers: [][]byte{{23}, {24}}, Outputs: []*privacyv2.OutputEffect{output, output}, Proof: []byte{25}, ExpiresAtUnix: math.MaxInt64, Audit: audit},
		&privacyv2.MsgBatchTransfer{Creator: "actor", Root: []byte{26}, Nullifiers: [][]byte{{27}, {28}}, Outputs: []*privacyv2.OutputEffect{output, output}, Proof: []byte{29}, ExpiresAtUnix: math.MaxInt64, Audit: audit},
		&privacyv2.MsgScheduleAuditKeyEpoch{Authority: "authority", Epoch: math.MaxUint64, ActivationHeight: math.MaxUint64, PublicKey: []byte{30}, Suite: 2, PossessionProof: []byte{31}},
		&privacyv2.MsgCancelPendingAuditEpoch{Authority: "authority", Epoch: math.MaxUint64},
		&privacyv2.MsgSetPrivacyHalt{Authority: "authority", Halted: true},
		&privacyv2.QueryAuditKeyRequest{Epoch: math.MaxUint64},
		&privacyv2.QueryAuditRecordResponse{Record: []byte{32}, StoreKey: []byte{33}, StateHeight: math.MaxInt64},
		&privacyv2.QueryAuditKeyScheduleResponse{ActiveEpoch: math.MaxUint64, NextActivationHeight: math.MaxUint64, NextEpoch: math.MaxUint64, Halted: true, StateHeight: math.MaxInt64},
		&privacyv2.QueryAuditConfigurationResponse{NetworkNonce: []byte{34}, InitialHeight: math.MaxUint64, CircuitIdentity: []byte{35}, StateHeight: math.MaxInt64},
	}
	type vector struct {
		TypeURL string `json:"type_url"`
		Hex     string `json:"hex"`
	}
	vectors := make([]vector, 0, len(messages))
	for _, message := range messages {
		encoded, err := proto.Marshal(message)
		if err != nil {
			panic(err)
		}
		vectors = append(vectors, vector{"/" + proto.MessageName(message), hex.EncodeToString(encoded)})
	}
	fixture := struct {
		Source  map[string]string `json:"source"`
		Scope   string            `json:"scope"`
		Vectors []vector          `json:"vectors"`
	}{
		map[string]string{"repository": "https://github.com/DELIGHT-LABS/clairveil", "release": "v0.6.1", "commit": "fad307abddd0daa1c880f2e423668f5c58a0e578"},
		"synthetic protobuf encoding only", vectors,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fixture); err != nil {
		panic(err)
	}
}
