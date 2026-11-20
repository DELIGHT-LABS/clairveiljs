// Test-only loopback proverd. Synthetic note/key material, exact Core implementation, development artifacts.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	amount "github.com/DELIGHT-LABS/clairveil/x/privacy/amount"
	audit "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/audit"
	deposit "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/deposit"
	service "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/proverservice"
	transport "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/provertransport"
	crypto "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto"
	af "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/auditfield"
	types "github.com/DELIGHT-LABS/clairveil/x/privacy/types"
	v2 "github.com/DELIGHT-LABS/clairveil/x/privacy/types/v2"
	zk "github.com/DELIGHT-LABS/clairveil/x/privacy/zk"
	tedwards "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/logger"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func must[T any](v T, e error) T {
	if e != nil {
		panic(e)
	}
	return v
}
func main() {
	logger.Disable()
	sdk.GetConfig().SetBech32PrefixForAccount("clair", "clairpub")
	if len(os.Args) != 3 { panic("two fixture arguments required") }
	serveOnly := os.Args[1] == "serve"
	dir, configPath := os.Args[1], os.Args[2]
	if serveOnly { dir = os.Args[2] }
	manifest := must(os.ReadFile(filepath.Join(dir, zk.ArtifactManifestFile)))
	artifactHash := sha256.Sum256(manifest)
	registry := must(zk.NewArtifactRegistry(zk.ArtifactRegistryConfig{ArtifactDir: dir, CircuitSetID: zk.AuditFieldCircuitSetID, RuntimeEnvironment: zk.ZKRuntimeEnvironmentDevelopment}))
	identity := must(registry.LocalCircuitSetIdentity())
	if serveOnly {
		listener := must(net.Listen("tcp", "127.0.0.1:0"))
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"baseUrl": "http://" + listener.Addr().String(), "identityBytes": must(identity.Marshal())}); err != nil { panic(err) }
		handler := service.NewAuditFieldHandler(registry, identity, time.Now, io.Discard, service.DefaultMaxRequestBz, "")
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		if err := server.Serve(listener); err != nil { panic(err) }
		return
	}
	var config struct {
		Network string `json:"network_digest_hex"`
		Records []struct {
			Key string `json:"public_key_hex"`
		} `json:"records"`
	}
	if err := json.Unmarshal(must(os.ReadFile(configPath)), &config); err != nil {
		panic(err)
	}
	key := must(af.NewAuditKeyFromPoint64(must(hex.DecodeString(config.Records[1].Key))))
	var network [32]byte
	copy(network[:], must(hex.DecodeString(config.Network)))
	snapshot := audit.Snapshot{Network: network, Epoch: 2, Key: key, StateHeight: 21, ArtifactHash: artifactHash}
	curve := tedwards.GetEdwardsCurve()
	var spend, view tedwards.PointAffine
	spend.ScalarMultiplication(&curve.Base, big.NewInt(11))
	view.ScalarMultiplication(&curve.Base, big.NewInt(13))
	sx, sy, err := crypto.PublicPointFieldValues(spend)
	if err != nil {
		panic(err)
	}
	vx, vy, err := crypto.PublicPointFieldValues(view)
	if err != nil {
		panic(err)
	}
	value := must(amount.Parse("100000000000000000000"))
	note := must(types.NewSecretNoteV1(sx, sy, vx, vy, value, types.ComputeSecretAssetIDV1("uclair"), crypto.FieldValueFromUint64(17), ""))
	commitment := must(note.CommitmentV1()).Bytes()
	cipherSize := must(types.EncryptedEnvelopeV1Size(types.EnvelopeDepositNoteV1))
	ciphertext := must(types.WrapEncryptedEnvelopeV1(types.EnvelopeDepositNoteV1, make([]byte, cipherSize-types.EncryptedEnvelopeV1HeaderSize)))
	creator := sdk.AccAddress(bytes.Repeat([]byte{0x31}, 20)).String()
	expiry := time.Now().Add(time.Hour).Unix()
	output := &v2.OutputEffect{Commitment: commitment[:], Ciphertext: ciphertext}
	prepared := must(deposit.PrepareAuditV2FromNormalNote(snapshot, creator, value.String()+"uclair", *note, output, expiry))
	defer prepared.Clear()
	full := must(deposit.BuildAuditV2Witness(prepared, *note))
	request := must(transport.NewAuditFieldProofRequest(prepared, full))
	scalar := must(prepared.ProverScalarBE32())
	envelope := must(prepared.EnvelopeBytes())
	plain := [][]byte{}
	assetBytes := note.AssetID.Bytes()
	am := note.Amount.Bytes32()
	sxBytes := sx.Bytes()
	syBytes := sy.Bytes()
	vxBytes := vx.Bytes()
	vyBytes := vy.Bytes()
	plain = append(plain, assetBytes[:], am[:], sxBytes[:], syBytes[:], vxBytes[:], vyBytes[:])
	listener := must(net.Listen("tcp", "127.0.0.1:0"))
	fixture := map[string]any{"baseUrl": "http://" + listener.Addr().String(), "identityBytes": must(identity.Marshal()), "plaintext": plain, "envelope": envelope, "syntheticWitness": scalar[:], "request": request,
		"message": map[string]any{"creator": creator, "amount": value.String() + "uclair", "expiresAtUnix": expiry, "output": map[string]any{"commitment": commitment[:], "ciphertext": ciphertext}}}
	raw := must(json.MarshalIndent(fixture, "", "  "))
	if err := os.WriteFile(filepath.Join(dir, "deposit.json"), append(raw, '\n'), 0600); err != nil {
		panic(err)
	}
	handler := service.NewAuditFieldHandler(registry, identity, time.Now, io.Discard, service.DefaultMaxRequestBz, "")
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
