// Built only against the pinned Core commit by build-audit-native.js.
// Public data in/out. The registry reads the exact immutable manifest and VK bytes supplied by the pinned host adapter.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/DELIGHT-LABS/clairveil/x/privacy/zk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/logger"
)

func verify() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 13+23*32+164+2*65536+1))
	if err != nil || len(raw) < 913 || string(raw[:4]) != "CVV2" {
		return fmt.Errorf("frame")
	}
	kind := int(raw[4])
	ml := int(binary.BigEndian.Uint32(raw[5:9]))
	kl := int(binary.BigEndian.Uint32(raw[9:13]))
	if kind < 1 || kind > 4 || ml < 1 || ml > 65536 || kl < 1 || kl > 65536 || len(raw) != 913+ml+kl {
		return fmt.Errorf("length")
	}
	proof := raw[749:913]
	manifest := raw[913 : 913+ml]
	key := raw[913+ml:]
	var m zk.RuntimeArtifactManifest
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("manifest trailing")
	}
	if !m.DevelopmentOnly {
		return fmt.Errorf("development bundle required")
	}
	if err := zk.ValidateAuditFieldArtifactManifest(&m); err != nil {
		return err
	}
	descriptor := m.Artifacts[(kind-1)*3+2]
	registry, err := zk.NewArtifactRegistry(zk.ArtifactRegistryConfig{CircuitSetID: zk.AuditFieldCircuitSetID, RuntimeEnvironment: zk.ZKRuntimeEnvironmentDevelopment,
		LookupEnv: func(string) (string, bool) { return "", false }, ReadFile: func(path string) ([]byte, error) {
			switch filepath.Base(path) {
			case zk.ArtifactManifestFile:
				return bytes.Clone(manifest), nil
			case descriptor.Filename:
				return bytes.Clone(key), nil
			default:
				return nil, fmt.Errorf("unexpected artifact")
			}
		}})
	if err != nil {
		return err
	}
	w, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	values := make(chan any, 23)
	for i := 0; i < 23; i++ {
		v := raw[13+i*32 : 45+i*32]
		var f fr.Element
		if err := f.SetBytesCanonical(v); err != nil {
			return err
		}
		values <- new(big.Int).SetBytes(v)
	}
	close(values)
	if err := w.Fill(23, 0, values); err != nil {
		return err
	}
	return registry.VerifyProof(zk.AuditFieldCircuitIDs()[kind-1], proof, w, m.CircuitSetIdentity)
}
func main() {
	logger.Disable()
	if err := verify(); err != nil {
		os.Exit(1)
	}
	if _, err := os.Stdout.Write([]byte("CVV2")); err != nil {
		os.Exit(1)
	}
}
