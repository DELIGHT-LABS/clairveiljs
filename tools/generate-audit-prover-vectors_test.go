// Injected only into an isolated, exact Core v0.6.1 extraction. Never a runtime setup or production trust pin.
package circuit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/auditfield"
	"github.com/DELIGHT-LABS/clairveil/x/privacy/zk"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
)

func TestClairveilJSAuditProofFixtures(t *testing.T) {
	dir := os.Getenv("CLAIRVEIL_AUDIT_PROOF_FIXTURES")
	require.NotEmpty(t, dir, "explicit temporary development fixture directory required")
	require.NoError(t, os.MkdirAll(dir, 0700))
	sums := map[string]string{}
	descriptors := zk.AuditFieldArtifactDescriptors()
	for index, id := range zk.AuditFieldCircuitIDs() {
		t.Run(string(id), func(t *testing.T) {
			f := newAuditFixture(t, auditfield.Kind(index+1), 16, 32)
			definition := reflect.New(reflect.TypeOf(f.assignment).Elem()).Interface().(frontend.Circuit)
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, definition)
			require.NoError(t, err)
			pk, vk, err := groth16.Setup(ccs)
			require.NoError(t, err)
			full, err := frontend.NewWitness(f.assignment, ecc.BN254.ScalarField())
			require.NoError(t, err)
			proof, err := groth16.Prove(ccs, pk, full)
			require.NoError(t, err)
			public, err := full.Public()
			require.NoError(t, err)
			require.NoError(t, groth16.Verify(proof, vk, public))
			for offset, object := range []io.WriterTo{ccs, pk, vk} {
				descriptor := descriptors[index*3+offset]
				file, err := os.OpenFile(filepath.Join(dir, descriptor.Filename), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				require.NoError(t, err)
				h := sha256.New()
				_, err = object.WriteTo(io.MultiWriter(file, h))
				require.NoError(t, err)
				require.NoError(t, file.Close())
				sums[descriptor.ChecksumEnv] = hex.EncodeToString(h.Sum(nil))
			}
			var encoded bytes.Buffer
			_, err = proof.WriteTo(&encoded)
			require.NoError(t, err)
			pi := []string{}
			for _, v := range public.Vector().(fr.Vector) {
				pi = append(pi, v.String())
			}
			raw, err := json.MarshalIndent(map[string]any{"kind": index + 1, "circuitId": id, "publicInputs": pi, "proof": encoded.Bytes(), "constraints": ccs.GetNbConstraints(), "productionSetup": false}, "", "  ")
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, "proof-"+string(rune('1'+index))+".json"), append(raw, '\n'), 0600))
			t.Logf("actual Core circuit %s: constraints=%d public=%d proof_bytes=%d", id, ccs.GetNbConstraints(), len(pi), encoded.Len())
		})
	}
	if t.Failed() {
		return
	}
	manifest, err := zk.AuditFieldManifestFromChecksums("temporary-single-party-sdk-test-only", "", sums)
	require.NoError(t, err)
	raw, err := json.MarshalIndent(manifest, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, zk.ArtifactManifestFile), append(raw, '\n'), 0600))
}
