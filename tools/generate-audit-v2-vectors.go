// Run inside an extracted, unmodified Core v0.6.1 module. All scalars,
// nonces and artifact hashes below are public synthetic test values.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	pa "github.com/DELIGHT-LABS/clairveil/x/privacy/client/sdk/audit"
	pc "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto"
	af "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/auditfield"
	zk "github.com/DELIGHT-LABS/clairveil/x/privacy/zk"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func hx(b []byte) string           { return hex.EncodeToString(b) }
func digest(b []byte) string       { h := sha256.Sum256(b); return hx(h[:]) }
func be(n uint64, size int) []byte { return new(big.Int).SetUint64(n).FillBytes(make([]byte, size)) }

func main() {
	paths := []string{
		"x/privacy/client/sdk/provider/audit_v2.go", "x/privacy/client/sdk/audit/key_record.go",
		"x/privacy/client/sdk/audit/prepared.go", "x/privacy/crypto/auditfield/domains.go",
		"x/privacy/crypto/auditfield/pop.go", "x/privacy/crypto/auditfield/schema.go",
		"x/privacy/types/genesis.go", "x/privacy/zk/audit_field_contract.go",
		"x/privacy/zk/manifest.go", "x/privacy/zk/schema.go",
	}
	files := map[string]string{}
	for _, path := range paths {
		files[path] = digest(must(os.ReadFile(path)))
	}
	checksums := map[string]string{}
	for _, d := range zk.AuditFieldArtifactDescriptors() {
		checksums[d.ChecksumEnv] = digest([]byte("synthetic:" + d.Filename))
	}
	manifest := must(zk.AuditFieldManifestFromChecksums("synthetic", "2026-10-23T00:00:00Z", checksums))
	manifestBytes := append(must(json.MarshalIndent(manifest, "", "  ")), '\n')
	identityBytes := must(manifest.CircuitSetIdentity.Marshal())
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
	}
	network := must(af.NetworkDigest("clairveil-test-04", nonce))
	rows := []map[string]any{}
	for i, epoch := range []uint64{1, 2, 9007199254740993, ^uint64(0)} {
		activation, registered, origin := uint64(20), uint64(12), byte(1)
		if i == 0 {
			activation, registered, origin = 9, 9, 3
		}
		if i == 2 {
			activation, registered, origin = 9007199254741000, 9007199254740999, 2
		}
		sk := must(pc.ImportAuditSecretKeyBE32(be(uint64(3+i), 32)))
		key := must(pc.AuditKeyFromSecret(sk))
		rand.Reader = bytes.NewReader(be(uint64(11+i), 32))
		pop := must(pc.CreateAuditPoP96(sk, network, epoch, activation))
		proof := must(pop.Bytes())
		raw := bytes.NewBuffer(nil)
		for _, v := range [][]byte{be(1, 2), be(epoch, 8), key.IDBytes(), be(uint64(af.AuditSuite), 2), key.Point().Bytes(), be(activation, 8), be(registered, 8), {origin}, bytes.Repeat([]byte{byte(i + 1)}, 32), be(registered, 8), proof} {
			raw.Write(v)
		}
		record := must(pa.ParseKeyRecord(raw.Bytes(), network, 10))
		state := activation + 1
		var artifactHash [32]byte
		copy(artifactHash[:], must(hex.DecodeString(digest(manifestBytes))))
		must(record.Snapshot(network, int64(state), artifactHash))
		rows = append(rows, map[string]any{"epoch": fmt.Sprint(epoch), "state_height": fmt.Sprint(state), "activation_height": fmt.Sprint(activation), "registered_height": fmt.Sprint(registered), "origin_kind": origin, "record_hex": hx(raw.Bytes()), "key_id_hex": hx(key.IDBytes()), "public_key_hex": hx(key.Point().Bytes()), "pop_hex": hx(proof)})
	}
	valid := must(hex.DecodeString(rows[1]["record_hex"].(string)))
	bad := []map[string]any{}
	addBad := func(name string, raw []byte) {
		_, err := pa.ParseKeyRecord(raw, network, 10)
		if err == nil {
			panic(name + " accepted")
		}
		bad = append(bad, map[string]any{"name": name, "record_hex": hx(raw)})
	}
	addBad("truncated", valid[:len(valid)-1])
	addBad("trailing", append(bytes.Clone(valid), 0))
	for _, item := range []struct {
		name   string
		offset int
	}{{"version", 1}, {"key-id", 10}, {"suite", 43}, {"origin-kind", 124}, {"origin-height", 164}, {"proof-response", len(valid) - 1}, {"epoch", 9}, {"activation", 115}} {
		name, offset := item.name, item.offset
		raw := bytes.Clone(valid)
		raw[offset] ^= 1
		addBad(name, raw)
	}
	raw := bytes.Clone(valid)
	binary.BigEndian.PutUint64(raw[108:116], 1<<63)
	addBad("height-overflow", raw)
	result := map[string]any{"source": map[string]any{"release": "v0.6.1", "commit": "fad307abddd0daa1c880f2e423668f5c58a0e578", "files": files}, "synthetic": true, "chain_id": "clairveil-test-04", "network_nonce_hex": hx(nonce[:]), "network_digest_hex": hx(network[:]), "initial_height": "10", "identity": manifest.CircuitSetIdentity, "identity_base64": base64.StdEncoding.EncodeToString(identityBytes), "manifest_base64": base64.StdEncoding.EncodeToString(manifestBytes), "artifact_hash": digest(manifestBytes), "records": rows, "invalid_records": bad}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		panic(err)
	}
}
