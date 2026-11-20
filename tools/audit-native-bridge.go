// Wallet-local pipe bridge for pinned Core v0.6.1. No secret CLI arguments,
// JSON, stderr diagnostics, files, network, or caller-selected entropy.
package main

import (
	"bytes"
	af "github.com/DELIGHT-LABS/clairveil/x/privacy/crypto/auditfield"
	"io"
	"os"
)

func run() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 6342))
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) < 5 || !bytes.Equal(raw[:4], []byte("CVA2")) {
		return io.ErrUnexpectedEOF
	}
	kind := af.Kind(raw[4])
	count, err := kind.PlaintextFieldCount()
	if err != nil {
		return err
	}
	if len(raw) != 5+32*(21+count) {
		return io.ErrUnexpectedEOF
	}
	fields := make([]af.Field32, 21+count)
	defer clear(fields)
	for i := range fields {
		fields[i], err = af.ParseField32(raw[5+32*i : 5+32*(i+1)])
		if err != nil {
			return err
		}
	}
	context, err := af.NewAuditContext(kind, fields[:21])
	if err != nil {
		return err
	}
	plain, err := af.NewAuditPlain(kind, fields[21:])
	if err != nil {
		return err
	}
	envelope, _, witness, err := af.EncryptAuditForProver(context, plain)
	if err != nil {
		return err
	}
	defer witness.Clear()
	scalar, err := witness.ToProverWitnessBE32()
	if err != nil {
		return err
	}
	defer clear(scalar[:])
	wire, err := envelope.Bytes()
	if err != nil {
		return err
	}
	response := append(append([]byte("CVA2"), wire...), scalar[:]...)
	defer clear(response)
	_, err = os.Stdout.Write(response)
	return err
}
func main() {
	if run() != nil {
		os.Exit(1)
	}
}
