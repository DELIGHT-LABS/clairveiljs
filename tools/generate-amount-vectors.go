// Run inside an extracted Core v0.6.1 module. Only synthetic public amounts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/DELIGHT-LABS/clairveil/x/privacy/amount"
)

type parsed struct {
	Input   string `json:"input"`
	Valid   bool   `json:"valid"`
	Decimal string `json:"decimal,omitempty"`
	JSON    string `json:"json,omitempty"`
}
type added struct {
	Left  string `json:"left"`
	Right string `json:"right"`
	Valid bool   `json:"valid"`
	Total string `json:"total,omitempty"`
}

func main() {
	source, err := os.ReadFile("x/privacy/amount/amount.go")
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(source)
	fixture := struct {
		Source map[string]string `json:"source"`
		Parse  []parsed          `json:"parse"`
		Add    []added           `json:"add"`
	}{Source: map[string]string{
		"release": "v0.6.1", "commit": "fad307abddd0daa1c880f2e423668f5c58a0e578",
		"path": "x/privacy/amount/amount.go", "sha256": hex.EncodeToString(digest[:]),
	}}
	for _, input := range []string{"0", "1", "18446744073709551615", "18446744073709551616", amount.MaxDecimal,
		"340282366920938463463374607431768211456", "-1", "-0", "+1", "", "00", "01", " 1", "1 ", "1\n", "1.0", "1e2", "１２"} {
		value, err := amount.Parse(input)
		row := parsed{Input: input, Valid: err == nil}
		if err == nil {
			encoded, err := json.Marshal(value)
			if err != nil {
				panic(err)
			}
			row.Decimal, row.JSON = value.String(), string(encoded)
		}
		fixture.Parse = append(fixture.Parse, row)
	}
	for _, pair := range [][2]string{{"0", "0"}, {"18446744073709551615", "1"}, {amount.MaxDecimal, "0"},
		{"340282366920938463463374607431768211454", "1"}, {amount.MaxDecimal, "1"}, {amount.MaxDecimal, amount.MaxDecimal}} {
		left, err := amount.Parse(pair[0])
		if err != nil {
			panic(err)
		}
		right, err := amount.Parse(pair[1])
		if err != nil {
			panic(err)
		}
		total, err := left.Add(right)
		row := added{Left: pair[0], Right: pair[1], Valid: err == nil}
		if err == nil {
			row.Total = total.String()
		}
		fixture.Add = append(fixture.Add, row)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(fixture); err != nil {
		panic(err)
	}
}
