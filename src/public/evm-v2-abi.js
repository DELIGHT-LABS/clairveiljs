// Maroo 823f6752e89a8d7157bd90973e7b1f9093e0ec10; Core v0.6.1.
// Only the three direct transaction entrypoints; no relay or batch surface.
export const evmPrivacyV2Abi = [
  {
    "inputs": [
      {
        "components": [
          {
            "components": [
              {
                "internalType": "bytes",
                "name": "commitment",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "ciphertext",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "viewTag",
                "type": "bytes"
              },
              {
                "internalType": "uint32",
                "name": "userPrivacyPolicy",
                "type": "uint32"
              },
              {
                "internalType": "uint32",
                "name": "userDisclosureMode",
                "type": "uint32"
              },
              {
                "internalType": "bytes",
                "name": "userDisclosureDigest",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "userDisclosureTargetPubkey",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "userDisclosurePayload",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "selfFullDisclosureDigest",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "selfViewDisclosurePayload",
                "type": "bytes"
              }
            ],
            "internalType": "struct PrivacyOutputEffect",
            "name": "output",
            "type": "tuple"
          },
          {
            "internalType": "bytes",
            "name": "proof",
            "type": "bytes"
          },
          {
            "internalType": "uint64",
            "name": "expiresAtUnix",
            "type": "uint64"
          },
          {
            "components": [
              {
                "internalType": "bytes",
                "name": "keyId",
                "type": "bytes"
              },
              {
                "internalType": "uint64",
                "name": "epoch",
                "type": "uint64"
              },
              {
                "internalType": "bytes",
                "name": "envelope",
                "type": "bytes"
              }
            ],
            "internalType": "struct PrivacyAuditAuthorization",
            "name": "audit",
            "type": "tuple"
          }
        ],
        "internalType": "struct PrivacyDepositRequest",
        "name": "request",
        "type": "tuple"
      }
    ],
    "name": "deposit",
    "outputs": [
      {
        "internalType": "bool",
        "name": "success",
        "type": "bool"
      }
    ],
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "components": [
          {
            "internalType": "bytes",
            "name": "proof",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "root",
            "type": "bytes"
          },
          {
            "internalType": "bytes[]",
            "name": "nullifiers",
            "type": "bytes[]"
          },
          {
            "components": [
              {
                "internalType": "bytes",
                "name": "commitment",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "ciphertext",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "viewTag",
                "type": "bytes"
              },
              {
                "internalType": "uint32",
                "name": "userPrivacyPolicy",
                "type": "uint32"
              },
              {
                "internalType": "uint32",
                "name": "userDisclosureMode",
                "type": "uint32"
              },
              {
                "internalType": "bytes",
                "name": "userDisclosureDigest",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "userDisclosureTargetPubkey",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "userDisclosurePayload",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "selfFullDisclosureDigest",
                "type": "bytes"
              },
              {
                "internalType": "bytes",
                "name": "selfViewDisclosurePayload",
                "type": "bytes"
              }
            ],
            "internalType": "struct PrivacyOutputEffect[]",
            "name": "outputs",
            "type": "tuple[]"
          },
          {
            "internalType": "uint64",
            "name": "expiresAtUnix",
            "type": "uint64"
          },
          {
            "components": [
              {
                "internalType": "bytes",
                "name": "keyId",
                "type": "bytes"
              },
              {
                "internalType": "uint64",
                "name": "epoch",
                "type": "uint64"
              },
              {
                "internalType": "bytes",
                "name": "envelope",
                "type": "bytes"
              }
            ],
            "internalType": "struct PrivacyAuditAuthorization",
            "name": "audit",
            "type": "tuple"
          }
        ],
        "internalType": "struct PrivacyTransferRequest",
        "name": "request",
        "type": "tuple"
      }
    ],
    "name": "transfer",
    "outputs": [
      {
        "internalType": "bool",
        "name": "success",
        "type": "bool"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "components": [
          {
            "internalType": "bytes",
            "name": "proof",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "root",
            "type": "bytes"
          },
          {
            "internalType": "bytes",
            "name": "nullifier",
            "type": "bytes"
          },
          {
            "internalType": "string",
            "name": "amount",
            "type": "string"
          },
          {
            "internalType": "address",
            "name": "recipient",
            "type": "address"
          },
          {
            "internalType": "uint64",
            "name": "expiresAtUnix",
            "type": "uint64"
          },
          {
            "components": [
              {
                "internalType": "bytes",
                "name": "keyId",
                "type": "bytes"
              },
              {
                "internalType": "uint64",
                "name": "epoch",
                "type": "uint64"
              },
              {
                "internalType": "bytes",
                "name": "envelope",
                "type": "bytes"
              }
            ],
            "internalType": "struct PrivacyAuditAuthorization",
            "name": "audit",
            "type": "tuple"
          }
        ],
        "internalType": "struct PrivacyWithdrawRequest",
        "name": "request",
        "type": "tuple"
      }
    ],
    "name": "withdraw",
    "outputs": [
      {
        "internalType": "bool",
        "name": "success",
        "type": "bool"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  }
];
