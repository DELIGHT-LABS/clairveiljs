/** Canonical field shapes shared across Core wire codecs. */
export interface NoteFields {
  receiverSpendPubKeyX: bigint;
  receiverSpendPubKeyY: bigint;
  receiverViewPubKeyX: bigint;
  receiverViewPubKeyY: bigint;
  amount: bigint;
  assetID: bigint;
  randomness: bigint;
  memo: string;
}

export interface DisclosureFields {
  plane: 1 | 2;
  outputIndex: number;
  policy: number;
  disclosedFieldBitmap: number;
  commitment: bigint;
  amount: bigint;
  assetID: bigint;
  senderSpendKeyX: bigint;
  senderSpendKeyY: bigint;
  senderViewKeyX: bigint;
  senderViewKeyY: bigint;
  recipientSpendKeyX: bigint;
  recipientSpendKeyY: bigint;
  recipientViewKeyX: bigint;
  recipientViewKeyY: bigint;
  disclosureBlinding: bigint;
}
