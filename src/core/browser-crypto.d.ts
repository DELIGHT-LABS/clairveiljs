export type BytesLike = Uint8Array | ArrayBuffer | ArrayBufferView | number[] | string;

export function bytes(value: BytesLike): Uint8Array;
export function utf8Bytes(value: unknown): Uint8Array;
export function utf8String(value: BytesLike): string;
export function bytesFromHex(value: string, label?: string): Uint8Array;
export function hexFromBytes(value: BytesLike): string;
export function bytesFromBase64(value: string, label?: string): Uint8Array;
export function base64FromBytes(value: BytesLike): string;
export function concatBytes(...values: BytesLike[]): Uint8Array;
export function randomBytes(length: number): Uint8Array;
export function sha256(value: BytesLike): Uint8Array;
export function sha256Hex(value: BytesLike): string;
export function hash160(value: BytesLike): Uint8Array;
export function aesGcmEncrypt(input: { key: BytesLike; nonce: BytesLike; plaintext: BytesLike }): Uint8Array;
export function aesGcmDecrypt(input: { key: BytesLike; nonce: BytesLike; ciphertext: BytesLike }): Uint8Array;
