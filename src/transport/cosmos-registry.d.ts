export interface ClairveilRegistryCodecBase {
  readonly typeUrl?: string;
  readonly encode: (...args: any[]) => { finish(): Uint8Array };
  readonly decode: (...args: any[]) => any;
}

export type ClairveilRegistryGeneratedType = ClairveilRegistryCodecBase & (
  | {
      readonly fromPartial: (...args: any[]) => any;
      readonly create?: (...args: any[]) => any;
    }
  | {
      readonly create: (...args: any[]) => any;
      readonly fromPartial?: (...args: any[]) => any;
    }
);

export interface ClairveilRegistryEncodeObject<T = unknown> {
  readonly typeUrl: string;
  readonly value: T;
}

export interface ClairveilRegistryDecodeObject {
  readonly typeUrl: string;
  readonly value: Uint8Array;
}

/** Public, dependency-safe structural surface of CosmJS Registry. */
export interface ClairveilRegistry {
  register(typeUrl: string, type: ClairveilRegistryGeneratedType): void;
  lookupType(typeUrl: string): ClairveilRegistryGeneratedType | undefined;
  encode<T>(encodeObject: ClairveilRegistryEncodeObject<T>): Uint8Array;
  encodeAsAny<T>(encodeObject: ClairveilRegistryEncodeObject<T>): ClairveilRegistryDecodeObject;
  encodeTxBody(txBodyFields: {
    readonly messages: readonly ClairveilRegistryEncodeObject[];
    readonly memo?: string;
    readonly timeoutHeight?: bigint;
    readonly extensionOptions?: readonly ClairveilRegistryDecodeObject[];
    readonly nonCriticalExtensionOptions?: readonly ClairveilRegistryDecodeObject[];
  }): Uint8Array;
  decode(decodeObject: ClairveilRegistryDecodeObject): unknown;
  decodeTxBody(txBody: Uint8Array): unknown;
}
