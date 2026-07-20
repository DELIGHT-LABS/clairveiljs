export type Uint64CursorInput = number | bigint | string;

export interface PrivacyEventsQuery {
  afterHeight?: Uint64CursorInput;
  after_height?: Uint64CursorInput;
  afterSequence?: Uint64CursorInput;
  after_sequence?: Uint64CursorInput;
  page?: number;
  limit?: number;
  eventTypes?: string[];
  event_types?: string[];
}

export interface ClairveilPublicClientOptions {
  rest?: string;
  restEndpoints?: string[];
  queryTimeoutMs?: number;
  fetchTimeoutMs?: number;
  queryRetry?: QueryRetryOptions | false;
  nullifierFailover?: boolean;
}

export interface QueryRetryOptions {
  retries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  jitter?: boolean;
  retryStatuses?: number[];
}

export interface ReserveResponse {
  denom: string;
  module_balance: string;
  total_deposited: string;
  total_withdrawn: string;
  expected_module_balance: string;
  invariant_holds: boolean;
}

export function eventAttribute(event: object, key: string): string;
export function isAuditableTransfer(event: object): boolean;

export class ClairveilPublicClient {
  constructor(options: ClairveilPublicClientOptions);
  rest: string;
  restEndpoints: string[];
  activeRestEndpoint: string;
  restUrl(path: string, endpoint?: string): string;
  fetchJson<T = object>(pathOrUrl: string, options?: {
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
    failover?: boolean;
    endpoint?: string;
    updateActiveEndpoint?: boolean;
  }): Promise<T>;
  fetchNullifierJson<T = object>(path: string, options?: {
    method?: string;
    body?: BodyInit | null;
    headers?: Record<string, string>;
  }): Promise<T>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchScanEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  checkNullifier(nullifierHex: string): Promise<object & { used?: boolean; Used?: boolean }>;
  checkNullifiers(nullifierHexes: readonly string[]): Promise<Map<string, boolean>>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
}

export function createClairveilPublicClient(options: ClairveilPublicClientOptions): ClairveilPublicClient;
