export interface PrivacyEventsQuery {
  afterHeight?: number;
  after_height?: number;
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
  fetchJson<T = object>(pathOrUrl: string): Promise<T>;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
  fetchReserve(denom: string): Promise<ReserveResponse>;
}

export function createClairveilPublicClient(options: ClairveilPublicClientOptions): ClairveilPublicClient;
