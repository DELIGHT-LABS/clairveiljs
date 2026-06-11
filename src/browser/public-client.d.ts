export interface PrivacyEventsQuery {
  afterHeight?: number;
  after_height?: number;
  page?: number;
  limit?: number;
  eventTypes?: string[];
  event_types?: string[];
}

export interface ClairveilPublicClientOptions {
  rest: string;
}

export function eventAttribute(event: object, key: string): string;
export function isAuditableTransfer(event: object): boolean;

export class ClairveilPublicClient {
  constructor(options: ClairveilPublicClientOptions);
  rest: string;
  restUrl(path: string): string;
  fetchPrivacyEvents(options?: PrivacyEventsQuery): Promise<object & { events?: object[] }>;
  fetchAuditableTransfers(options?: PrivacyEventsQuery): Promise<object & { events: object[] }>;
}

export function createClairveilPublicClient(options: ClairveilPublicClientOptions): ClairveilPublicClient;
