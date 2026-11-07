/**
 * Thin, typed client for the Pigeon Mail HTTP API.
 *
 * The webmail is served by the Pigeon API itself, so every request is
 * same-origin and authenticated with `Authorization: Bearer pk_…`.
 * The key lives in localStorage and never leaves the device otherwise.
 */

export const API_KEY_STORAGE = 'pigeon_api_key';
export const FROM_STORAGE = 'pigeon_from';

export type Theme = 'light' | 'dark';

export type Scope = 'send' | 'read' | 'full';

export type WebhookEvent =
  | 'email.sent'
  | 'email.delivered'
  | 'email.delivery_delayed'
  | 'email.bounced'
  | 'email.failed'
  | 'email.received';

export const WEBHOOK_EVENTS: readonly WebhookEvent[] = [
  'email.sent',
  'email.delivered',
  'email.delivery_delayed',
  'email.bounced',
  'email.failed',
  'email.received',
];

export interface AuthVerdict {
  spf: string;
  dkim: string;
  dmarc: string;
  tls?: string;
}

export interface AttachmentMeta {
  id: string;
  filename: string;
  size: number;
}

export interface InboxMessage {
  id: string;
  from_addr: string;
  subject?: string;
  created_at?: string;
  /** Set when this copy arrived for a shared address (alias or catch-all), not the account itself. */
  delivered_for?: string;
}

export interface MessageDetail {
  id: string;
  from_addr: string;
  read?: boolean;
  to?: string[];
  subject?: string;
  created_at?: string;
  body_text?: string;
  body_html?: string;
  attachments?: AttachmentMeta[];
  auth?: AuthVerdict;
  sealed_body?: string;
}

export type SentStatus =
  | 'queued'
  | 'scheduled'
  | 'sending'
  | 'sent'
  | 'deferred'
  | 'bounced'
  | 'failed'
  | 'cancelled';

export interface SentMessage {
  id: string;
  status: SentStatus;
  created_at: string;
  from?: string;
  to?: string[];
  subject?: string;
}

export interface ApiKeyView {
  id: string;
  name: string;
  scopes: Scope[];
  sandbox?: boolean;
  revoked?: boolean;
  last_used_at?: string | null;
  created_at?: string;
}

export interface ApiKeyCreated {
  id: string;
  key: string;
}

export interface WebhookView {
  id: string;
  url: string;
  events: string[];
  created_at?: string;
}

export interface WebhookCreated extends WebhookView {
  secret: string;
}

export interface Template {
  id: string;
  name: string;
  /** Short human description, absent when the template has none. */
  description?: string;
  subject?: string;
  html?: string;
  text?: string;
  updated_at?: string;
}

export interface DnsRecord {
  type: 'A' | 'MX' | 'TXT';
  host: string;
  value: string;
  priority?: number;
}

export interface DomainView {
  id: string;
  name: string;
  verified: boolean;
  checked_at?: string;
}

export interface SuppressionEntry {
  address: string;
  reason: 'manual' | 'bounce' | 'complaint';
  created_at?: string;
}

/** One outbound attachment: base64 `content` (no dataURL prefix), as the API expects. */
export interface SendAttachment {
  filename: string;
  content: string;
}

export interface SendPayload {
  from: string;
  to: string[];
  cc?: string[];
  subject: string;
  text: string;
  html?: string;
  /** ≤ 10 per message, ≤ 25 MB decoded total (docs/API.md). */
  attachments?: SendAttachment[];
  /** ≤ 10, each `[a-z0-9-]{1,40}`. */
  tags?: string[];
  /** Future ISO-8601 instant; the message stays `scheduled` until then. */
  scheduled_at?: string;
}

export interface SendAccepted {
  id: string;
  status: 'queued' | 'scheduled';
  e2e?: string;
}

/** A saved, unsent email. Bodies come back verbatim — drafts are editable state. */
export interface DraftView {
  id: string;
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject?: string;
  html?: string;
  text?: string;
  attachments: SendAttachment[];
  tags: string[];
  updated_at: string;
}

/** Body of `POST /v1/drafts` and `PATCH /v1/drafts/{id}`: every member optional. */
export interface DraftPayload {
  from?: string;
  to?: string[];
  cc?: string[];
  bcc?: string[];
  subject?: string;
  html?: string;
  text?: string;
  attachments?: SendAttachment[];
  tags?: string[];
}

interface DraftPage {
  items: DraftView[];
  page: { total: number; has_more: boolean; next_offset: number | null };
}

/** A demo (offline) read result: the UI labels it so nobody mistakes it for real mail. */
export interface ReadResult<T> {
  data: T;
  demo: boolean;
  /** Per-folder counts, present on folder listings (PR #20). */
  counts?: FolderCounts;
  /** Inbox counts per shared address, present on folder listings. */
  deliveredForCounts?: DeliveredForCount[];
}

/**
 * One `delivered_for` marker with its inbox count: the webmail's pseudo-folder.
 *
 * The message stays in `inbox`; this is what a "Delivered to" filter selects.
 */
export interface DeliveredForCount {
  address: string;
  count: number;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }

  get isNetwork(): boolean {
    return this.status === 0;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }

  get isForbidden(): boolean {
    return this.status === 403;
  }
}

interface ProblemBody {
  title?: string;
  detail?: string;
  type?: string;
}

export type MailFolder = 'inbox' | 'sent' | 'spam' | 'trash';

export interface FolderCounts {
  inbox: number;
  sent: number;
  spam: number;
  trash: number;
}

interface MessagePage {
  items: InboxMessage[];
  page: { total: number; has_more: boolean; next_offset: number | null };
  counts?: FolderCounts;
  delivered_for_counts?: DeliveredForCount[];
}

interface EmailPage {
  items: SentMessage[];
  page: { total: number; has_more: boolean; next_offset: number | null };
}

export function getStoredKey(): string | null {
  try {
    const value = localStorage.getItem(API_KEY_STORAGE);
    return value !== null && value.trim().length > 0 ? value.trim() : null;
  } catch {
    return null;
  }
}

export function storeKey(key: string | null): void {
  try {
    if (key === null) {
      localStorage.removeItem(API_KEY_STORAGE);
    } else {
      localStorage.setItem(API_KEY_STORAGE, key);
    }
  } catch {
    // Ignore storage failures (private mode); the in-memory state still works.
  }
}

const ACCOUNT_EMAIL_STORAGE = 'pigeon_account_email';

/** The account email typed at login — the default From for new compose sessions. */
export function getStoredAccountEmail(): string {
  try {
    return localStorage.getItem(ACCOUNT_EMAIL_STORAGE) ?? '';
  } catch {
    return '';
  }
}

export function storeAccountEmail(address: string): void {
  try {
    localStorage.setItem(ACCOUNT_EMAIL_STORAGE, address);
  } catch {
    // Ignore storage failures (private mode).
  }
}

export function clearStoredAccountEmail(): void {
  try {
    localStorage.removeItem(ACCOUNT_EMAIL_STORAGE);
  } catch {
    // Ignore storage failures.
  }
}

export function getStoredFrom(): string {
  try {
    return localStorage.getItem(FROM_STORAGE) ?? '';
  } catch {
    return '';
  }
}

export function storeFrom(address: string): void {
  try {
    localStorage.setItem(FROM_STORAGE, address);
  } catch {
    // Ignore storage failures.
  }
}

export function maskKey(key: string): string {
  if (key.length <= 12) {
    return key;
  }
  return `${key.slice(0, 8)}…${key.slice(-4)}`;
}

async function request<T>(key: string | null, path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (key !== null && key.length > 0) {
    headers.Authorization = `Bearer ${key}`;
  }
  if (init?.body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  let response: Response;
  try {
    response = await fetch(path, { ...init, headers });
  } catch {
    throw new ApiError('network', 0, 'network');
  }

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`.trim();
    let code = 'http-error';
    try {
      const problem = (await response.json()) as ProblemBody;
      if (typeof problem.detail === 'string') {
        detail = problem.detail;
      } else if (typeof problem.title === 'string') {
        detail = problem.title;
      }
      if (typeof problem.type === 'string') {
        code = problem.type;
      }
    } catch {
      // Non-JSON error body: keep the status line.
    }
    throw new ApiError(detail, response.status, code);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

function offline<T>(demo: T): ReadResult<T> {
  return { data: demo, demo: true };
}

function isNetworkError(error: unknown): boolean {
  return error instanceof ApiError && error.isNetwork;
}

/* ------------------------------------------------------------------ */
/* Demo data — only used when the API cannot be reached (clearly        */
/* labelled "Demo preview" in the UI). It never replaces real mail.     */
/* ------------------------------------------------------------------ */

const now = Date.now();
const minutesAgo = (minutes: number): string => new Date(now - minutes * 60_000).toISOString();

interface DemoMessage extends MessageDetail {
  preview: string;
  unread: boolean;
  encrypted: boolean;
}

const DEMO_MESSAGES: DemoMessage[] = [
  {
    id: 'msg_demo7f3a9c21',
    from_addr: 'Mara Vélez <mara@estudio-norte.com>',
    to: ['you@pigeon.local'],
    subject: 'Final cover — tell me what you feel',
    created_at: minutesAgo(24),
    unread: true,
    encrypted: true,
    preview: 'I pushed the type a little warmer and left the pigeon alone on the right. Third option is my favourite…',
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', tls: 'TLS 1.3' },
    body_text:
      'Hey,\n\nThe final cover is attached. I pushed the type a little warmer and left the pigeon alone on the right — it finally breathes.\n\nThird option is my favourite: the terracotta reads like sunrise instead of a warning sign. If you approve today, the printer can start Thursday.\n\nOne small thing: can we keep the paper stock uncoated? It makes the whole thing feel like a book instead of a brochure.\n\n— Mara\nEstudio Norte',
    attachments: [{ id: 'atc_demo1', filename: 'pigeon-cover-final.pdf', size: 2_481_203 }],
  },
  {
    id: 'msg_demo2b8e4d10',
    from_addr: 'Pigeon Server <postmaster@pigeon.local>',
    to: ['you@pigeon.local'],
    subject: 'Weekly deliverability report',
    created_at: minutesAgo(96),
    unread: true,
    encrypted: true,
    preview: '4,182 messages delivered · 3 deferred · 1 bounced. DMARC alignment held at 99.8%.',
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', tls: 'TLS 1.3' },
    body_text:
      'Deliverability, last 7 days\n\n  Delivered   4,182\n  Deferred        3  (all recovered)\n  Bounced         1  (hard, unknown mailbox)\n\nDMARC alignment held at 99.8%. SPF and DKIM passed for every outbound domain. The single bounce came from a misspelled recipient at a domain we have not seen before.\n\nNo action needed.',
  },
  {
    id: 'msg_demo9a1c7e42',
    from_addr: 'Ines Duarte <ines@duarte.dev>',
    to: ['you@pigeon.local'],
    subject: 'Re: the encryption model doc',
    created_at: minutesAgo(60 * 5),
    unread: false,
    encrypted: true,
    preview: 'Sealed at rest, decrypted only for the reader. That is the sentence I would put on the landing page.',
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', tls: 'TLS 1.3' },
    body_text:
      '“Sealed at rest, decrypted only for the reader.”\n\nThat is the sentence I would put on the landing page. It says what the thing does without turning into a lecture on cryptography.\n\nThe rest of the doc reads well. I only tripped on the key-rotation section — it assumes the reader knows what an envelope key is. One paragraph of setup would fix it.\n\n— Ines',
  },
  {
    id: 'msg_demo4c5b8f91',
    from_addr: 'No-reply <receipts@trailhead-outfitters.example>',
    to: ['you@pigeon.local'],
    subject: 'Your order shipped (order #A-2291)',
    created_at: minutesAgo(60 * 26),
    unread: false,
    encrypted: true,
    preview: 'Your parcel left the warehouse this morning and should arrive between Thursday and Saturday…',
    auth: { spf: 'pass', dkim: 'fail', dmarc: 'fail', tls: 'TLS 1.2' },
    body_text:
      'Hi,\n\nYour parcel left the warehouse this morning and should arrive between Thursday and Saturday. Tracking number 1Z-8841-2210.\n\nYou can change the delivery address from your account for the next 12 hours.\n\nThanks for choosing Trailhead Outfitters.',
  },
  {
    id: 'msg_demo6d2a3b77',
    from_addr: 'Tomas Lindqvist <tomas@northlight.se>',
    to: ['you@pigeon.local'],
    subject: 'Invitation: design systems dinner, Nov 14',
    created_at: minutesAgo(60 * 49),
    unread: false,
    encrypted: true,
    preview: 'We are gathering twelve people who care about type, spacing and quiet interfaces. No slides, no pitches.',
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', tls: 'TLS 1.3' },
    body_text:
      'We are gathering twelve people who care about type, spacing and quiet interfaces. No slides, no pitches — just dinner and a long table.\n\nThursday November 14, 19:30, at the old printing house on Södermalm.\n\nBring one thing you made that you are proud of. Nothing else.\n\n— Tomas',
  },
  {
    id: 'msg_demo1e9f5c03',
    from_addr: 'Security <alerts@pigeon.local>',
    to: ['you@pigeon.local'],
    subject: 'New API key created',
    created_at: minutesAgo(60 * 73),
    unread: false,
    encrypted: true,
    preview: 'A new key named “laptop” with the send and read scopes was created from 203.0.113.42.',
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', tls: 'TLS 1.3' },
    body_text:
      'A new API key named “laptop” with the send and read scopes was created from 203.0.113.42.\n\nIf this was you, nothing to do. If it was not, revoke the key in Account → API keys and rotate your credentials.',
  },
];

const DEMO_BY_ID = new Map<string, DemoMessage>(DEMO_MESSAGES.map((message) => [message.id, message]));

const DEMO_SENT: SentMessage[] = [
  {
    id: 'eml_demo3f7c1a20',
    status: 'sent',
    created_at: minutesAgo(42),
    from: 'you@pigeon.local',
    to: ['mara@estudio-norte.com'],
    subject: 'Re: Final cover — tell me what you feel',
  },
  {
    id: 'eml_demo8b2d4e11',
    status: 'sent',
    created_at: minutesAgo(60 * 4),
    from: 'you@pigeon.local',
    to: ['ines@duarte.dev'],
    subject: 'Re: the encryption model doc',
  },
  {
    id: 'eml_demo5a9e6c34',
    status: 'deferred',
    created_at: minutesAgo(60 * 22),
    from: 'you@pigeon.local',
    to: ['hello@northlight.se'],
    subject: 'Dinner on the 14th',
  },
  {
    id: 'eml_demo2c1f8b55',
    status: 'sent',
    created_at: minutesAgo(60 * 70),
    from: 'you@pigeon.local',
    to: ['team@pigeon.local'],
    subject: 'Notes from the design review',
  },
];

/* ------------------------------------------------------------------ */
/* Reads                                                               */
/* ------------------------------------------------------------------ */

export async function fetchFolder(
  key: string | null,
  folder: MailFolder,
  deliveredFor?: string | null,
): Promise<ReadResult<InboxMessage[]>> {
  // `delivered_for` narrows the inbox to the copies that arrived for one shared
  // address (an alias or a catch-all local part); the message never leaves `inbox`.
  const marker =
    deliveredFor !== undefined && deliveredFor !== null && deliveredFor.length > 0
      ? `&delivered_for=${encodeURIComponent(deliveredFor)}`
      : '';
  try {
    const page = await request<MessagePage>(
      key,
      `/v1/messages?folder=${folder}&limit=100${marker}`,
    );
    return {
      data: page.items,
      demo: false,
      counts: page.counts,
      deliveredForCounts: page.delivered_for_counts,
    };
  } catch (error) {
    if (isNetworkError(error) && folder === 'inbox') {
      return offline(
        DEMO_MESSAGES.map((message) => ({
          id: message.id,
          from_addr: message.from_addr,
          subject: message.subject,
          created_at: message.created_at,
        })),
      );
    }
    throw error;
  }
}

export async function fetchSent(key: string | null): Promise<ReadResult<SentMessage[]>> {
  try {
    const page = await request<EmailPage>(key, '/v1/emails?limit=100');
    return { data: page.items, demo: false };
  } catch (error) {
    if (isNetworkError(error)) {
      return offline(DEMO_SENT);
    }
    throw error;
  }
}

export async function fetchMessage(key: string | null, id: string): Promise<ReadResult<MessageDetail>> {
  try {
    const message = await request<MessageDetail>(key, `/v1/messages/${encodeURIComponent(id)}?sealed=false`);
    return { data: message, demo: false };
  } catch (error) {
    // Only the bundled sample mail may stand in for a failed read. A real id that
    // the network could not reach must stay an error: substituting demo content
    // would present fabricated mail as if it were the user's own.
    const demo = isNetworkError(error) ? DEMO_BY_ID.get(id) : undefined;
    if (demo !== undefined) {
      return offline(demo);
    }
    throw error;
  }
}

export interface DemoEnrichment {
  preview: string;
  unread: boolean;
}

/** Demo-only metadata for list rows (real metadata comes from the API). */
export function demoEnrichment(id: string): DemoEnrichment | null {
  const message = DEMO_BY_ID.get(id);
  if (message === undefined) {
    return null;
  }
  return { preview: message.preview, unread: message.unread };
}

/* ------------------------------------------------------------------ */
/* Writes                                                              */
/* ------------------------------------------------------------------ */

export async function sendEmail(key: string | null, payload: SendPayload): Promise<SendAccepted> {
  return request<SendAccepted>(key, '/v1/emails', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function fetchApiKeys(key: string | null): Promise<ApiKeyView[]> {
  return request<ApiKeyView[]>(key, '/v1/account/keys');
}

export async function createApiKey(
  key: string | null,
  name: string,
  scopes: Scope[],
  sandbox: boolean,
): Promise<ApiKeyCreated> {
  return request<ApiKeyCreated>(key, '/v1/account/keys', {
    method: 'POST',
    body: JSON.stringify({ name, scopes, sandbox }),
  });
}

export async function revokeApiKey(key: string | null, id: string): Promise<ApiKeyView> {
  return request<ApiKeyView>(key, `/v1/account/keys/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify({ revoked: true }),
  });
}

export async function fetchWebhooks(key: string | null): Promise<WebhookView[]> {
  return request<WebhookView[]>(key, '/v1/webhooks');
}

export async function createWebhook(
  key: string | null,
  url: string,
  events: WebhookEvent[],
): Promise<WebhookCreated> {
  return request<WebhookCreated>(key, '/v1/webhooks', {
    method: 'POST',
    body: JSON.stringify({ url, events }),
  });
}

export async function deleteWebhook(key: string | null, id: string): Promise<void> {
  await request<void>(key, `/v1/webhooks/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

/**
 * Plain text as editor HTML: escaped and newline-preserving. Used to seed the
 * rich-text compose box from a stored draft or template that has no HTML part.
 */
export function textToHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\n/g, '<br>');
}

/** Extract readable text from an HTML part without injecting it into the DOM. */
export function htmlToText(html: string): string {
  const parsed = new DOMParser().parseFromString(html, 'text/html');
  parsed.querySelectorAll('br').forEach((node) => {
    node.replaceWith('\n');
  });
  parsed.querySelectorAll('p, div, li, tr').forEach((node) => {
    node.append('\n\n');
  });
  return (parsed.body.textContent ?? '').replace(/\n{3,}/g, '\n\n').trim();
}

/** `Name <address>` → readable name, falling back to the address. */
export function displayName(from: string): string {
  const match = /^\s*"?([^"<]*)"?\s*<([^>]+)>\s*$/.exec(from);
  if (match !== null) {
    const name = (match[1] ?? '').trim();
    return name.length > 0 ? name : (match[2] ?? from);
  }
  return from;
}

/**
 * Strip everything from an HTML fragment that must never reach a
 * `contentEditable` sink: `<script>`, the embedding/plugin elements and every
 * inline `on*` handler.
 *
 * Why: an account is shared by several actors (a human and one or more agents),
 * so template and draft HTML returned by the API is other people's input. A
 * stored `<img onerror=…>` must not run in whichever browser opens that draft
 * next, so the HTML is cleaned where it is injected, not where it is stored.
 */
export function sanitizeEmailHtml(html: string): string {
  const parsed = new DOMParser().parseFromString(html, 'text/html');
  parsed.querySelectorAll('script, iframe, object, embed').forEach((node) => {
    node.remove();
  });
  parsed.querySelectorAll('*').forEach((node) => {
    for (const attribute of Array.from(node.attributes)) {
      if (attribute.name.toLowerCase().startsWith('on')) {
        node.removeAttribute(attribute.name);
      }
    }
  });
  return parsed.body.innerHTML;
}

/**
 * Human-readable byte size, the single formatter behind every size in the UI:
 * `512 B`, `12.4 kB`, `2.4 MB`.
 */
export function formatSize(bytes: number, lang?: string): string {
  const format = (value: number, digits: number): string =>
    new Intl.NumberFormat(lang, { maximumFractionDigits: digits }).format(value);
  if (bytes < 1024) {
    return `${format(bytes, 0)} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${format(bytes / 1024, 1)} kB`;
  }
  return `${format(bytes / (1024 * 1024), 1)} MB`;
}

/** `Name <address>` → `address`. */
export function emailAddress(from: string): string {
  const match = /<([^>]+)>/.exec(from);
  return (match?.[1] ?? from).trim();
}

export function initials(name: string): string {
  const source = displayName(name);
  const parts = source
    .split(/[\s._@-]+/)
    .filter((part) => part.length > 0)
    .slice(0, 2);
  if (parts.length === 0) {
    return '?';
  }
  return parts.map((part) => part.charAt(0).toUpperCase()).join('');
}

/** Stable hue for the avatar tint, so a sender keeps the same colour. */
export function avatarHue(seed: string): number {
  let hash = 0;
  for (let index = 0; index < seed.length; index += 1) {
    hash = (hash * 31 + seed.charCodeAt(index)) % 360;
  }
  return hash;
}

// ------------------------------------------------------------- Templates

export async function fetchTemplates(key: string | null): Promise<Template[]> {
  return request<Template[]>(key, '/v1/templates');
}

export async function createTemplate(
  key: string | null,
  tpl: { name: string; description?: string; subject?: string; html?: string; text?: string },
): Promise<Template> {
  return request<Template>(key, '/v1/templates', {
    method: 'POST',
    body: JSON.stringify(tpl),
  });
}

export async function deleteTemplate(key: string | null, id: string): Promise<void> {
  await request<void>(key, `/v1/templates/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export async function testSendTemplate(
  key: string | null,
  id: string,
  to: string[],
  variables: Record<string, string>,
): Promise<SendAccepted> {
  return request<SendAccepted>(key, `/v1/templates/${encodeURIComponent(id)}/test-send`, {
    method: 'POST',
    body: JSON.stringify({ to, variables }),
  });
}

// ------------------------------------------------------------- Drafts

/** Drafts of the account, newest save first. */
export async function fetchDrafts(key: string | null, limit = 100): Promise<DraftView[]> {
  const page = await request<DraftPage>(key, `/v1/drafts?limit=${limit}`);
  return page.items;
}

export async function createDraft(key: string | null, draft: DraftPayload): Promise<DraftView> {
  return request<DraftView>(key, '/v1/drafts', {
    method: 'POST',
    body: JSON.stringify(draft),
  });
}

export async function updateDraft(
  key: string | null,
  id: string,
  draft: DraftPayload,
): Promise<DraftView> {
  return request<DraftView>(key, `/v1/drafts/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(draft),
  });
}

export async function deleteDraft(key: string | null, id: string): Promise<void> {
  await request<void>(key, `/v1/drafts/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

/** Send a draft through the real send path; the draft is deleted server-side. */
export async function sendDraft(key: string | null, id: string): Promise<SendAccepted> {
  return request<SendAccepted>(key, `/v1/drafts/${encodeURIComponent(id)}/send`, {
    method: 'POST',
    body: JSON.stringify({}),
  });
}

// ------------------------------------------------------------- Domains

export async function fetchDomains(key: string | null): Promise<DomainView[]> {
  return request<DomainView[]>(key, '/v1/domains');
}

export async function fetchDomainDns(key: string | null, id: string): Promise<DnsRecord[]> {
  return request<DnsRecord[]>(key, `/v1/domains/${encodeURIComponent(id)}/dns`);
}

// ------------------------------------------------------------- Suppressions

export async function fetchSuppressions(key: string | null, limit = 100): Promise<SuppressionEntry[]> {
  const page = await request<{ items: SuppressionEntry[] }>(
    key,
    `/v1/suppressions?limit=${limit}`,
  );
  return page.items;
}

export async function addSuppressions(
  key: string | null,
  addresses: string[],
  reason: 'manual' | 'bounce' | 'complaint',
): Promise<void> {
  await request<void>(key, '/v1/suppressions', {
    method: 'POST',
    body: JSON.stringify({ addresses, reason }),
  });
}

export async function removeSuppression(key: string | null, address: string): Promise<void> {
  await request<void>(
    key,
    `/v1/suppressions/${encodeURIComponent(address)}`,
    { method: 'DELETE' },
  );
}

// ------------------------------------------------------------- Organizations (multi-tenant)

/** Role inside an organization. `owner` is transferred by patching a member, never invited. */
export type OrgRole = 'owner' | 'admin' | 'member';

/** An organization the account belongs to (`GET /v1/orgs`). */
export interface OrgView {
  id: number;
  name: string;
  created_at: string;
  /** The caller's own role. Only the "my organizations" listing sends it. */
  role?: OrgRole;
}

/** One account of an organization. One account is one mailbox, never merged. */
export interface OrgMemberView {
  account_id: number;
  email: string;
  /** Human name; empty when nobody has set one. */
  display_name: string;
  role: OrgRole;
  created_at?: string;
  /** Not emitted by the v0.1 API — kept optional so a status cell appears if it ever is. */
  status?: string;
}

/** A freshly created member plus the one-time bootstrap token they log in with. */
export interface OrgMemberCreated {
  member: OrgMemberView;
  bootstrap_token: string;
}

/** An invitation to join an organization. The plaintext token is never listed. */
export interface InvitationView {
  id: number;
  email: string;
  role: OrgRole;
  invited_by: number;
  created_at: string;
  expires_at: string;
  accepted_at?: string;
}

/** An invitation plus its one-time token: this is the only response that carries it. */
export interface InvitationCreated {
  invitation: InvitationView;
  token: string;
}

/** What happens to unknown local parts of a managed domain. */
export type CatchallAction = 'route' | 'discard';

/** One account holding a catch-all, with its own pause switch. */
export interface CatchallAssignment {
  account_id: number;
  email?: string;
  /** True suspends only this member's copy. */
  paused: boolean;
  created_at?: string;
}

/**
 * The domain-level catch-all decision plus who receives a routed copy.
 *
 * The rule is the decision; the recipients are assignments, several per domain.
 */
export interface CatchallRuleView {
  domain: string;
  action: CatchallAction;
  assignments?: CatchallAssignment[];
  created_at: string;
}

/** One account that may send as an alias and receives a copy of its mail. */
export interface AliasAssignment {
  account_id: number;
  email?: string;
  created_at?: string;
}

/**
 * A sender alias: a secondary address on a served domain that owns no mailbox.
 *
 * Mail to it is copied into every assignee's inbox, and every assignee may send
 * as it.
 */
export interface AliasView {
  id: number;
  address: string;
  domain: string;
  assignments: AliasAssignment[];
  created_at: string;
}

export async function createOrg(key: string | null, name: string): Promise<OrgView> {
  return request<OrgView>(key, '/v1/orgs', {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}

export async function fetchMyOrgs(key: string | null): Promise<OrgView[]> {
  return request<OrgView[]>(key, '/v1/orgs');
}

export async function fetchOrgMembers(key: string | null, orgId: number): Promise<OrgMemberView[]> {
  return request<OrgMemberView[]>(key, `/v1/orgs/${orgId}/members`);
}

/**
 * Create an account inside the organization.
 *
 * The API answers with a bootstrap token: the member logs in with their address
 * and that token as the code. It is shown once and only its hash is stored.
 */
export async function createMember(
  key: string | null,
  orgId: number,
  email: string,
  displayName: string,
  role: Exclude<OrgRole, 'owner'>,
): Promise<OrgMemberCreated> {
  const name = displayName.trim();
  return request<OrgMemberCreated>(key, `/v1/orgs/${orgId}/members`, {
    method: 'POST',
    body: JSON.stringify({ email, role, ...(name.length > 0 ? { display_name: name } : {}) }),
  });
}

/** Change a role and/or a display name. At least one field must be present. */
export async function patchMember(
  key: string | null,
  orgId: number,
  accountId: number,
  patch: { role?: OrgRole; display_name?: string },
): Promise<OrgMemberView> {
  return request<OrgMemberView>(key, `/v1/orgs/${orgId}/members/${accountId}`, {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

/** Mint a one-time invitation token. Nothing is emailed: the admin delivers it. */
export async function createInvitation(
  key: string | null,
  orgId: number,
  email: string,
  role: Exclude<OrgRole, 'owner'>,
): Promise<InvitationCreated> {
  return request<InvitationCreated>(key, `/v1/orgs/${orgId}/invitations`, {
    method: 'POST',
    body: JSON.stringify({ email, role }),
  });
}

export async function fetchInvitations(
  key: string | null,
  orgId: number,
): Promise<InvitationView[]> {
  return request<InvitationView[]>(key, `/v1/orgs/${orgId}/invitations`);
}

/** Revoke an invitation: the token stops working. */
export async function deleteInvitation(
  key: string | null,
  orgId: number,
  invitationId: number,
): Promise<void> {
  await request<void>(key, `/v1/orgs/${orgId}/invitations/${invitationId}`, {
    method: 'DELETE',
  });
}

/** Redeem an invitation token against the authenticated account (burns it). */
export async function acceptInvitation(key: string | null, token: string): Promise<OrgView> {
  return request<OrgView>(key, '/v1/invitations/accept', {
    method: 'POST',
    body: JSON.stringify({ token }),
  });
}

/**
 * Set what happens to unknown local parts of `domain`.
 *
 * Only the domain-level decision travels here: the recipients are assignments
 * (`assignCatchall`), so flipping the action never forgets who was receiving.
 */
export async function setCatchall(
  key: string | null,
  domain: string,
  action: CatchallAction,
): Promise<CatchallRuleView> {
  return request<CatchallRuleView>(key, `/v1/catchall/${encodeURIComponent(domain)}`, {
    method: 'PUT',
    body: JSON.stringify({ action }),
  });
}

/** `mine` narrows the listing to the catch-alls the caller holds. */
export async function fetchCatchalls(
  key: string | null,
  mine = false,
): Promise<CatchallRuleView[]> {
  return request<CatchallRuleView[]>(key, mine ? '/v1/catchall?mine=1' : '/v1/catchall');
}

/** Remove a rule and its assignees, restoring the `550` for unknown local parts. */
export async function deleteCatchall(key: string | null, domain: string): Promise<void> {
  await request<void>(key, `/v1/catchall/${encodeURIComponent(domain)}`, { method: 'DELETE' });
}

/** Give one mailbox a copy of the domain's catch-all mail (owner/admin). */
export async function assignCatchall(
  key: string | null,
  domain: string,
  accountId: number,
): Promise<CatchallRuleView> {
  return request<CatchallRuleView>(key, `/v1/catchall/${encodeURIComponent(domain)}/assign`, {
    method: 'POST',
    body: JSON.stringify({ account_id: accountId }),
  });
}

/** Stop one mailbox receiving that copy (owner/admin). */
export async function unassignCatchall(
  key: string | null,
  domain: string,
  accountId: number,
): Promise<void> {
  await request<void>(
    key,
    `/v1/catchall/${encodeURIComponent(domain)}/assign/${accountId}`,
    { method: 'DELETE' },
  );
}

/** The admin force: pause or resume somebody else's copy (owner/admin). */
export async function patchCatchallAssignment(
  key: string | null,
  domain: string,
  accountId: number,
  paused: boolean,
): Promise<CatchallAssignment> {
  return request<CatchallAssignment>(
    key,
    `/v1/catchall/${encodeURIComponent(domain)}/assignments/${accountId}`,
    { method: 'PATCH', body: JSON.stringify({ paused }) },
  );
}

/** Pause the caller's own copy. `domain` is required when they hold several. */
export async function pauseMyCatchall(
  key: string | null,
  domain?: string,
): Promise<CatchallAssignment> {
  return request<CatchallAssignment>(key, '/v1/catchall/me/pause', {
    method: 'POST',
    body: JSON.stringify(domain !== undefined ? { domain } : {}),
  });
}

/** Resume the caller's own copy. */
export async function resumeMyCatchall(
  key: string | null,
  domain?: string,
): Promise<CatchallAssignment> {
  return request<CatchallAssignment>(key, '/v1/catchall/me/resume', {
    method: 'POST',
    body: JSON.stringify(domain !== undefined ? { domain } : {}),
  });
}

// ------------------------------------------------------------- Sender aliases

/**
 * The aliases the caller may send as.
 *
 * `mine` asks for the caller's own list only, which is what the compose From menu
 * offers; without it an owner/admin receives every alias of the deployment.
 */
export async function fetchAliases(key: string | null, mine = false): Promise<AliasView[]> {
  return request<AliasView[]>(key, mine ? '/v1/aliases?mine=1' : '/v1/aliases');
}

/** Claim a free address on a served domain (owner/admin). */
export async function createAlias(key: string | null, address: string): Promise<AliasView> {
  return request<AliasView>(key, '/v1/aliases', {
    method: 'POST',
    body: JSON.stringify({ address }),
  });
}

/** Delete an alias and every assignment to it (owner/admin). */
export async function deleteAlias(key: string | null, id: number): Promise<void> {
  await request<void>(key, `/v1/aliases/${id}`, { method: 'DELETE' });
}

/** Share the alias with one account (owner/admin). */
export async function assignAlias(
  key: string | null,
  id: number,
  accountId: number,
): Promise<AliasView> {
  return request<AliasView>(key, `/v1/aliases/${id}/assign`, {
    method: 'POST',
    body: JSON.stringify({ account_id: accountId }),
  });
}

/** Stop one account sending as the alias and receiving its mail (owner/admin). */
export async function unassignAlias(
  key: string | null,
  id: number,
  accountId: number,
): Promise<AliasView> {
  return request<AliasView>(key, `/v1/aliases/${id}/unassign`, {
    method: 'POST',
    body: JSON.stringify({ account_id: accountId }),
  });
}

// ------------------------------------------------------------- Sessions & 2FA (PR #21)

/** Login: email (+ TOTP/recovery code when 2FA is active). Session cookie is set by the server. */
export interface LoginResult {
  session_id: string;
  expires_at: string;
}

export async function login(email: string, code?: string): Promise<LoginResult> {
  const response = await fetch('/v1/auth/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, ...(code ? { code } : {}) }),
  });
  if (response.status === 403) {
    const problem = await response.json().catch(() => null);
    throw new TwoFaRequiredError(problem?.title ?? '2FA required');
  }
  if (!response.ok) {
    throw new Error(`login failed: ${response.status}`);
  }
  return response.json() as Promise<LoginResult>;
}

export class TwoFaRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TwoFaRequiredError';
  }
}

export async function logout(): Promise<void> {
  await fetch('/v1/auth/logout', { method: 'POST', credentials: 'same-origin' });
}

export interface TotpEnrollment {
  secret_base32: string;
  otpauth_uri: string;
}

export async function enroll2fa(): Promise<TotpEnrollment> {
  const response = await fetch('/v1/account/2fa/enroll', {
    method: 'POST',
    credentials: 'same-origin',
  });
  if (!response.ok) throw new Error(`enroll failed: ${response.status}`);
  return response.json() as Promise<TotpEnrollment>;
}

export async function activate2fa(code: string): Promise<string[]> {
  const response = await fetch('/v1/account/2fa/activate', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) throw new Error(`activate failed: ${response.status}`);
  const data = (await response.json()) as { recovery_codes: string[] };
  return data.recovery_codes;
}

export async function verify2fa(code: string): Promise<void> {
  const response = await fetch('/v1/account/2fa/verify', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) throw new Error(`verify failed: ${response.status}`);
}

export async function disable2fa(code: string): Promise<void> {
  const response = await fetch('/v1/account/2fa/disable', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) throw new Error(`disable failed: ${response.status}`);
}

/**
 * Ask the server whether the HttpOnly session cookie is valid.
 *
 * `document.cookie` never exposes HttpOnly cookies, so the old localStorage
 * check was always false after a reload (jd-judge JD-A-003). This returns the
 * server's verdict instead.
 */
export async function hasSession(): Promise<boolean> {
  try {
    const response = await fetch('/v1/auth/check', { credentials: 'same-origin' });
    return response.status === 204;
  } catch {
    return false;
  }
}


// ------------------------------------------------------------- Folders / read state (PR #20)

export async function patchMessage(
  key: string | null,
  id: string,
  patch: { folder?: MailFolder; read?: boolean },
): Promise<void> {
  await request<void>(key, `/v1/messages/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify(patch),
  });
}

export async function deleteMessage(key: string | null, id: string): Promise<void> {
  await request<void>(key, `/v1/messages/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export async function emptyTrash(key: string | null): Promise<number> {
  const result = await request<{ deleted: number }>(key, '/v1/messages/empty-trash', {
    method: 'POST',
  });
  return result.deleted;
}

/* ------------------------------------------------------------------ */
/* Account settings (server-side policy)                               */
/* ------------------------------------------------------------------ */

/**
 * The account's mailbox policy. Unlike the preferences stored in this browser
 * (language, theme, motion), these live on the server: the webmail, an agent over
 * MCP and the purge worker all read the same row.
 */
export interface AccountSettings {
  /** Days a message stays in the trash before it is deleted (`0` = keep forever). */
  trash_retention_days: number;
}

export async function fetchAccountSettings(key: string | null): Promise<AccountSettings> {
  return request<AccountSettings>(key, '/v1/account/settings');
}

/**
 * Save the trash retention. `0` is a real value ("keep forever"), which is why it
 * is sent as-is rather than turned into "no preference".
 */
export async function saveTrashRetention(
  key: string | null,
  days: number,
): Promise<AccountSettings> {
  return request<AccountSettings>(key, '/v1/account/settings', {
    method: 'PATCH',
    body: JSON.stringify({ trash_retention_days: days }),
  });
}

/** Clear the stored last-used From (sign-out / identity switch). */
export function clearStoredFrom(): void {
  try {
    localStorage.removeItem(FROM_STORAGE);
  } catch {
    // Ignore storage failures.
  }
}
