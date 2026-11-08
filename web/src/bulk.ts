/**
 * Bulk-action plumbing.
 *
 * The API only knows how to patch or delete one message at a time, so a bulk
 * action is a client-side loop. That loop has to respect the per-account rate
 * limit (10 req/s, burst 50): firing 200 PATCHes at once gets a wall of 429s and
 * a half-applied selection. Everything here is pure — no React, no fetch — so
 * the ordering, throttling and accounting rules are unit tested.
 */

import { ApiError } from './api';

/** Requests per burst: 25 keeps a chunk well inside the 50-request bucket. */
export const BULK_CHUNK_SIZE = 25;
/** Pause between chunks, so two chunks cannot exhaust the 10 req/s refill. */
export const BULK_CHUNK_DELAY_MS = 250;
/** How many times a single 429'd message is retried before it is reported. */
export const BULK_MAX_RETRIES = 3;
/** Widest wait we are willing to sit through for one chunk. */
const MAX_RETRY_DELAY_MS = 8_000;

export interface BulkOutcome {
  /** Ids the server accepted, in the order they were submitted. */
  applied: string[];
  /** Ids that still need action; the selection keeps them for a retry. */
  failed: string[];
}

export interface BulkRunOptions {
  /** Applies the action to a single message. */
  run: (id: string) => Promise<void>;
  chunkSize?: number;
  chunkDelayMs?: number;
  maxRetries?: number;
  /** Delay before retrying `id` after `error`, or `null` to stop retrying. */
  retryDelay?: (error: unknown, attempt: number) => number | null;
  /** Injectable for tests. */
  sleep?: (ms: number) => Promise<void>;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

/** Splits ids into submission chunks, preserving order. */
export function chunkIds(ids: readonly string[], size: number = BULK_CHUNK_SIZE): string[][] {
  const safeSize = Number.isFinite(size) && size >= 1 ? Math.floor(size) : BULK_CHUNK_SIZE;
  const chunks: string[][] = [];
  for (let index = 0; index < ids.length; index += safeSize) {
    chunks.push(ids.slice(index, index + safeSize));
  }
  return chunks;
}

/**
 * How long to wait before retrying after `error`, or `null` when the error is
 * not worth retrying. Only 429 (and 503, which the bucket also emits) are
 * retried: a 403 or a 404 will fail again no matter how long we wait.
 */
export function retryDelayFor(error: unknown, attempt: number): number | null {
  if (!(error instanceof ApiError)) {
    return null;
  }
  if (error.status !== 429 && error.status !== 503) {
    return null;
  }
  const backoff = 300 * Math.pow(2, attempt);
  const hinted = error.retryAfterMs;
  const wait = hinted !== null ? Math.max(hinted, backoff) : backoff;
  return Math.min(wait, MAX_RETRY_DELAY_MS);
}

async function runOne(id: string, options: BulkRunOptions): Promise<boolean> {
  const maxRetries = options.maxRetries ?? BULK_MAX_RETRIES;
  const sleep = options.sleep ?? defaultSleep;
  const retryDelay = options.retryDelay ?? retryDelayFor;
  let attempt = 0;
  for (;;) {
    try {
      await options.run(id);
      return true;
    } catch (error) {
      const wait = attempt < maxRetries ? retryDelay(error, attempt) : null;
      if (wait === null) {
        return false;
      }
      attempt += 1;
      if (wait > 0) {
        await sleep(wait);
      }
    }
  }
}

/**
 * Applies `run` to every id in throttled chunks and reports exactly what the
 * server accepted. Never throws: a failed id is reported, not propagated, so a
 * partial failure cannot hide the work that did land.
 */
export async function runBulk(
  ids: readonly string[],
  options: BulkRunOptions,
): Promise<BulkOutcome> {
  const chunkSize = options.chunkSize ?? BULK_CHUNK_SIZE;
  const chunkDelayMs = options.chunkDelayMs ?? BULK_CHUNK_DELAY_MS;
  const sleep = options.sleep ?? defaultSleep;
  const applied: string[] = [];
  const failed: string[] = [];
  const chunks = chunkIds(ids, chunkSize);

  for (const [index, chunk] of chunks.entries()) {
    if (index > 0 && chunkDelayMs > 0) {
      await sleep(chunkDelayMs);
    }
    const results = await Promise.all(chunk.map((id) => runOne(id, options)));
    for (const [position, id] of chunk.entries()) {
      if (results[position] === true) {
        applied.push(id);
      } else {
        failed.push(id);
      }
    }
  }

  return { applied, failed };
}

/**
 * The ids MailList should act on: the selection intersected with what is on
 * screen right now, in display order. A stale id (a message removed by another
 * tab, or hidden by the unread filter) is never sent to the server again.
 */
export function deriveActiveIds(
  visibleIds: readonly string[],
  selectedIds: ReadonlySet<string>,
): string[] {
  return visibleIds.filter((id) => selectedIds.has(id));
}

/** Same intersection, as a stable set, for master-checkbox state. */
export function activeSelection(
  visibleIds: readonly string[],
  selectedIds: ReadonlySet<string>,
): Set<string> {
  return new Set(deriveActiveIds(visibleIds, selectedIds));
}

/**
 * Selection left after a bulk action: succeeded ids are dropped, failed ids
 * stay checked so the user can retry the same selection. All ids stay when
 * nothing succeeded.
 */
export function remainingSelection(
  selectedIds: ReadonlySet<string>,
  appliedIds: readonly string[],
): Set<string> {
  const applied = new Set(appliedIds);
  const next = new Set<string>();
  for (const id of selectedIds) {
    if (!applied.has(id)) {
      next.add(id);
    }
  }
  return next;
}

/**
 * The message the reader should show once `removedIds` leave the visible list:
 * the next one below, then the ones above (closest first), or `null` when the
 * folder is now empty.
 */
export function nextSurvivor(
  visibleIds: readonly string[],
  removedIds: ReadonlySet<string>,
  currentId: string | null,
): string | null {
  const index = currentId === null ? -1 : visibleIds.indexOf(currentId);
  const order =
    index >= 0
      ? [...visibleIds.slice(index + 1), ...visibleIds.slice(0, index).reverse()]
      : [...visibleIds];
  return order.find((id) => !removedIds.has(id)) ?? null;
}
