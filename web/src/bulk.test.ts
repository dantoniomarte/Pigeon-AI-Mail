import { describe, expect, it } from 'vitest';

import { ApiError } from './api';
import {
  BULK_CHUNK_SIZE,
  chunkIds,
  deriveActiveIds,
  nextSurvivor,
  remainingSelection,
  retryDelayFor,
  runBulk,
} from './bulk';

/** A sleep stand-in that records the waits instead of waiting. */
function recorder(): { sleep: (ms: number) => Promise<void>; waits: number[] } {
  const waits: number[] = [];
  return {
    waits,
    sleep: (ms: number) => {
      waits.push(ms);
      return Promise.resolve();
    },
  };
}

function ids(count: number): string[] {
  return Array.from({ length: count }, (_, index) => `m${index}`);
}

describe('chunkIds', () => {
  it('keeps submission order across chunks', () => {
    const chunks = chunkIds(ids(7), 3);
    expect(chunks).toEqual([
      ['m0', 'm1', 'm2'],
      ['m3', 'm4', 'm5'],
      ['m6'],
    ]);
  });

  it('returns no chunks for an empty selection', () => {
    expect(chunkIds([], 25)).toEqual([]);
  });

  it('falls back to the default size for a nonsense chunk size', () => {
    const one = chunkIds(ids(30), 0);
    expect(one).toHaveLength(Math.ceil(30 / BULK_CHUNK_SIZE));
    expect(one[0]).toHaveLength(BULK_CHUNK_SIZE);
  });
});

describe('runBulk', () => {
  it('applies every id and reports them in order', async () => {
    const seen: string[] = [];
    const outcome = await runBulk(ids(5), {
      run: (id) => {
        seen.push(id);
        return Promise.resolve();
      },
      chunkSize: 2,
      sleep: async () => {},
    });
    expect(outcome.applied).toEqual(ids(5));
    expect(outcome.failed).toEqual([]);
    expect(seen).toEqual(ids(5));
  });

  it('throttles: chunk size caps concurrency and only chunks wait', async () => {
    let inFlight = 0;
    let peak = 0;
    const { sleep, waits } = recorder();
    await runBulk(ids(6), {
      run: async () => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await Promise.resolve();
        inFlight -= 1;
      },
      chunkSize: 2,
      chunkDelayMs: 120,
      sleep,
    });
    expect(peak).toBe(2);
    // Three chunks, so two pauses between them — never before the first.
    expect(waits).toEqual([120, 120]);
  });

  it('retries a 429 after waiting and counts it as applied', async () => {
    const { sleep, waits } = recorder();
    const attempts: string[] = [];
    let limited = false;
    const outcome = await runBulk(['a'], {
      run: async (id) => {
        attempts.push(id);
        if (!limited) {
          limited = true;
          throw new ApiError('slow down', 429, 'rate-limited', 400);
        }
      },
      sleep,
    });
    expect(attempts).toEqual(['a', 'a']);
    expect(waits).toEqual([400]);
    expect(outcome.applied).toEqual(['a']);
    expect(outcome.failed).toEqual([]);
  });

  it('gives up after the retry budget and reports the id as failed', async () => {
    const { sleep, waits } = recorder();
    let calls = 0;
    const outcome = await runBulk(['a', 'b'], {
      run: async (id) => {
        if (id === 'a') {
          calls += 1;
          throw new ApiError('slow down', 429, 'rate-limited', 0);
        }
      },
      maxRetries: 2,
      sleep,
    });
    expect(calls).toBe(3); // first attempt + 2 retries
    expect(outcome.applied).toEqual(['b']);
    expect(outcome.failed).toEqual(['a']);
    expect(waits.length).toBe(2);
  });

  it('does not retry a permanent error', async () => {
    let calls = 0;
    const outcome = await runBulk(['a'], {
      run: async () => {
        calls += 1;
        throw new ApiError('forbidden', 403, 'forbidden');
      },
      sleep: async () => {},
    });
    expect(calls).toBe(1);
    expect(outcome.failed).toEqual(['a']);
  });

  it('reports applied and failed counts honestly on a partial failure', async () => {
    const outcome = await runBulk(ids(4), {
      run: async (id) => {
        if (id === 'm1' || id === 'm3') {
          throw new ApiError('boom', 500, 'server');
        }
      },
      sleep: async () => {},
    });
    expect(outcome.applied).toEqual(['m0', 'm2']);
    expect(outcome.failed).toEqual(['m1', 'm3']);
    expect(outcome.applied.length + outcome.failed.length).toBe(4);
  });

  it('never throws when every id fails', async () => {
    const outcome = await runBulk(ids(3), {
      run: async () => {
        throw new Error('nope');
      },
      sleep: async () => {},
    });
    expect(outcome.applied).toEqual([]);
    expect(outcome.failed).toEqual(ids(3));
  });
});

describe('retryDelayFor', () => {
  it('honours Retry-After over the exponential backoff', () => {
    expect(retryDelayFor(new ApiError('slow', 429, 'x', 5_000), 0)).toBe(5_000);
  });

  it('backs off exponentially without a header', () => {
    expect(retryDelayFor(new ApiError('slow', 429, 'x'), 0)).toBe(300);
    expect(retryDelayFor(new ApiError('slow', 429, 'x'), 2)).toBe(1_200);
  });

  it('caps the wait so a bulk action cannot hang forever', () => {
    expect(retryDelayFor(new ApiError('slow', 429, 'x', 600_000), 0)).toBe(8_000);
  });

  it('refuses to retry errors that will fail again', () => {
    expect(retryDelayFor(new ApiError('forbidden', 403, 'x'), 0)).toBeNull();
    expect(retryDelayFor(new Error('plain'), 0)).toBeNull();
  });
});

describe('deriveActiveIds', () => {
  it('intersects the selection with the visible ids in display order', () => {
    const selected = new Set(['m2', 'm0']);
    expect(deriveActiveIds(['m0', 'm1', 'm2'], selected)).toEqual(['m0', 'm2']);
  });

  it('drops stale ids the list no longer shows', () => {
    const selected = new Set(['gone', 'm1']);
    expect(deriveActiveIds(['m1'], selected)).toEqual(['m1']);
  });

  it('is empty when nothing is selected', () => {
    expect(deriveActiveIds(['m1', 'm2'], new Set())).toEqual([]);
  });
});

describe('remainingSelection', () => {
  it('keeps only the ids that failed', () => {
    const selected = new Set(['a', 'b', 'c']);
    expect([...remainingSelection(selected, ['a', 'c'])]).toEqual(['b']);
  });

  it('keeps the whole selection when nothing succeeded', () => {
    const selected = new Set(['a', 'b']);
    expect([...remainingSelection(selected, [])]).toEqual(['a', 'b']);
  });

  it('empties the selection when everything succeeded', () => {
    const selected = new Set(['a', 'b']);
    expect(remainingSelection(selected, ['a', 'b']).size).toBe(0);
  });
});

describe('nextSurvivor', () => {
  const visible = ['a', 'b', 'c', 'd'];

  it('prefers the next message below the removed one', () => {
    expect(nextSurvivor(visible, new Set(['b']), 'b')).toBe('c');
  });

  it('falls back upwards when the last message goes', () => {
    expect(nextSurvivor(visible, new Set(['d']), 'd')).toBe('c');
  });

  it('skips other removed neighbours', () => {
    expect(nextSurvivor(visible, new Set(['b', 'c']), 'b')).toBe('d');
  });

  it('returns null when the folder is emptied', () => {
    expect(nextSurvivor(visible, new Set(visible), 'b')).toBeNull();
  });

  it('starts from the top when the current id is not in the list', () => {
    expect(nextSurvivor(visible, new Set(['a']), 'not-there')).toBe('b');
  });
});

describe('selection integration', () => {
  it('a partial bulk failure leaves exactly the failed ids selected', async () => {
    const selected = new Set(['a', 'b', 'c', 'd']);
    const active = deriveActiveIds(['a', 'b', 'c', 'd'], selected);
    const outcome = await runBulk(active, {
      run: async (id) => {
        if (id === 'b') {
          throw new ApiError('boom', 500, 'server');
        }
      },
      sleep: async () => {},
    });
    const left = remainingSelection(selected, outcome.applied);
    expect([...left]).toEqual(['b']);
    expect(left.has('a')).toBe(false);
  });
});
