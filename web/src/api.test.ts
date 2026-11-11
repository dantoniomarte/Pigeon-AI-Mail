import { afterEach, describe, expect, it, vi } from 'vitest';

import { demoEnrichment, fetchFolder, fetchSent, isDemoSentId } from './api';

/**
 * Demo mode has no server to count for it, so the offline counts are derived from
 * the bundled sample mail. These pins keep those badges honest: the inbox badge
 * must equal the unread rows the list marks bold, and each folder size must equal
 * the list it stands for. A hand-written constant would drift the moment a sample
 * message is added.
 */
describe('demo folder counts', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Make every read fail at the network layer: the only path into demo mode. */
  function goOffline(): void {
    vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')));
  }

  it('matches the demo inbox it hands over', async () => {
    goOffline();
    const result = await fetchFolder(null, 'inbox');

    expect(result.demo).toBe(true);
    const counts = result.counts;
    expect(counts).toBeDefined();

    const unread = result.data.filter(
      (message) => demoEnrichment(message.id)?.unread === true,
    ).length;
    expect(unread).toBeGreaterThan(0);
    expect(counts?.unread_inbox).toBe(unread);
    expect(counts?.inbox).toBe(result.data.length);
    expect(counts?.unread_spam).toBe(0);
    expect(counts?.unread_trash).toBe(0);
  });

  it('never reports unread outbound mail', async () => {
    goOffline();
    const sent = await fetchSent(null);

    expect(sent.demo).toBe(true);
    expect(sent.counts?.sent).toBe(sent.data.length);
    // Outbound copies are never unread, so the contract has no member for it:
    // a client must not be able to render an unread Sent badge.
    expect(Object.keys(sent.counts ?? {})).not.toContain('unread_sent');
  });
});

describe('isDemoSentId', () => {
  it('gates the demo delete branch by id shape, not the global demo flag', () => {
    expect(isDemoSentId('eml_demo3f7c1a20')).toBe(true);
    expect(isDemoSentId('eml_6df88cf040747e6d')).toBe(false);
    expect(isDemoSentId('msg_0000000c')).toBe(false);
  });
});
