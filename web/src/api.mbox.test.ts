import { describe, expect, it } from 'vitest';

import { mboxEscapeBytes } from './api';

/** The server's pigeon_api::mime::mbox_escape_bytes, mirrored for drift pins. */
function rustMboxEscapeBytes(document: Uint8Array): Uint8Array {
  // Mirrors the server's empty guard (mime.rs).
  if (document.length === 0) {
    return new Uint8Array(0);
  }
  const out: number[] = [];
  let lineStart = 0;
  for (let index = 0; index <= document.length; index += 1) {
    const atEnd = index === document.length;
    if (atEnd || document[index] === 0x0a) {
      const line = document.subarray(lineStart, index);
      let depth = 0;
      while (depth < line.length && line[depth] === 0x3e) {
        depth += 1;
      }
      const rest = line.subarray(depth);
      const isFrom =
        rest.length >= 5 &&
        rest[0] === 0x46 &&
        rest[1] === 0x72 &&
        rest[2] === 0x6f &&
        rest[3] === 0x6d &&
        rest[4] === 0x20;
      if (isFrom) {
        out.push(0x3e);
      }
      for (const byte of line) {
        out.push(byte);
      }
      if (atEnd && out[out.length - 1] !== 0x0a) {
        out.push(0x0a);
      }
      if (!atEnd) {
        out.push(0x0a);
      }
      lineStart = index + 1;
    }
  }
  return new Uint8Array(out);
}

describe('mboxEscapeBytes (client twin of the server escape)', () => {
  it('matches the Rust escape on every line shape', () => {
    const cases: Uint8Array[] = [
      new TextEncoder().encode('From the top.\r\n>From quoted.\r\n>>From nested.\r\nFrom: untouched\r\ntail'),
      new TextEncoder().encode(''),
      new TextEncoder().encode('no trailing newline From x'),
      new TextEncoder().encode('lone cr\rtail'),
      new TextEncoder().encode('From:\r\n>From:\r\n'),
      new Uint8Array([0x65, 0x73, 0x70, 0x61, 0xf1, 0x6f, 0x6c, 0x0d, 0x0a]),
    ];
    for (const input of cases) {
      expect(Array.from(mboxEscapeBytes(input))).toEqual(Array.from(rustMboxEscapeBytes(input)));
    }
  });

  it('escapes every line-initial From_ so readers never split mid-body', () => {
    const escaped = new TextDecoder().decode(
      mboxEscapeBytes(new TextEncoder().encode('From x\r\n>From y\r\n')),
    );
    expect(escaped).toBe('>From x\r\n>>From y\r\n');
  });

  it('round-trips 8-bit bytes unchanged', () => {
    const latin1 = new Uint8Array([0x65, 0x73, 0x70, 0x61, 0xf1, 0x6f, 0x6c, 0x0d, 0x0a]);
    expect(Array.from(mboxEscapeBytes(latin1))).toEqual([0x65, 0x73, 0x70, 0x61, 0xf1, 0x6f, 0x6c, 0x0d, 0x0a]);
  });
});
