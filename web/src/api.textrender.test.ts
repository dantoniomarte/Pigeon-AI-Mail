import { describe, expect, it } from 'vitest';

import { buildEmailFrame, decodeMimeWords, linkifyText } from './api';

describe('linkifyText', () => {
  it('splits text around an https url and keeps surrounding words', () => {
    expect(linkifyText('See https://ejemplo.com/a?b=1&c=2 now.')).toEqual([
      { kind: 'text', value: 'See ' },
      { kind: 'link', value: 'https://ejemplo.com/a?b=1&c=2', href: 'https://ejemplo.com/a?b=1&c=2' },
      { kind: 'text', value: ' now.' },
    ]);
  });

  it('links www addresses with an https href and drops trailing punctuation', () => {
    expect(linkifyText('visita www.ejemplo.com.ar/path.')).toEqual([
      { kind: 'text', value: 'visita ' },
      { kind: 'link', value: 'www.ejemplo.com.ar/path', href: 'https://www.ejemplo.com.ar/path' },
      { kind: 'text', value: '.' },
    ]);
  });

  it('returns a single text token when there is no url', () => {
    expect(linkifyText('sin enlaces')).toEqual([{ kind: 'text', value: 'sin enlaces' }]);
    expect(linkifyText('')).toEqual([]);
  });

  it('linkifies several urls in one string', () => {
    const tokens = linkifyText('https://a.dev y www.b.dev');
    expect(tokens.filter((token) => token.kind === 'link')).toHaveLength(2);
    expect(tokens[0]).toEqual({ kind: 'link', value: 'https://a.dev', href: 'https://a.dev' });
  });
});

describe('buildEmailFrame', () => {
  const body = '<h2>Title</h2><p>Body copy</p>';

  it('wraps the email html with a strict csp and a blank-target base', () => {
    const doc = buildEmailFrame(body, false);
    expect(doc).toContain('<!doctype html>');
    expect(doc).toContain('<base target="_blank">');
    expect(doc).toContain(body);
    // Scripts are dead twice over: sandbox + default-src 'none'.
    expect(doc).toContain("default-src 'none'");
  });

  it('blocks remote images by default and allows data urls', () => {
    const doc = buildEmailFrame(body, false);
    expect(doc).toContain('img-src data: blob:');
    expect(doc).not.toContain('http:');
    // Long URLs in email markup must wrap, not stretch the frame document;
    // fixed-width newsletter tables and images scale down like mainstream
    // mail readers do.
    expect(doc).toContain('overflow-wrap:anywhere');
    expect(doc).toContain('table{max-width:100%}');
    expect(doc).toContain('img{max-width:100%;height:auto}');
  });

  it('allows remote images only when the reader explicitly asked', () => {
    expect(buildEmailFrame(body, true)).toContain('img-src https: http:');
  });

  it('strips scripts, embeds and inline handlers from the email html', () => {
    const doc = buildEmailFrame(
      '<p>hi</p><script>window.__pwned=1</script><iframe src="https://evil.example"></iframe>' +
        '<object data="x"></object><embed src="x"><img src="https://cdn.example/x.png" onerror="steal()">',
      false,
    );
    // Sender scripts are gone; the frame ships exactly one script (the
    // height bootstrap injected after the body html, not sender markup).
    const body = doc.slice(doc.indexOf('<body>'));
    expect(body).not.toContain('<script');
    expect(doc).not.toContain('<iframe');
    expect(doc).not.toContain('<object');
    expect(doc).not.toContain('<embed');
    expect(doc).not.toContain('onerror');
    expect(doc.match(/<script/g)).toHaveLength(1);
    expect(doc).toContain('pigeon-frame-height');
    expect(doc).toContain("script-src 'unsafe-inline'");
    expect(doc).toContain('<p>hi</p>');
  });
});

describe('decodeMimeWords', () => {
  it('decodes B and Q encoded words for legacy stored subjects', () => {
    expect(decodeMimeWords('=?UTF-8?B?UHJvZHVjdCBwdWxzZSDigJQgRmVicnVhcnk=?=')).toBe('Product pulse — February');
    expect(decodeMimeWords('=?utf-8?Q?Caf=C3=A9_con_leche?=')).toBe('Café con leche');
    expect(decodeMimeWords('=?ISO-8859-1?B?Q2Fm6Q==?=')).toBe('Café');
  });

  it('joins adjacent words without the separating whitespace and keeps prose', () => {
    expect(decodeMimeWords('=?utf-8?Q?Bienvenido?= =?utf-8?Q?de_nuevo?=')).toBe('Bienvenidode nuevo');
    expect(decodeMimeWords('Re: =?utf-8?Q?prueba?= del sistema')).toBe('Re: prueba del sistema');
    expect(decodeMimeWords('asunto normal')).toBe('asunto normal');
    expect(decodeMimeWords('')).toBe('');
  });

  it('passes unknown charsets and malformed markers through verbatim', () => {
    expect(decodeMimeWords('=?koi8-r?B?/v7w8Q==?=')).toBe('=?koi8-r?B?/v7w8Q==?=');
    expect(decodeMimeWords('=?utf-8?')).toBe('=?utf-8?');
  });
});

describe('buildEmailFrame dark scheme', () => {
  const body = '<p>hello</p><table style="background:#ffffff"><tr><td>cell</td></tr></table>';

  it('emits a dark override layer when the scheme is dark', () => {
    const doc = buildEmailFrame(body, false, 'dark');
    expect(doc).toContain('pigeon-dark-email');
    expect(doc).toContain('color-scheme:dark');
    expect(doc).not.toContain('html{background:#fff}');
  });

  it('keeps the light canvas when the scheme is light', () => {
    const doc = buildEmailFrame(body, false, 'light');
    expect(doc).toContain('html{background:#fff;overflow-x:auto');
    expect(doc).not.toContain('pigeon-dark-email');
  });

  it('defaults to light for existing callers', () => {
    expect(buildEmailFrame(body, false)).toContain('html{background:#fff;overflow-x:auto');
  });
});

describe('buildEmailFrame style preservation', () => {
  it('keeps the email own style block and injects it after the base', () => {
    const doc = buildEmailFrame(
      '<html><head><style>pre{background:#1e222e}</style></head><body><pre><code>x</code></pre></body></html>',
      false,
    );
    const styles = doc.match(/<style>([^<]*)<\/style>/g) ?? [];
    expect(styles.length).toBe(2);
    expect(styles[0]).toContain('html{background:#fff;overflow-x:auto');
    expect(styles[1]).toContain('pre{background:#1e222e}');
  });
});

describe('dark painted surfaces preservation', () => {
  // The real-world pattern behind "Visit group"/"View profile" buttons:
  // the fill lives on the enclosing cell (bgcolor), not on the anchor.
  const visitGroup =
    '<table><tr><td bgcolor="#1877f2" style="border-radius:6px">' +
    '<a href="https://groups.example.com/visit" style="display:inline-block;padding:10px 16px;color:#ffffff;font-weight:600">Visit group</a>' +
    '</td></tr></table>';

  it('keeps button-like cells painted with contrasting text in dark', () => {
    const doc = buildEmailFrame(visitGroup, false, 'dark');
    expect(doc).toContain('data-pk=');
    expect(doc).toContain('background-color:rgb(24, 119, 242)!important');
    expect(doc).toContain('color:rgb(255, 255, 255)!important');
    // The anchor itself is painted too, so the clickable area is the button.
    expect(doc).toContain('data-pk=');
  });

  it('keeps OTP-style chips painted (light fill, dark text)', () => {
    const doc = buildEmailFrame(
      '<p style="background:#f0f2f5;padding:14px 20px;border-radius:8px;font-size:34px">03730</p>',
      false,
      'dark',
    );
    expect(doc).toContain('data-pk=');
    expect(doc).toContain('background-color:rgb(240, 242, 245)!important');
    expect(doc).toMatch(/color:#111418!important/);
  });

  it('neutralizes long-text containers (no dark glare)', () => {
    const doc = buildEmailFrame(
      '<div style="background:#0f6b5c;padding:18px"><p>' + 'x'.repeat(120) + '</p></div>',
      false,
      'dark',
    );
    expect(doc).not.toContain('data-pk=');
    expect(doc).toContain('background-color:transparent!important');
  });

  it('escapes hostile fill values (no style escape, no script)', () => {
    const doc = buildEmailFrame(
      '<div style="background:#fff}</style><script>parent.postMessage({type:\'pwned\'},\'*\')</script><style>a:;padding:4px">Verify</div>',
      false,
      'dark',
    );
    // The hostile payload is parsed to nothing: no data-pk, no raw escape,
    // exactly one script (the height bootstrap).
    expect(doc.match(/<script/g)).toHaveLength(1);
    expect(doc).not.toContain('pwned');
    expect(doc).not.toContain('data-pk');
    expect(doc).not.toContain('@layer pigeon-dark-email{[data-pk');
  });

  it('preserves named colors with contrasting text', () => {
    const doc = buildEmailFrame(
      '<div style="background:white;padding:18px">Order shipped</div>',
      false,
      'dark',
    );
    expect(doc).toContain('background-color:rgb(255, 255, 255)!important');
    expect(doc).toContain('color:#111418!important');
  });

  it('treats near-transparent fills as non-surfaces', () => {
    const doc = buildEmailFrame(
      '<div style="background:rgba(255,255,255,0.08);padding:18px">dark panel</div>',
      false,
      'dark',
    );
    expect(doc).not.toContain('data-pk=');
  });

  it('lets a nested CTA keep its own fill over the preserved card', () => {
    const doc = buildEmailFrame(
      '<div style="background:#ffffff;padding:20px"><a style="background:#1877f2;color:#fff;padding:10px 14px">Confirm</a></div>',
      false,
      'dark',
    );
    // The card is preserved (short text) AND the anchor is preserved: the
    // anchor's own rule (0,1,0) must beat the :where() descendant rule.
    expect(doc).toContain('background-color:rgb(24, 119, 242)!important');
    expect(doc).toContain('background-color:rgb(255, 255, 255)!important');
    // Order: card rule first, anchor rule after (document order).
    const cardPos = doc.indexOf('background-color:rgb(255, 255, 255)!important');
    const anchorPos = doc.indexOf('background-color:rgb(24, 119, 242)!important');
    expect(anchorPos).toBeGreaterThan(cardPos);
  });

  it('gives outlined padded anchors a low-key affordance in dark', () => {
    const doc = buildEmailFrame(
      '<a style="display:inline-block;padding:12px 22px;border:2px solid #1877f2;color:#1877f2">Get started</a>',
      false,
      'dark',
    );
    expect(doc).toContain('background-color:rgba(108,178,255,.12)!important');
    expect(doc).toContain('border:1px solid rgba(108,178,255,.5)!important');
  });
});
