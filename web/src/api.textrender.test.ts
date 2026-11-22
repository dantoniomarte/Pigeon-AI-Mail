import { describe, expect, it } from 'vitest';

import { buildEmailFrame, linkifyText } from './api';

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
    expect(doc).not.toContain('<script');
    expect(doc).not.toContain('<iframe');
    expect(doc).not.toContain('<object');
    expect(doc).not.toContain('<embed');
    expect(doc).not.toContain('onerror');
    expect(doc).toContain('<p>hi</p>');
  });
});
