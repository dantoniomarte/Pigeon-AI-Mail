// Dark-mode email contrast audit (evidence for odd/tasks/dark-email-contrast.md).
// Usage: node web/scripts/dark-contrast-audit.mjs <path-to-web-dist>
// Requires the local API mock (see mock in the PR run log) on :8801 serving
// that dist, with the adversarial fixture email "Adversarial dark patterns"
// (gradient headline, !important colors, filter:invert, mark/del, CTA,
// bgcolor table, styled input). Measures WCAG contrast of real rendered
// elements composited over the REAL iframe box background. Exit 1 on any
// element below 4.5:1. Requires camoufox-js (npx cache path below).
import { Camoufox } from '/home/dantonio/.npm/_npx/bed392e8e779d408/node_modules/camoufox-js/dist/index.js';

const browser = await Camoufox({ headless: true, window: [1440, 900] });
const results = [];
const check = (name, ok, detail = '') => results.push(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'es-AR' });
  await page.goto('http://127.0.0.1:8801/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });

  await page.click('text=Adversarial dark patterns');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(900);
  const boxBg = await page.evaluate(() => {
    const frame = document.querySelector('.reader__frame');
    return frame !== null ? getComputedStyle(frame).backgroundColor : null;
  });

  const frame = page.frames().find((f) => f.url() === 'about:srcdoc');
  const audit = await frame.evaluate((boxBg) => {
    const parse = (color) => {
      if (typeof color !== 'string') return null;
      const match = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
      if (!match) return null;
      return {
        r: Number(match[1]),
        g: Number(match[2]),
        b: Number(match[3]),
        a: match[4] === undefined ? 1 : Number(match[4]),
      };
    };
    const mix = (top, under) => ({
      r: Math.round(top.r * top.a + under.r * (1 - top.a)),
      g: Math.round(top.g * top.a + under.g * (1 - top.a)),
      b: Math.round(top.b * top.a + under.b * (1 - top.a)),
      a: 1,
    });
    const lum = (c) => {
      const [lr, lg, lb] = [c.r, c.g, c.b].map((v) => {
        const x = v / 255;
        return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * lr + 0.7152 * lg + 0.0722 * lb;
    };
    const contrast = (fg, bg) => {
      const l1 = lum(fg);
      const l2 = lum(bg);
      const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
      return (hi + 0.05) / (lo + 0.05);
    };
    const compositedBg = (el) => {
      // innermost -> outermost; base is the real iframe box color
      const chain = [];
      let node = el;
      while (node && node !== document.documentElement) {
        const parsed = parse(getComputedStyle(node).backgroundColor);
        if (parsed && parsed.a > 0) chain.unshift(parsed);
        node = node.parentElement;
      }
      let under = parse(boxBg) ?? { r: 23, g: 26, b: 35, a: 1 };
      for (const layer of chain) under = mix(layer, under);
      return under;
    };
    const out = [];
    for (const selector of ['h1', 'p', 'del', 'mark', 'a', 'th', 'td', 'input', '.invcheck']) {
      const el = document.querySelector(selector);
      if (!el) { out.push({ selector, missing: true }); continue; }
      const fg = parse(getComputedStyle(el).color);
      if (!fg) { out.push({ selector, skipped: true }); continue; }
      const ratio = contrast(fg, compositedBg(el));
      out.push({
        selector,
        color: getComputedStyle(el).color,
        ratio: ratio.toFixed(2),
        text: (el.textContent ?? el.value ?? '').trim().slice(0, 24),
      });
    }
    return out;
  }, boxBg);

  check('iframe box dark/transparent in dark mode', boxBg === 'rgba(0, 0, 0, 0)' || boxBg === 'transparent', String(boxBg));

  for (const row of audit) {
    if (row.missing) { check(`${row.selector} present`, false, 'missing'); continue; }
    if (row.skipped) { check(`${row.selector} measurable`, false, 'no color'); continue; }
    check(`${row.selector} contrast >= 4.5`, Number(row.ratio) >= 4.5, `ratio=${row.ratio} color=${row.color} text="${row.text}"`);
  }

  await page.locator('.reader__frame').screenshot({ path: '/tmp/pigeon-visual/21-dark-adversarial.png' });

  const failures = results.filter((l) => l.startsWith('FAIL'));
  console.log(results.join('\n'));
  console.log(`\n${results.length - failures.length}/${results.length} checks passed`);
  process.exitCode = failures.length ? 1 : 0;
} finally {
  await browser.close();
}
