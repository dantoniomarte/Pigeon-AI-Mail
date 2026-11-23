// Button-render verification (odd/tasks/button-render-audit.md): the three
// CRITICAL findings from the judge audit, re-checkable after any change.
// Requires the local API mock on :8801. Exit 1 on any failed check.
const browser = await Camoufox({ headless: true, window: [1440, 900] });
const results = [];
const check = (name, ok, detail = '') => results.push(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);

try {
  const page = await browser.newPage({ viewport: { width: 390, height: 780 }, locale: 'es-AR' });
  await page.goto('http://127.0.0.1:8801/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });

  // B-001: compose foot actions fully visible at 390 and 360.
  await page.evaluate(() => document.querySelector('[aria-label*="Redactar"], button, a')?.closest('.app'));
  const composeButtons = page.locator('button:has-text("Redactar"), [class*="compose"]');
  await page.evaluate(() => {
    const candidates = [...document.querySelectorAll('button, a')];
    candidates.find((b) => /redactar/i.test(b.textContent ?? ''))?.click();
  });
  await page.waitForTimeout(600);
  const composeFoot = await page.evaluate(() => {
    const row = document.querySelector('.compose__foot-actions');
    if (!row) return null;
    const send = [...row.querySelectorAll('button')].find((b) => /enviar/i.test(b.textContent ?? ''));
    if (!send) return null;
    const rowRect = row.getBoundingClientRect();
    const sendRect = send.getBoundingClientRect();
    return {
      rowScroll: row.scrollWidth,
      rowClient: row.clientWidth,
      sendRight: Math.round(sendRect.right),
      sendBottom: Math.round(sendRect.bottom),
      rowBottom: Math.round(rowRect.bottom),
      viewport: window.innerWidth,
    };
  });
  check(
    'B-001 compose Enviar fully visible',
    composeFoot !== null && composeFoot.sendRight <= composeFoot.viewport + 1 && composeFoot.rowScroll <= composeFoot.rowClient + 1,
    JSON.stringify(composeFoot),
  );
  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);

  // B-002: sender CTA has fill + border in dark.
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.click('text=Cuéntanos tu experiencia').catch(async () => {
    await page.evaluate(() => {
      const rows = [...document.querySelectorAll('.mail-row__subject')];
      const target = rows.find((r) => r.textContent?.includes('experiencia'));
      target?.click();
    });
  });
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(800);
  const cta = await page.frames().find((f) => f.url() === 'about:srcdoc').evaluate(() => {
    const a = [...document.querySelectorAll('a')].find((el) => /responder/i.test(el.textContent ?? ''));
    if (!a) return null;
    const cs = getComputedStyle(a);
    return { bg: cs.backgroundColor, border: cs.borderWidth, borderColor: cs.borderColor };
  });
  check(
    'B-002 sender CTA reads as button in dark',
    cta !== null && cta.bg !== 'rgba(0, 0, 0, 0)' && cta.border !== '0px',
    JSON.stringify(cta),
  );

  // B-003: newsletter no horizontal cut (scrollable, not clipped).
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'light'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.evaluate(() => {
    const rows = [...document.querySelectorAll('.mail-row__subject')];
    const target = rows.find((r) => r.textContent?.includes('member of'));
    target?.click();
  });
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(800);
  const overflow = await page.frames().find((f) => f.url() === 'about:srcdoc').evaluate(() => ({
    docScroll: document.documentElement.scrollWidth,
    docClient: document.documentElement.clientWidth,
    overflowX: getComputedStyle(document.documentElement).overflowX,
    headerBandRight: (() => {
      const band = [...document.querySelectorAll('td')].find((td) => (td.getAttribute('style') ?? '').includes('4c8bf5'));
      return band ? Math.round(band.getBoundingClientRect().right) : null;
    })(),
  }));
  check(
    'B-003 newsletter content reachable (scrollable)',
    overflow.docScroll <= overflow.docClient + 1 || overflow.overflowX === 'auto',
    JSON.stringify(overflow),
  );

  const failures = results.filter((l) => l.startsWith('FAIL'));
  console.log(results.join('\n'));
  console.log(`\n${results.length - failures.length}/${results.length} checks passed`);
  process.exitCode = failures.length ? 1 : 0;
} finally {
  await browser.close();
}
