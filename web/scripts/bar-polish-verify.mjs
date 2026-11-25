// Bar-polish verification (user round: desktop two-row bar + mobile delete
// ambiguity): mid-band icon-only one-row layout, danger-red delete vs trash.
// Requires the local API mock on :8801. Exit 1 on any failed check.
const browser = await Camoufox({ headless: true, window: [1440, 900] });
const results = [];
const check = (name, ok, detail = '') => results.push(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
try {
  const page = await browser.newPage({ viewport: { width: 1000, height: 800 }, locale: 'es-AR' });
  await page.goto('http://127.0.0.1:8801/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.waitForTimeout(600);
  await page.click('.mail-row >> nth=0');
  await page.waitForSelector('.reader__bar-actions', { timeout: 15000 });
  await page.waitForTimeout(2500);

  const mid = await page.evaluate(() => {
    const bar = document.querySelector('.reader__bar-actions');
    const rect = bar.getBoundingClientRect();
    const buttons = [...bar.querySelectorAll('button')];
    const rows = new Set(buttons.map((b) => Math.round(b.getBoundingClientRect().top)));
    const deleteBtn = buttons.find((b) => (b.getAttribute('aria-label') ?? '').includes('Eliminar'));
    const trashBtn = buttons.find((b) => (b.getAttribute('aria-label') ?? '').includes('Papelera'));
    return {
      rows: rows.size,
      barHeight: Math.round(rect.height),
      overflow: bar.scrollWidth > bar.clientWidth,
      deleteVisible: deleteBtn ? deleteBtn.getBoundingClientRect().right <= window.innerWidth + 2 : null,
      dColor: deleteBtn ? getComputedStyle(deleteBtn).color : null,
      labels: buttons.map((b) => b.getAttribute('aria-label')),
      tColor: trashBtn ? getComputedStyle(trashBtn).color : null,
      labels: buttons.map((b) => b.getAttribute('aria-label')),
    };
  });
  check('mid-band (1000px): one row of actions', mid.rows === 1, `rows=${mid.rows} barH=${mid.barHeight}`);
  check('mid-band: no overflow', !mid.overflow);
  check('mid-band: delete present and visible', mid.deleteVisible === true, JSON.stringify(mid.labels));
  check('mid-band: delete styled different from trash', mid.dColor !== mid.tColor, `del=${mid.dColor} trash=${mid.tColor}`);
  check('mid-band (1000px): one row of actions', mid.rows === 1, `rows=${mid.rows} barH=${mid.barHeight}`);
  check('mid-band: no overflow', !mid.overflow);
  check('mid-band: delete visible', mid.deleteVisible === true);
  check('mid-band: delete styled different from trash', !mid.sameColor, `del=${mid.dColor} trash=${mid.tColor}`);

  // Mobile 390px: trash vs delete distinct icons/colors.
  await page.setViewportSize({ width: 390, height: 780 });
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.waitForTimeout(600);
  await page.click('.mail-row >> nth=0');
  await page.waitForSelector('.reader__bar-actions', { timeout: 15000 });
  await page.waitForTimeout(2500);
  const mobile = await page.evaluate(() => {
    const bar = document.querySelector('.reader__bar-actions');
    if (bar === null) return { exists: false, labels: [], dColor: null, tColor: null, distinct: false };
    const buttons = [...bar.querySelectorAll('button')];
    const deleteBtn = buttons.find((b) => (b.getAttribute('aria-label') ?? '').includes('Eliminar'));
    const trashBtn = buttons.find((b) => (b.getAttribute('aria-label') ?? '').includes('Papelera'));
    const dColor = deleteBtn ? getComputedStyle(deleteBtn).color : null;
    const tColor = trashBtn ? getComputedStyle(trashBtn).color : null;
    return {
      exists: true,
      labels: buttons.map((b) => b.getAttribute('aria-label')),
      dColor,
      tColor,
      distinct: dColor !== tColor,
    };
  });
  check('mobile: bar present', mobile.exists);
  check('mobile: delete danger-red vs trash default', mobile.distinct, `del=${mobile.dColor} trash=${mobile.tColor} labels=${JSON.stringify(mobile.labels)}`);
  check('mobile: delete danger-red vs trash default', mobile.distinct, `del=${mobile.dColor} trash=${mobile.tColor} labels=${JSON.stringify(mobile.labels)}`);

  await page.screenshot({ path: '/tmp/pigeon-visual/30-mobile-bar.png' });
  const failures = results.filter((l) => l.startsWith('FAIL'));
  console.log(results.join('\n'));
  console.log(`\n${results.length - failures.length}/${results.length} checks passed`);
  process.exitCode = failures.length ? 1 : 0;
} finally { await browser.close(); }
