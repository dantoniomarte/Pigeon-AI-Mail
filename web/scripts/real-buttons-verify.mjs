// Real-button verification (odd/tasks/button-render-audit.md, user round):
// Visit group / View profile cells (fill on the cell, not the anchor) and the
// OTP chip must render painted with contrasting text in dark. Requires the
// local API mock on :8801 with the real-pattern fixtures. Exit 1 on failure.
const browser = await Camoufox({ headless: true, window: [1440, 900] });
const results = [];
const check = (name, ok, detail = '') => results.push(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);

// WCAG contrast between two rgb() strings.
const lum = (color) => {
  const m = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
  if (m === null) return null;
  const [r, g, b] = [1, 2, 3].map((i) => {
    const v = Number(m[i]) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (fg, bg) => {
  const l1 = lum(fg);
  const l2 = lum(bg);
  if (l1 === null || l2 === null) return null;
  const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
};

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'es-AR' });
  await page.goto('http://127.0.0.1:8801/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });

  // --- Visit group / View profile in dark: painted + contrasting -----------
  await page.click('text=Lucas, visit your new group');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(1000);
  const frame = page.frames().filter((f) => f.url() === 'about:srcdoc').pop();
  const buttons = await frame.evaluate(() =>
    [...document.querySelectorAll('a')].map((a) => {
      const cs = getComputedStyle(a);
      const cell = a.closest('td');
      return {
        text: (a.textContent ?? '').trim(),
        color: cs.color,
        anchorBg: cs.backgroundColor,
        cellBg: cell ? getComputedStyle(cell).backgroundColor : null,
      };
    }),
  );
  for (const b of buttons) {
    const fill = b.anchorBg !== 'rgba(0, 0, 0, 0)' ? b.anchorBg : b.cellBg;
    const ratio = fill !== null ? contrast(b.color, fill) : null;
    check(
      `button "${b.text}" painted (solid fill) in dark`,
      fill !== null && !fill.startsWith('rgba(0, 0, 0, 0') && !fill.startsWith('rgba(108,178'),
      JSON.stringify(b),
    );
    check(
      `button "${b.text}" text contrast >= 3:1 on its fill`,
      ratio !== null && ratio >= 3,
      `ratio=${ratio}`,
    );
  }

  // --- OTP chip in dark: painted, contrasting digits ------------------------
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'light'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.click('text=03730 is your Facebook confirmation');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(900);
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.click('text=03730 is your Facebook confirmation');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(1000);
  const frame2 = page.frames().filter((f) => f.url() === 'about:srcdoc').pop();
  const otp = await frame2.evaluate(() => {
    const chips = [...document.querySelectorAll('p')].filter((p) => /^\d{5}$/.test((p.textContent ?? '').trim()));
    if (chips.length === 0) return null;
    const cs = getComputedStyle(chips[0]);
    return { bg: cs.backgroundColor, color: cs.color, text: chips[0].textContent };
  });
  const otpRatio = otp !== null ? contrast(otp.color, otp.bg) : null;
  check('OTP chip painted in dark', otp !== null && otp.bg !== 'rgba(0, 0, 0, 0)' && otp.bg !== 'transparent', JSON.stringify(otp));
  check('OTP digits contrast >= 3:1', otpRatio !== null && otpRatio >= 3, `ratio=${otpRatio}`);

  const failures = results.filter((l) => l.startsWith('FAIL'));
  console.log(results.join('\n'));
  console.log(`\n${results.length - failures.length}/${results.length} checks passed`);
  process.exitCode = failures.length ? 1 : 0;
} finally {
  await browser.close();
}
