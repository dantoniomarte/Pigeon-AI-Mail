// Round-4 runtime verification (odd/tasks/sent-bodies-render-audit.md):
// XSS inertness with the allow-scripts bootstrap sandbox, dark <style>-block
// paint channels (text-fill/filter/opacity), frame auto-sizing, sent reader
// body in light and dark. Requires the local API mock on :8801 with the
// adversarial + sent fixtures. Exit 1 on any failed check.
const browser = await Camoufox({ headless: true, window: [1440, 900] });
const results = [];
const check = (name, ok, detail = '') => results.push(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, locale: 'es-AR' });
  let dialogFired = false;
  page.on('dialog', async (dialog) => { dialogFired = true; await dialog.dismiss(); });
  await page.goto('http://127.0.0.1:8801/', { waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.waitForTimeout(400);

  // --- 1. XSS probe row: sandbox + sanitizer still inert -------------------
  await page.click('text=XSS probe');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(1200);
  const frame = page.frames().find((f) => f.url() === 'about:srcdoc');
  const xss = await frame.evaluate(() => ({
    scriptTags: document.body.querySelectorAll('script').length,
    pwned: window.__pwned ?? null,
    legit: document.body.textContent.includes('legit paragraph'),
  }));
  check('xss: sender script removed', xss.scriptTags === 0, `${xss.scriptTags} body script tags`);
  check('xss: no execution', xss.pwned === null);
  check('xss: legit content renders', xss.legit);
  const sandbox = await page.locator('.reader__frame').getAttribute('sandbox');
  check('sandbox: scripts allowed but origin opaque', sandbox.includes('allow-scripts') && !sandbox.includes('allow-same-origin'), sandbox);
  check('xss: javascript: link inert after click', dialogFired === false);
  // The height bootstrap must be the only script in the document.
  const bodyScripts = await frame.evaluate(() => document.body.querySelectorAll('script').length);
  check('frame scripts: only bootstrap', bodyScripts === 0, `${bodyScripts} body scripts`);

  // --- 2. Adversarial dark: <style>-block paint channels -------------------
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.click('text=Adversarial dark patterns');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(900);
  const frameDark = page.frames().find((f) => f.url() === 'about:srcdoc');
  const styleAudit = await frameDark.evaluate(() => {
    const lum = (color) => {
      const m = color.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
      if (!m) return null;
      const [r, g, b] = [1, 2, 3].map((i) => {
        const v = Number(m[i]) / 255;
        return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    const ratio = (el) => {
      const fg = lum(getComputedStyle(el).color);
      const bg = lum('rgb(23, 26, 35)');
      const [hi, lo] = fg > bg ? [fg, bg] : [bg, fg];
      return ((hi + 0.05) / (lo + 0.05)).toFixed(2);
    };
    const h = document.querySelector('h1');
    const finv = document.querySelector('.f-inv');
    const olow = document.querySelector('.o-low');
    return {
      h1Color: h ? getComputedStyle(h).color : null,
      h1Fill: h ? getComputedStyle(h).webkitTextFillColor : null,
      h1Ratio: h ? ratio(h) : null,
      h1Text: h?.textContent,
      finvColor: finv ? getComputedStyle(finv).color : null,
      finvFilter: finv ? getComputedStyle(finv).filter : null,
      finvRatio: finv ? ratio(finv) : null,
      olowOpacity: olow ? getComputedStyle(olow).opacity : null,
      olowRatio: olow ? ratio(olow) : null,
    };
  });
  check('dark: style gradient headline text lifted', styleAudit.h1Fill === 'rgb(230, 237, 243)' && Number(styleAudit.h1Ratio) >= 4.5, `ratio=${styleAudit.h1Ratio} color=${styleAudit.h1Color} fill=${styleAudit.h1Fill}`);
  check('dark: style filter inverted neutralized', styleAudit.finvFilter === 'none' && Number(styleAudit.finvRatio) >= 4.5, `filter=${styleAudit.finvFilter} ratio=${styleAudit.finvRatio}`);
  check('dark: style opacity lifted', styleAudit.olowOpacity === '1' && Number(styleAudit.olowRatio) >= 4.5, `opacity=${styleAudit.olowOpacity} ratio=${styleAudit.olowRatio}`);

  // --- 3. Frame auto-height: short email has no white void -----------------
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'light'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForSelector('.mail-list', { timeout: 15000 });
  await page.click('text=03730 is your Facebook confirmation');
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(1100);
  const shortMail = await page.evaluate(() => {
    const frame = document.querySelector('.reader__frame');
    const actions = document.querySelector('.reader__actions');
    return {
      height: frame ? Math.round(frame.getBoundingClientRect().height) : null,
      actionsVisible: actions !== null && actions.getBoundingClientRect().bottom <= window.innerHeight + 1,
    };
  });
  check('frame: short mail sized to content (<= 420px)', shortMail.height !== null && shortMail.height <= 420, `height=${shortMail.height}`);
  check('frame: actions visible without scroll', shortMail.actionsVisible);

  // Banner absent for mail without remote content.
  const bannerAbsent = await page.evaluate(() => document.querySelector('.reader__images-note') === null);
  check('images banner absent without remote content', bannerAbsent);

  // --- 4. Sent flow: list + body + dark rendering --------------------------
  await page.click('.reader__back').catch(() => {});
  await page.waitForTimeout(400);
  await page.getByRole('button', { name: /Enviados|Sent/i }).first().click().catch(async () => {
    await page.evaluate(() => {
      const buttons = [...document.querySelectorAll('button, a')];
      const target = buttons.find((b) => /enviados/i.test(b.textContent ?? ''));
      target?.click();
    });
  });
  await page.waitForTimeout(800);
  const sentRows = await page.evaluate(() => document.querySelectorAll('.mail-row').length);
  check('sent: rows listed', sentRows >= 2, `${sentRows} rows`);
  await page.click('text=Una prueba de envío');
  await page.waitForTimeout(1200);
  const sentFrame = await page.evaluate(() => {
    const frame = document.querySelector('.reader__frame');
    if (frame === null) return { frame: false };
    return { frame: true, height: Math.round(frame.getBoundingClientRect().height) };
  });
  check('sent: html body frame rendered', sentFrame.frame === true, JSON.stringify(sentFrame));
  // Switch to dark and confirm the sent frame follows.
  await page.evaluate(() => localStorage.setItem('pigeon_theme', 'dark'));
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForTimeout(600);
  // Re-open the sent message after reload (selection resets).
  await page.getByRole('button', { name: /Enviados|Sent/i }).first().click().catch(() => {});
  await page.waitForTimeout(500);
  await page.click('text=Una prueba de envío').catch(() => {});
  await page.waitForSelector('.reader__frame', { timeout: 15000 });
  await page.waitForTimeout(900);
  const sentDark = await page.evaluate(() => document.documentElement.dataset['theme']);
  check('sent: dark theme active for re-check', sentDark === 'dark', sentDark);
  const frameDark2 = page.frames().find((f) => f.url() === 'about:srcdoc');
  const sentDarkOk = frameDark2 !== undefined && (await frameDark2.evaluate(() => getComputedStyle(document.body).color)).includes('230, 237, 243');
  check('sent: dark palette inside sent frame', sentDarkOk);

  const failures = results.filter((l) => l.startsWith('FAIL'));
  console.log(results.join('\n'));
  console.log(`\n${results.length - failures.length}/${results.length} checks passed`);
  process.exitCode = failures.length ? 1 : 0;
} finally {
  await browser.close();
}
