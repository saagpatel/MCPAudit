// Optional browser acceptance: requires an installed Playwright and Chromium.
// MCPAUDIT_PLAYWRIGHT_MODULE can select an existing installation without downloads.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs/promises');
const { pathToFileURL } = require('node:url');
const { chromium } = require(process.env.MCPAUDIT_PLAYWRIGHT_MODULE || 'playwright');

async function check(page, width, scheme, fixture) {
  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    content: document.documentElement.scrollWidth,
  }));
  assert.ok(dimensions.content <= dimensions.viewport, `${fixture}: ${width}/${scheme} overflows`);
  assert.equal(await page.locator('script').count(), 0);
  const contrast = await page.locator('footer').evaluate(element => {
    const rgb = color => color.match(/[\d.]+/g).slice(0, 3).map(Number);
    const luminance = color => rgb(color).map(channel => {
      const value = channel / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    }).reduce((sum, channel, index) => sum + channel * [0.2126, 0.7152, 0.0722][index], 0);
    const foreground = luminance(getComputedStyle(element).color);
    const background = luminance(getComputedStyle(document.body).backgroundColor);
    return (Math.max(foreground, background) + 0.05) / (Math.min(foreground, background) + 0.05);
  });
  assert.ok(contrast >= 4.5, `${fixture}: muted contrast ${contrast}`);
}

async function main() {
  const output = path.resolve('output/playwright');
  await fs.mkdir(output, { recursive: true });
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.MCPAUDIT_BROWSER_CHANNEL ? { channel: process.env.MCPAUDIT_BROWSER_CHANNEL } : {}),
  });
  try {
    const page = await browser.newPage();
    for (const fixture of ['sample_audit_report', 'config_only_report']) {
      for (const width of [1440, 390]) {
        for (const scheme of ['light', 'dark']) {
          await page.setViewportSize({ width, height: 1000 });
          await page.emulateMedia({ colorScheme: scheme });
          await page.goto(pathToFileURL(path.resolve(`tests/fixtures/html/${fixture}.html`)).href);
          await check(page, width, scheme, fixture);
          await page.screenshot({ path: path.join(output, `${fixture}-${width}-${scheme}.png`), fullPage: true });
          await page.locator('details').evaluateAll(elements => elements.forEach(element => { element.open = true; }));
          await check(page, width, scheme, fixture);
          console.log(`${fixture}: ${width}/${scheme}, collapsed and expanded: passed`);
        }
      }
    }
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
