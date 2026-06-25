import express from "express";
import { chromium } from "playwright";
import dns from "node:dns/promises";
import net from "node:net";
import crypto from "node:crypto";
import axe from "axe-core";
import { HtmlValidate } from "html-validate";
import * as csstree from "css-tree";

const app = express();
const port = Number(process.env.PORT || 3000);
const allowPrivateUrls = process.env.WEBQUEST_ALLOW_PRIVATE_URLS === "true";
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

let browserPromise;
let persistentContextPromise;
let browserUseCount = 0;
let activeAnalyses = 0;
const analysisQueue = [];
const maxConcurrentAnalyses = Math.max(1, Number(process.env.WEBQUEST_MAX_CONCURRENT_ANALYSES || 1));
const maxQueuedAnalyses = Math.max(1, Number(process.env.WEBQUEST_MAX_QUEUED_ANALYSES || 20));
const recycleBrowserAfterUses = Math.max(1, Number(process.env.WEBQUEST_RECYCLE_BROWSER_AFTER_USES || 35));
const recycleBrowserAfterRssMb = Math.max(128, Number(process.env.WEBQUEST_RECYCLE_BROWSER_AFTER_RSS_MB || 420));
const maxColorblindScreenshots = Math.max(1, Number(process.env.WEBQUEST_MAX_COLORBLIND_SCREENSHOTS || 6));
const maxBrokenLinkWorkers = Math.max(1, Number(process.env.WEBQUEST_BROKEN_LINK_WORKERS || 4));
const defaultDomainPages = Math.max(1, Number(process.env.WEBQUEST_DOMAIN_DEFAULT_PAGES || 150));
const maxDomainPages = Math.max(defaultDomainPages, Number(process.env.WEBQUEST_DOMAIN_MAX_PAGES || 20000));
const defaultDomainSeconds = Math.max(5, Number(process.env.WEBQUEST_DOMAIN_DEFAULT_SECONDS || 300));
const maxDomainSeconds = Math.max(defaultDomainSeconds, Number(process.env.WEBQUEST_DOMAIN_MAX_SECONDS || 28800));
const domainJobTtlMs = Math.max(60000, Number(process.env.WEBQUEST_DOMAIN_JOB_TTL_MS || 600000));
const domainJobs = new Map();
const defaultViewport = Object.freeze({ width: 1280, height: 720 });
const crcTable = createCrcTable();

function shouldIgnoreHttpStatus(status, options = {}) {
  return (options.ignore401 && status === 401) || (options.ignore403 && status === 403);
}

const htmlValidator = new HtmlValidate({
  extends: ["html-validate:recommended"],
});

function browserContextOptions(extra = {}) {
  return {
    bypassCSP: true,
    locale: "nb-NO",
    serviceWorkers: "block",
    viewport: { ...defaultViewport },
    userAgent:
      "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
    ...extra,
  };
}

function normalizeViewport(widthValue, heightValue) {
  const width = Number.parseInt(String(widthValue || ""), 10);
  const height = Number.parseInt(String(heightValue || ""), 10);

  return {
    width: Number.isFinite(width) ? Math.min(7680, Math.max(240, width)) : defaultViewport.width,
    height: Number.isFinite(height) ? Math.min(4320, Math.max(200, height)) : defaultViewport.height,
  };
}

async function getBrowser() {
  if (!browserPromise) {
    browserPromise = chromium.launch({
      args: [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-renderer-backgrounding",
        "--disable-extensions",
      ],
    }).catch((error) => {
      browserPromise = null;
      throw error;
    });
  }

  browserUseCount += 1;
  return browserPromise;
}

function currentRssMb() {
  return Math.round(process.memoryUsage().rss / 1024 / 1024);
}

async function closeSharedBrowser(reason = "") {
  if (!browserPromise) {
    return;
  }

  const browser = await browserPromise.catch(() => null);
  browserPromise = null;
  browserUseCount = 0;

  if (browser) {
    await browser.close().catch(() => {});
  }

  if (reason) {
    console.log(`Chromium recycled: ${reason}. RSS ${currentRssMb()} MB.`);
  }
}

async function recycleBrowserIfNeeded() {
  if (!browserPromise || activeAnalyses > 0) {
    return;
  }

  const rss = currentRssMb();

  if (browserUseCount >= recycleBrowserAfterUses) {
    await closeSharedBrowser(`${browserUseCount} uses`);
    return;
  }

  if (rss >= recycleBrowserAfterRssMb) {
    await closeSharedBrowser(`RSS ${rss} MB`);
  }
}

function acquireAnalysisSlot() {
  if (activeAnalyses < maxConcurrentAnalyses) {
    activeAnalyses += 1;
    return Promise.resolve();
  }

  if (analysisQueue.length >= maxQueuedAnalyses) {
    return Promise.reject(new Error("Analyzeren er opptatt. Prøv igjen om litt."));
  }

  return new Promise((resolve) => {
    analysisQueue.push(resolve);
  });
}

function releaseAnalysisSlot() {
  activeAnalyses = Math.max(0, activeAnalyses - 1);

  const next = analysisQueue.shift();

  if (next) {
    activeAnalyses += 1;
    next();
    return;
  }

  recycleBrowserIfNeeded().catch((error) => {
    console.error("Kunne ikke resirkulere Chromium:", error);
  });
}

function normalizeUrl(url) {
  const trimmed = String(url || "").trim();

  if (!trimmed) {
    return "";
  }

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    return trimmed;
  }

  return `https://${trimmed}`;
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    const value = ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
    const ranges = [
      ["10.0.0.0", 8],
      ["127.0.0.0", 8],
      ["169.254.0.0", 16],
      ["172.16.0.0", 12],
      ["192.168.0.0", 16],
      ["0.0.0.0", 8],
    ];

    return ranges.some(([base, bits]) => {
      const baseParts = base.split(".").map(Number);
      const baseValue =
        ((baseParts[0] << 24) >>> 0) +
        (baseParts[1] << 16) +
        (baseParts[2] << 8) +
        baseParts[3];
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return (value & mask) === (baseValue & mask);
    });
  }

  return ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80:");
}

async function validatePublicUrl(url) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    throw new Error("URL-en er ikke gyldig.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("URL-en må starte med http eller https.");
  }

  if (!allowPrivateUrls && parsed.hostname === "localhost") {
    throw new Error("Lokale adresser kan ikke analyseres.");
  }

  if (allowPrivateUrls) {
    return parsed.href;
  }

  const addresses = await dns.lookup(parsed.hostname, { all: true });

  if (addresses.some((entry) => isPrivateIp(entry.address))) {
    throw new Error("Private eller lokale adresser kan ikke analyseres.");
  }

  return parsed.href;
}

function httpStatusText(status, statusText = "") {
  return `${status}${statusText ? ` ${statusText}` : ""}`;
}

function friendlyErrorMessage(error, fallback = "Jeg fikk ikke analysert siden.") {
  const message = String(error?.message || error || "");

  if (/URL-en/i.test(message)) {
    return message;
  }

  if (/ENOTFOUND|getaddrinfo|ERR_NAME_NOT_RESOLVED|Name or service not known/i.test(message)) {
    return "URL-en kan ikke nås. Domenet finnes ikke, eller DNS-oppslag feilet.";
  }

  if (/ETIMEDOUT|timed out|Timeout|ERR_CONNECTION_TIMED_OUT/i.test(message)) {
    return "URL-en kan ikke nås. Siden svarte ikke innen tidsfristen.";
  }

  if (/ECONNREFUSED|ERR_CONNECTION_REFUSED/i.test(message)) {
    return "URL-en kan ikke nås. Serveren avviste tilkoblingen.";
  }

  if (/ECONNRESET|ERR_CONNECTION_RESET/i.test(message)) {
    return "URL-en kan ikke nås. Tilkoblingen ble brutt.";
  }

  if (/ERR_CERT|certificate|SSL|TLS/i.test(message)) {
    return "URL-en kan ikke nås på grunn av sertifikatfeil.";
  }

  if (/ERR_TOO_MANY_REDIRECTS|redirect/i.test(message)) {
    return "URL-en kan ikke nås. Siden videresender for mange ganger.";
  }

  return fallback;
}

async function checkReachableUrl(url) {
  const validatedUrl = await validatePublicUrl(url);
  let lastError = null;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const method = attempt < 3 ? "HEAD" : "GET";

    try {
      let response = await fetch(validatedUrl, {
        method,
        redirect: "follow",
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
        },
      });

      if ([405, 501].includes(response.status) && method === "HEAD") {
        response = await fetch(validatedUrl, {
          method: "GET",
          redirect: "follow",
          signal: controller.signal,
          headers: {
            "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
          },
        });
      }

      if (response.status >= 500 && attempt < 3) {
        await new Promise((resolve) => setTimeout(resolve, 350 * attempt));
        continue;
      }

      if (response.status >= 400) {
        return {
          ok: false,
          url: response.url || validatedUrl,
          status: response.status,
          statusText: response.statusText,
          error: `URL-en kan ikke nås. Serveren svarte ${httpStatusText(response.status, response.statusText)}.`,
        };
      }

      return {
        ok: true,
        url: response.url || validatedUrl,
        status: response.status,
        statusText: response.statusText,
      };
    } catch (error) {
      lastError = error;

      if (attempt < 3) {
        await new Promise((resolve) => setTimeout(resolve, 350 * attempt));
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    ok: false,
    url: validatedUrl,
    error: friendlyErrorMessage(lastError, "URL-en kan ikke nås."),
  };
}

function setCorsHeaders(req, res) {
  const origin = req.get("origin");

  if (!origin) {
    return;
  }

  if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Vary", "Origin");
    res.set("Access-Control-Expose-Headers", "Content-Disposition");
  }
}

async function analyzePage(url, analyzer, options = {}) {
  const viewport = options.viewport || defaultViewport;

  if (process.env.WEBQUEST_USE_PERSISTENT_BROWSER === "true" && !options.forceFreshContext) {
    const context = await getPersistentContext();
    let page;

    try {
      page = await context.newPage();
      await page.setViewportSize(viewport);
      await gotoForAnalysis(page, url, 90000);
      const cookieResult = await handleCookieChoice(page, options);

      if (cookieResult) {
        return cookieResult;
      }

      return await withPageInfo(page, analyzer);
    } catch (error) {
      if (isClosedBrowserError(error)) {
        await resetPersistentContext();
        const retryContext = await getPersistentContext();
        page = await retryContext.newPage();
        await page.setViewportSize(viewport);
        await gotoForAnalysis(page, url, 90000);
        const cookieResult = await handleCookieChoice(page, options);

        if (cookieResult) {
          return cookieResult;
        }

        return await withPageInfo(page, analyzer);
      }

      throw error;
    } finally {
      if (page) {
        await page.close().catch(() => {});
      }
    }
  }

  const browser = await getBrowser();
  const context = await browser.newContext(browserContextOptions({ viewport }));
  const page = await context.newPage();
  let session;

  try {
    await gotoForAnalysis(page, url, 30000);
    const cookieResult = await handleCookieChoice(page, options);

    if (cookieResult) {
      return cookieResult;
    }

    return await withPageInfo(page, analyzer);
  } finally {
    await context.close().catch(() => {});
  }
}

async function handleCookieChoice(page, options = {}) {
  const rawChoice = String(options.cookieChoice || "").trim();
  let choices = [];

  if (rawChoice) {
    try {
      const parsed = JSON.parse(rawChoice);
      choices = Array.isArray(parsed) ? parsed.map((choice) => String(choice || "").trim()).filter(Boolean) : [rawChoice];
    } catch {
      choices = [rawChoice];
    }
  }

  if (!options.cookieFlow && choices.length === 0) {
    return null;
  }

  if (choices.length > 0) {
    const appliedChoices = [];

    for (const choice of choices) {
      if (choice === "__skip__") {
        return null;
      }

      const clickResult = await clickCookieControl(page, choice);

      if (!clickResult?.clicked) {
        const banner = await detectCookieBanner(page);

        if (banner) {
          return {
            ok: true,
            cookieChoiceNeeded: true,
            cookieBanner: {
              ...banner,
              message: `Valget «${choice}» kunne ikke aktiveres. Velg på nytt.`,
              appliedChoices,
            },
            pageInfo: await getPageInfo(page),
          };
        }

        return null;
      }

      appliedChoices.push(clickResult.label || choice);
    }

    const nextBanner = await detectCookieBanner(page);

    if (nextBanner) {
      return {
        ok: true,
        cookieChoiceNeeded: true,
        cookieBanner: {
          ...nextBanner,
          message: "Dialogen er fortsatt åpen. Velg neste kontroll.",
          appliedChoices,
        },
        pageInfo: await getPageInfo(page),
      };
    }

    return null;
  }

  const banner = await detectCookieBanner(page);

  if (!banner) {
    return null;
  }

  return {
    ok: true,
    cookieChoiceNeeded: true,
    cookieBanner: banner,
    pageInfo: await getPageInfo(page),
  };
}

async function detectCookieBanner(page) {
  for (const frame of page.frames()) {
    const result = await frame.evaluate(() => {
    const keywordPattern = /cookie|cookies|informasjonskaps|samtykke|consent|gdpr|usercentrics|onetrust|cookiebot/i;
    const weakKeywordPattern = /personvern|privacy/i;
    const choicePattern = /^(godta|godkjenn|aksepter|accept|allow|agree|tillat|avvis|avslå|decline|reject|deny|ikke godta|ikke tillat|bare nødvendige|kun nødvendige|nødvendige|necessary|essential|lagre|save|bekreft|confirm|fortsett|continue|samtykk|innstillinger|settings|tilpass|administrer|manage|detaljer|details|utvalg|valg)/i;
    const policyPattern = /cookie|cookies|informasjonskaps|samtykke|consent/i;
    const closePattern = /^(lukk|close|dismiss|×|x)$/i;
    const explicitPattern = /cookie|consent|samtykke|gdpr|onetrust|cookiebot|usercentrics|trustarc|didomi|quantcast|coi-banner/i;
    const controlSelector = "button, a[href], input[type='button'], input[type='submit'], input[type='reset'], [role='button'], summary";

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function queryAll(root, selector) {
      const results = Array.from(root.querySelectorAll(selector));
      const elements = Array.from(root.querySelectorAll("*"));

      if (root instanceof Element && root.shadowRoot) {
        results.push(...queryAll(root.shadowRoot, selector));
      }

      elements.forEach((element) => {
        if (element.shadowRoot) {
          results.push(...queryAll(element.shadowRoot, selector));
        }
      });

      return results;
    }

    function visible(element) {
      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);

      return rect.width > 0 &&
        rect.height > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number.parseFloat(style.opacity || "1") > 0.05;
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 4; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function controlName(element) {
      const ariaLabelledby = element.getAttribute("aria-labelledby");
      const labelledText = ariaLabelledby
        ? ariaLabelledby.split(/\s+/)
            .map((id) => normalized(document.getElementById(id)?.innerText || document.getElementById(id)?.textContent))
            .filter(Boolean)
            .join(" ")
        : "";

      return normalized(
        element.getAttribute("aria-label") ||
        labelledText ||
        element.value ||
        element.innerText ||
        element.textContent ||
        element.title ||
        element.getAttribute("name")
      );
    }

    function isLikelyPageChrome(element, rect, style) {
      const tag = element.tagName.toLowerCase();

      if (["header", "footer", "main", "nav"].includes(tag)) {
        return true;
      }

      if (element.closest("header, footer, main, nav")) {
        return true;
      }

      if (style.position === "static" && rect.top > window.innerHeight * 0.75) {
        return true;
      }

      return false;
    }

    function cookieControlKind(control) {
      const label = control.label.toLowerCase();

      if (choicePattern.test(label)) return "action";
      if (closePattern.test(label)) return "close";
      if (policyPattern.test(label)) return "policy";
      return "";
    }

    function isLikelyCookieControl(control) {
      return Boolean(cookieControlKind(control));
    }

    const candidates = queryAll(document,
      "[role='dialog'], [aria-modal='true'], dialog, aside, section, div, form"
    )
      .filter(visible)
      .map((element) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        const text = normalized(element.innerText || element.textContent);
        const allControls = queryAll(element, controlSelector)
          .filter((control) => visible(control))
          .map((control) => ({
            label: controlName(control),
            selector: selectorFor(control),
            element: control.tagName.toLowerCase(),
          }))
          .filter((control) =>
            control.label &&
            !/cookiebot av|powered by|åpner i et nytt vindu|opens in a new window/i.test(control.label) &&
            !/^(cookie information|onetrust|cookiebot|usercentrics|didomi|trustarc)$/i.test(control.label)
          );
        const controls = allControls
          .filter(isLikelyCookieControl)
          .map((control) => ({
            ...control,
            kind: cookieControlKind(control),
          }))
          .slice(0, 10);
        const fixed = ["fixed", "sticky"].includes(style.position);
        const modal = element.getAttribute("role") === "dialog" ||
          element.getAttribute("aria-modal") === "true" ||
          element.tagName.toLowerCase() === "dialog";
        const nearViewportEdge = rect.top < 80 ||
          rect.bottom > window.innerHeight - 80 ||
          rect.left < 40 ||
          rect.right > window.innerWidth - 40;
        const largeOverlay = rect.width >= window.innerWidth * 0.45 &&
          rect.height >= 80 &&
          rect.top < window.innerHeight &&
          nearViewportEdge;
        const hasStrongKeyword = keywordPattern.test(text);
        const hasWeakKeyword = weakKeywordPattern.test(text);
        const likelyControls = controls.filter(isLikelyCookieControl);
        const actionControls = controls.filter((control) => control.kind === "action");
        const pageChrome = isLikelyPageChrome(element, rect, style);
        const explicit = explicitPattern.test([
          element.id,
          element.className,
          element.getAttribute("aria-label"),
          element.getAttribute("data-testid"),
        ].map(normalized).join(" "));
        const unrelatedControls = Math.max(0, allControls.length - controls.length);
        const score =
          (hasStrongKeyword ? 4 : 0) +
          (!hasStrongKeyword && hasWeakKeyword ? 1 : 0) +
          (actionControls.length ? 4 : 0) +
          (controls.length ? 2 : 0) +
          (fixed ? 2 : 0) +
          (modal ? 2 : 0) +
          (explicit ? 5 : 0) +
          (largeOverlay ? 1 : 0) -
          (pageChrome ? 6 : 0) -
          Math.min(8, Math.floor(unrelatedControls / 3)) -
          (text.length > 4000 ? 8 : text.length > 1800 ? 4 : 0);

        return { element, text, controls, likelyControls, actionControls, score, fixed, modal, explicit, largeOverlay, pageChrome, rect };
      })
      .filter((candidate) =>
        candidate.score >= 8 &&
        candidate.controls.length > 0 &&
        candidate.actionControls.length > 0 &&
        (!candidate.pageChrome || candidate.modal || candidate.fixed || candidate.explicit) &&
        (candidate.modal || candidate.fixed || candidate.explicit || candidate.largeOverlay)
      )
      .sort((a, b) =>
        b.score - a.score ||
        (a.rect.width * a.rect.height) - (b.rect.width * b.rect.height) ||
        a.text.length - b.text.length
      );

    const best = candidates[0];

    if (!best) {
      return null;
    }

    return {
      textStart: best.text.slice(0, 300),
      selector: selectorFor(best.element),
      controls: best.controls.map((control, index) => ({
        index: index + 1,
        label: control.label,
        selector: control.selector,
        element: control.element,
      })),
    };
    }).catch(() => null);

    if (result) {
      return {
        ...result,
        frameUrl: frame === page.mainFrame() ? "" : frame.url(),
      };
    }
  }

  return null;
}

async function clickCookieControl(page, choice) {
  let clickResult = { clicked: false };

  for (const frame of page.frames()) {
    clickResult = await frame.evaluate(async (rawChoice) => {
    const keywordPattern = /cookie|cookies|informasjonskaps|samtykke|consent|gdpr|usercentrics|onetrust|cookiebot/i;
    const weakKeywordPattern = /personvern|privacy/i;
    const choicePattern = /^(godta|godkjenn|aksepter|accept|allow|agree|tillat|avvis|avslå|decline|reject|deny|ikke godta|ikke tillat|bare nødvendige|kun nødvendige|nødvendige|necessary|essential|lagre|save|bekreft|confirm|fortsett|continue|samtykk|innstillinger|settings|tilpass|administrer|manage|detaljer|details|utvalg|valg)/i;
    const policyPattern = /cookie|cookies|informasjonskaps|samtykke|consent/i;
    const closePattern = /^(lukk|close|dismiss|×|x)$/i;
    const explicitPattern = /cookie|consent|samtykke|gdpr|onetrust|cookiebot|usercentrics|trustarc|didomi|quantcast|coi-banner/i;
    const controlSelector = "button, a[href], input[type='button'], input[type='submit'], input[type='reset'], [role='button'], summary";
    const normalizedChoice = String(rawChoice || "").replace(/\s+/g, " ").trim().toLowerCase();

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function queryAll(root, selector) {
      const results = Array.from(root.querySelectorAll(selector));
      const elements = Array.from(root.querySelectorAll("*"));

      if (root instanceof Element && root.shadowRoot) {
        results.push(...queryAll(root.shadowRoot, selector));
      }

      elements.forEach((element) => {
        if (element.shadowRoot) {
          results.push(...queryAll(element.shadowRoot, selector));
        }
      });

      return results;
    }

    function visible(element) {
      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);

      return rect.width > 0 &&
        rect.height > 0 &&
        style.display !== "none" &&
        style.visibility !== "hidden" &&
        Number.parseFloat(style.opacity || "1") > 0.05;
    }

    function controlName(element) {
      const ariaLabelledby = element.getAttribute("aria-labelledby");
      const labelledText = ariaLabelledby
        ? ariaLabelledby.split(/\s+/)
            .map((id) => normalized(document.getElementById(id)?.innerText || document.getElementById(id)?.textContent))
            .filter(Boolean)
            .join(" ")
        : "";

      return normalized(
        element.getAttribute("aria-label") ||
        labelledText ||
        element.value ||
        element.innerText ||
        element.textContent ||
        element.title ||
        element.getAttribute("name")
      );
    }

    function isLikelyPageChrome(element, rect, style) {
      const tag = element.tagName.toLowerCase();

      if (["header", "footer", "main", "nav"].includes(tag)) {
        return true;
      }

      if (element.closest("header, footer, main, nav")) {
        return true;
      }

      if (style.position === "static" && rect.top > window.innerHeight * 0.75) {
        return true;
      }

      return false;
    }

    function isLikelyCookieControl(label) {
      return choicePattern.test(label) ||
        policyPattern.test(label) ||
        closePattern.test(label);
    }

    const containers = queryAll(document,
      "[role='dialog'], [aria-modal='true'], dialog, aside, section, div, form"
    )
      .filter(visible)
      .filter((element) => {
        const rect = element.getBoundingClientRect();
        const style = window.getComputedStyle(element);
        const text = normalized(element.innerText || element.textContent);
        const controls = queryAll(element, controlSelector)
          .filter(visible)
          .map(controlName)
          .filter(Boolean);
        const fixed = ["fixed", "sticky"].includes(style.position);
        const modal = element.getAttribute("role") === "dialog" ||
          element.getAttribute("aria-modal") === "true" ||
          element.tagName.toLowerCase() === "dialog";
        const nearViewportEdge = rect.top < 80 ||
          rect.bottom > window.innerHeight - 80 ||
          rect.left < 40 ||
          rect.right > window.innerWidth - 40;
        const largeOverlay = rect.width >= window.innerWidth * 0.45 &&
          rect.height >= 80 &&
          rect.top < window.innerHeight &&
          nearViewportEdge;
        const hasStrongKeyword = keywordPattern.test(text);
        const hasWeakKeyword = weakKeywordPattern.test(text);
        const explicit = explicitPattern.test([
          element.id,
          element.className,
          element.getAttribute("aria-label"),
          element.getAttribute("data-testid"),
        ].map(normalized).join(" "));

        return (!isLikelyPageChrome(element, rect, style) || modal || fixed || explicit) &&
          (modal || fixed || explicit || largeOverlay) &&
          (hasStrongKeyword || hasWeakKeyword) &&
          controls.some((label) => isLikelyCookieControl(label.toLowerCase()));
      })
      .sort((a, b) => {
        const aRect = a.getBoundingClientRect();
        const bRect = b.getBoundingClientRect();
        return (aRect.width * aRect.height) - (bRect.width * bRect.height);
      });
    const seenControls = new Set();
    const controls = containers
      .flatMap((container) => queryAll(container, controlSelector))
      .filter(visible)
      .map((element) => ({
        element,
        label: controlName(element),
      }))
      .filter((control) => {
        if (
          !control.label ||
          !isLikelyCookieControl(control.label.toLowerCase()) ||
          /cookiebot av|powered by|åpner i et nytt vindu|opens in a new window/i.test(control.label) ||
          /^(cookie information|onetrust|cookiebot|usercentrics|didomi|trustarc)$/i.test(control.label) ||
          seenControls.has(control.element)
        ) {
          return false;
        }

        seenControls.add(control.element);
        return true;
      })
      .map((control, index) => ({
        ...control,
        index: index + 1,
      }));
    const numericChoice = Number.parseInt(normalizedChoice, 10);
    const exact = controls.find((control) => control.index === numericChoice) ||
      controls.find((control) => control.label.toLowerCase() === normalizedChoice) ||
      controls.find((control) => control.label.toLowerCase().includes(normalizedChoice));

    if (!exact) {
      return { clicked: false };
    }

    exact.element.click();
    await new Promise((resolve) => setTimeout(resolve, 800));
    return { clicked: true, label: exact.label };
    }, choice).catch(() => ({ clicked: false }));

    if (clickResult.clicked) {
      break;
    }
  }

  if (clickResult.clicked) {
    await page.waitForLoadState("networkidle", { timeout: 3000 }).catch(() => {});
    await page.waitForTimeout(500);
  }

  return clickResult;
}

async function withPageInfo(page, analyzer) {
  const result = await analyzer(page);

  if (result && typeof result === "object" && !Array.isArray(result)) {
    return {
      ...result,
      pageInfo: await getPageInfo(page),
    };
  }

  return result;
}

async function getPageInfo(page) {
  return page.evaluate(() => {
    const text = String(document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 300);

    return {
      title: document.title || "",
      finalUrl: location.href,
      bodyTextStart: text,
      headingCount: document.querySelectorAll("h1, h2, h3, h4, h5, h6").length,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
    };
  }).catch(() => ({
    title: "",
    finalUrl: page.url(),
    bodyTextStart: "",
    headingCount: 0,
  }));
}

async function gotoForAnalysis(page, url, timeout) {
  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout,
  });

  if (response && response.status() >= 400) {
    throw new Error(`URL-en kan ikke nås. Serveren svarte ${httpStatusText(response.status(), response.statusText())}.`);
  }

  await page.waitForLoadState("load", { timeout: Math.min(timeout, 15000) }).catch(() => {});
  await page.waitForTimeout(1200);
  await waitForAutomaticLogin(page, url, timeout);
}

async function waitForAutomaticLogin(page, originalUrl, timeout) {
  const originalHost = new URL(originalUrl).hostname;
  const loginPattern = /login\.microsoftonline\.com|login\.windows\.net|oauth2|authorize/i;
  const currentUrl = page.url();
  const title = await page.title().catch(() => "");

  if (!loginPattern.test(currentUrl) && !/logg på|sign in|sign-in/i.test(title)) {
    return;
  }

  await page.waitForURL((nextUrl) => {
    try {
      const parsed = new URL(String(nextUrl));
      return parsed.hostname === originalHost || parsed.hostname.endsWith(`.${originalHost}`);
    } catch {
      return false;
    }
  }, { timeout: Math.min(timeout, 45000) }).catch(() => {});

  await page.waitForLoadState("domcontentloaded", { timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(2000);
}

function isClosedBrowserError(error) {
  const message = String(error && error.message ? error.message : error || "");
  return /Target page, context or browser has been closed|Browser has been closed|Context closed/i.test(message);
}

async function getPersistentContext() {
  if (!persistentContextPromise) {
    const options = browserContextOptions({
      headless: false,
    });
    const browserChannel = process.env.WEBQUEST_BROWSER_CHANNEL;

    if (browserChannel) {
      options.channel = browserChannel;
    }

    persistentContextPromise = chromium.launchPersistentContext(
      process.env.WEBQUEST_BROWSER_PROFILE || "./webquest-browser-profile",
      options
    );
  }

  return persistentContextPromise;
}

async function resetPersistentContext() {
  if (!persistentContextPromise) {
    return;
  }

  try {
    const context = await persistentContextPromise;
    await context.close();
  } catch {
  } finally {
    persistentContextPromise = null;
  }
}

function extractResponseText(data) {
  if (typeof data.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }

  return (data.output || [])
    .flatMap((item) => item.content || [])
    .filter((content) => content.type === "output_text" && content.text)
    .map((content) => content.text)
    .join("\n")
    .trim();
}

async function renderImageAsDataUrl(imageUrl) {
  const browser = await getBrowser();
  const context = await browser.newContext(browserContextOptions({
    viewport: { width: 1400, height: 1000 },
  }));
  const page = await context.newPage();

  try {
    await page.setContent(
      `<!doctype html>
      <html lang="no">
        <head>
          <meta charset="utf-8">
          <style>
            html, body { margin: 0; padding: 24px; background: #fff; }
            img { display: block; max-width: 1200px; max-height: 900px; width: auto; height: auto; }
          </style>
        </head>
        <body>
          <img id="webquest-image" alt="" src="${imageUrl.replace(/"/g, "&quot;")}">
        </body>
      </html>`,
      { waitUntil: "domcontentloaded" }
    );

    await page.evaluate(() =>
      new Promise((resolve, reject) => {
        const image = document.getElementById("webquest-image");

        if (!image) {
          reject(new Error("Fant ikke bildet."));
          return;
        }

        if (image.complete && image.naturalWidth > 0) {
          resolve();
          return;
        }

        image.addEventListener("load", () => resolve(), { once: true });
        image.addEventListener("error", () => reject(new Error("Bildet kunne ikke lastes.")), { once: true });
        window.setTimeout(() => reject(new Error("Bildet brukte for lang tid på å laste.")), 15000);
      })
    );

    const image = page.locator("#webquest-image");
    const buffer = await image.screenshot({ type: "png" });
    return `data:image/png;base64,${buffer.toString("base64")}`;
  } finally {
    await context.close().catch(() => {});
  }
}

async function describeImage(url) {
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    throw new Error("OPENAI_API_KEY mangler på serveren.");
  }

  const imageDataUrl = await renderImageAsDataUrl(url);
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: process.env.OPENAI_VISION_MODEL || "gpt-4.1-mini",
      input: [
        {
          role: "user",
          content: [
            {
              type: "input_text",
              text:
                "Beskriv selve bildet på norsk. Ikke vurder om bildet trenger alt-tekst. " +
                "Beskriv motiv, synlig tekst, layout, farger, stil og bakgrunn. " +
                "Hvis bildet er en logo eller et ikon, beskriv formen og teksten konkret.",
            },
            {
              type: "input_image",
              image_url: imageDataUrl,
              detail: "high",
            },
          ],
        },
      ],
      max_output_tokens: 500,
    }),
  });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error?.message || "Bildet kunne ikke beskrives.");
  }

  const description = extractResponseText(data);

  if (!description) {
    throw new Error("Bildet ble analysert, men svaret manglet beskrivelse.");
  }

  return {
    ok: true,
    engine: "openai",
    url,
    description,
  };
}

async function getHeadings(page) {
  await page.waitForSelector("h1, h2, h3, h4, h5, h6", { timeout: 10000 }).catch(() => {});

  return page.locator("h1, h2, h3, h4, h5, h6").evaluateAll((headings) =>
    headings
      .map((heading) => {
        function hasHiddenAncestor(element) {
          for (let node = element; node; node = node.parentElement) {
            const style = window.getComputedStyle(node);

            if (
              node.hasAttribute("hidden") ||
              node.getAttribute("type") === "hidden" ||
              style.display === "none" ||
              style.visibility === "hidden" ||
              style.visibility === "collapse" ||
              style.contentVisibility === "hidden"
            ) {
              return true;
            }
          }

          return false;
        }

        function hasAriaHiddenAncestor(element) {
          for (let node = element; node; node = node.parentElement) {
            if (node.getAttribute("aria-hidden") === "true") {
              return true;
            }
          }

          return false;
        }

        if (hasHiddenAncestor(heading)) {
          return null;
        }

        return {
          level: Number(heading.tagName.slice(1)),
          text:
            heading.getAttribute("aria-label") ||
            heading.innerText.replace(/\s+/g, " ").trim() ||
            heading.textContent.replace(/\s+/g, " ").trim() ||
            "(tom overskrift)",
          ariaHidden: hasAriaHiddenAncestor(heading),
        };
      })
      .filter(Boolean)
  );
}

async function getLanguage(page) {
  return page.evaluate(() => document.documentElement.getAttribute("lang")?.trim() || "");
}

function collectAccessibilityData(mode) {
  function normalized(text) {
    return String(text || "").replace(/\s+/g, " ").trim();
  }

  function isHidden(element, options = {}) {
    if (!element || !(element instanceof Element) || options.allowHidden) {
      return false;
    }

    if (element.tagName.toLowerCase() === "input" && element.type === "hidden") {
      return true;
    }

    for (let node = element; node; node = node.parentElement) {
      const style = window.getComputedStyle(node);

      if (
        node.hasAttribute("hidden") ||
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.visibility === "collapse" ||
        style.contentVisibility === "hidden"
      ) {
        return true;
      }
    }

    return false;
  }

  function selectorFor(element) {
    if (element.id) {
      return `#${CSS.escape(element.id)}`;
    }

    const parts = [];

    for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
      const tag = node.tagName.toLowerCase();
      const parent = node.parentElement;

      if (!parent) {
        parts.unshift(tag);
        break;
      }

      const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
      const index = sameTag.indexOf(node) + 1;
      parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
    }

    return parts.join(" > ");
  }

  function textFromSubtree(node, options = {}) {
    if (!node) {
      return "";
    }

    if (node.nodeType === Node.TEXT_NODE) {
      return normalized(node.textContent);
    }

    if (!(node instanceof Element) || isHidden(node, options) || node.getAttribute("aria-hidden") === "true") {
      return "";
    }

    const name = accessibleName(node, { ...options, fromContent: true });

    if (name.value) {
      return name.value;
    }

    return normalized(Array.from(node.childNodes).map((child) => textFromSubtree(child, options)).join(" "));
  }

  function labelText(element) {
    const labels = element.labels ? Array.from(element.labels) : [];

    if (!labels.length && element.id) {
      labels.push(...document.querySelectorAll(`label[for="${CSS.escape(element.id)}"]`));
    }

    return normalized(labels.map((label) => textFromSubtree(label, { allowHidden: true })).join(" "));
  }

  function svgTitle(element) {
    const title = Array.from(element.children).find((child) => child.tagName.toLowerCase() === "title");
    return title ? normalized(title.textContent) : "";
  }

  function nativeName(element) {
    const tag = element.tagName.toLowerCase();
    const type = (element.getAttribute("type") || "").toLowerCase();

    if (["img", "area"].includes(tag) || (tag === "input" && type === "image")) {
      if (element.hasAttribute("alt")) {
        return { value: normalized(element.getAttribute("alt")), source: "alt" };
      }
    }

    if (["input", "select", "textarea", "output", "meter", "progress"].includes(tag)) {
      const text = labelText(element);

      if (text) {
        return { value: text, source: "label" };
      }
    }

    if (tag === "input" && ["button", "submit", "reset"].includes(type)) {
      const value = normalized(element.getAttribute("value"));

      if (value) {
        return { value, source: "value" };
      }
    }

    if (tag === "svg") {
      const title = svgTitle(element);

      if (title) {
        return { value: title, source: "svg title" };
      }
    }

    if (tag === "iframe" && element.hasAttribute("title")) {
      return { value: normalized(element.getAttribute("title")), source: "title" };
    }

    return null;
  }

  function canNameFromContent(element) {
    const tag = element.tagName.toLowerCase();
    const role = normalized(element.getAttribute("role")).toLowerCase();

    return ["a", "button", "summary", "option", "legend", "label"].includes(tag) ||
      ["button", "link", "menuitem", "option", "tab", "treeitem"].includes(role);
  }

  function accessibleName(element, options = {}) {
    if (!(element instanceof Element) || isHidden(element, options)) {
      return { value: "", source: "ingen" };
    }

    const labelledBy = normalized(element.getAttribute("aria-labelledby"));

    if (!options.fromLabelledBy && labelledBy) {
      const value = normalized(labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((reference) => accessibleName(reference, { allowHidden: true, fromLabelledBy: true }).value ||
          textFromSubtree(reference, { allowHidden: true }))
        .join(" "));

      if (value) {
        return { value, source: "aria-labelledby" };
      }
    }

    const ariaLabel = normalized(element.getAttribute("aria-label"));

    if (!options.fromContent && ariaLabel) {
      return { value: ariaLabel, source: "aria-label" };
    }

    const native = nativeName(element);

    if (native) {
      return native;
    }

    if (options.fromContent || canNameFromContent(element)) {
      const value = normalized(Array.from(element.childNodes).map((child) => textFromSubtree(child, options)).join(" "));

      if (value) {
        return { value, source: "innhold" };
      }
    }

    const title = normalized(element.getAttribute("title"));

    if (title) {
      return { value: title, source: "title" };
    }

    return { value: "", source: "ingen" };
  }

  function fieldType(element) {
    const tagName = element.tagName.toLowerCase();

    if (tagName === "input") {
      return element.getAttribute("type") || "text";
    }

    return tagName;
  }

  function fieldValue(element) {
    const tagName = element.tagName.toLowerCase();
    const type = fieldType(element);

    if (type === "password") {
      return "(skjult)";
    }

    if (type === "checkbox" || type === "radio") {
      const value = element.getAttribute("value") || "";
      return `${value}${element.checked ? " (valgt)" : " (ikke valgt)"}`;
    }

    if (tagName === "select") {
      return Array.from(element.selectedOptions)
        .map((option) => normalized(option.textContent) || option.value)
        .join(", ");
    }

    if (tagName === "button") {
      return element.getAttribute("value") || "";
    }

    return element.value || element.getAttribute("value") || "";
  }

  function fieldInfo(element) {
    const tagName = element.tagName.toLowerCase();
    const kind =
      tagName === "button" ||
      ["button", "submit", "reset", "image"].includes((element.getAttribute("type") || "").toLowerCase())
        ? "button"
        : "field";
    const name = accessibleName(element);

    return {
      kind,
      type: fieldType(element),
      value: fieldValue(element),
      name: name.value,
      nameSource: name.source,
    };
  }

  function firstLegend(fieldset) {
    const legend = Array.from(fieldset.children).find(
      (child) => child.tagName && child.tagName.toLowerCase() === "legend"
    );

    return legend ? normalized(legend.innerText || legend.textContent) : "";
  }

  if (mode === "fields") {
    const fieldSelector = "input, textarea, select, button";
    const groups = [];
    const groupedFields = new Set();
    const fieldsets = Array.from(document.querySelectorAll("fieldset")).filter((fieldset) => !isHidden(fieldset));

    fieldsets.forEach((fieldset) => {
      const fields = Array.from(fieldset.querySelectorAll(fieldSelector)).filter(
        (field) => field.closest("fieldset") === fieldset && !isHidden(field)
      );

      fields.forEach((field) => groupedFields.add(field));

      groups.push({
        type: "fieldset",
        legend: firstLegend(fieldset),
        fields: fields.map(fieldInfo),
      });
    });

    const ungroupedFields = Array.from(document.querySelectorAll(fieldSelector)).filter(
      (field) => !groupedFields.has(field) && !field.closest("fieldset") && !isHidden(field)
    );

    if (ungroupedFields.length > 0) {
      groups.unshift({
        type: "ungrouped",
        fields: ungroupedFields.map(fieldInfo),
      });
    }

    return groups;
  }

  if (mode === "links") {
    const links = Array.from(document.querySelectorAll("a[href]")).map((link) => {
      const name = accessibleName(link);

      return {
        name: name.value,
        nameSource: name.source,
        href: link.href,
        newWindow: link.target === "_blank",
        selector: selectorFor(link),
      };
    });
    const issues = [];
    const byText = new Map();
    const byHref = new Map();

    links.forEach((link) => {
      if (!link.name) {
        issues.push(`Lenke mangler tekst: ${link.href}`);
      }

      if (link.newWindow && !/nytt|new/i.test(link.name)) {
        issues.push(`Lenke åpnes i nytt vindu uten at teksten sier det: ${link.name || link.href}`);
      }

      const textKey = link.name.toLowerCase();
      const hrefKey = link.href;

      if (textKey) {
        if (!byText.has(textKey)) {
          byText.set(textKey, new Set());
        }

        byText.get(textKey).add(hrefKey);
      }

      if (!byHref.has(hrefKey)) {
        byHref.set(hrefKey, new Set());
      }

      if (textKey) {
        byHref.get(hrefKey).add(link.name);
      }
    });

    byText.forEach((hrefs, text) => {
      if (hrefs.size > 1) {
        issues.push(`Samme lenketekst går til ulike URL-er: ${text}`);
      }
    });

    byHref.forEach((texts, href) => {
      if (texts.size > 1) {
        issues.push(`Samme URL har ulike lenketekster: ${href}`);
      }
    });

    return { links, issues };
  }

  if (mode === "emails") {
    const emailPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
    const emailTestPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
    const seen = new Set();
    const emails = [];

    function cleanEmail(value) {
      const cleaned = normalized(String(value || "")
        .replace(/^mailto:/i, "")
        .split("?")[0]
        .replace(/[<>()\[\],;:]+$/g, ""));

      try {
        return decodeURIComponent(cleaned);
      } catch {
        return cleaned;
      }
    }

    function addEmail(item) {
      const email = cleanEmail(item.email);

      if (!email || !emailPattern.test(email)) {
        emailPattern.lastIndex = 0;
        return;
      }

      emailPattern.lastIndex = 0;
      const key = `${email.toLowerCase()}|${item.source}|${item.selector || ""}`;

      if (seen.has(key)) {
        return;
      }

      seen.add(key);
      emails.push({
        ...item,
        email,
      });
    }

    Array.from(document.querySelectorAll("a[href^='mailto:'], a[href^='MAILTO:']")).forEach((link) => {
      const name = accessibleName(link);
      const href = link.getAttribute("href") || "";
      const addresses = cleanEmail(href).split(/[;,]/).map(cleanEmail).filter(Boolean);

      addresses.forEach((email) => {
        addEmail({
          source: "mailto",
          linkText: name.value,
          nameSource: name.source,
          email,
          href,
          selector: selectorFor(link),
        });
      });
    });

    const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;

        if (!parent || isHidden(parent) || parent.closest("script, style, noscript, textarea, input, a[href^='mailto:'], a[href^='MAILTO:']")) {
          return NodeFilter.FILTER_REJECT;
        }

      return emailTestPattern.test(node.textContent || "")
          ? NodeFilter.FILTER_ACCEPT
          : NodeFilter.FILTER_REJECT;
      },
    });

    while (walker.nextNode()) {
      const node = walker.currentNode;
      const parent = node.parentElement;
      const text = node.textContent || "";
      const matches = text.match(emailPattern) || [];

      matches.forEach((email) => {
        addEmail({
          source: "tekst",
          linkText: "",
          nameSource: "",
          email,
          href: "",
          selector: selectorFor(parent),
        });
      });
    }

    return { emails };
  }

  if (mode === "images") {
    function svgPreviewDataUrl(element) {
      if (element.tagName.toLowerCase() !== "svg") {
        return "";
      }

      try {
        const svg = element.outerHTML;
        const encoded = window.btoa(unescape(encodeURIComponent(svg)));
        return `data:image/svg+xml;base64,${encoded}`;
      } catch {
        return "";
      }
    }

    function backgroundImageUrls(element) {
      const style = window.getComputedStyle(element);
      const value = style.backgroundImage || "";
      const urls = [];
      const pattern = /url\((['"]?)(.*?)\1\)/g;
      let match;

      while ((match = pattern.exec(value)) !== null) {
        const rawUrl = normalized(match[2]);

        if (!rawUrl) {
          continue;
        }

        try {
          urls.push(new URL(rawUrl, document.baseURI).href);
        } catch {
          urls.push(rawUrl);
        }
      }

      return urls;
    }

    const htmlImages = Array.from(document.querySelectorAll("img, svg, input[type='image'], area")).map((image) => {
      const tagName = image.tagName.toLowerCase();
      const name = accessibleName(image);
      const owner = image.closest("a[href], button, [role='link'], [role='button']");
      const ownerName = owner ? accessibleName(owner) : { value: "", source: "ingen" };
      const hasAlt = image.hasAttribute("alt");
      const alt = image.getAttribute("alt") || "";
      const role = normalized(image.getAttribute("role"));
      const ariaHidden = image.closest("[aria-hidden='true']") !== null;
      const isDecorative = ariaHidden || role === "presentation" || role === "none" || (hasAlt && alt === "");
      let altStatus = "mangler alt";

      if (hasAlt && alt === "") {
        altStatus = "tom alt";
      } else if (hasAlt) {
        altStatus = alt;
      } else if (tagName === "svg") {
        altStatus = svgTitle(image) || "mangler tekstalternativ";
      }

      const src = image.currentSrc || image.src || image.href?.baseVal || image.getAttribute("href") || "";

      return {
        altStatus,
        elementType: tagName,
        name: name.value,
        nameSource: name.source,
        ownerName: ownerName.value,
        ownerNameSource: ownerName.source,
        ownerRole: owner ? owner.tagName.toLowerCase() : "",
        src,
        previewSrc: src || svgPreviewDataUrl(image),
        role,
        ariaHidden,
        isDecorative,
        selector: selectorFor(image),
      };
    });

    const cssBackgroundImages = Array.from(document.querySelectorAll("body *"))
      .filter((element) => !isHidden(element))
      .flatMap((element) => {
        const rect = element.getBoundingClientRect();

        if (rect.width < 1 || rect.height < 1) {
          return [];
        }

        return backgroundImageUrls(element).map((src) => ({
          altStatus: "CSS-bakgrunnsbilde",
          elementType: "css-background",
          name: "",
          nameSource: "CSS background-image",
          ownerName: "",
          ownerNameSource: "",
          ownerRole: "",
          src,
          previewSrc: src,
          role: normalized(element.getAttribute("role")),
          ariaHidden: element.closest("[aria-hidden='true']") !== null,
          isDecorative: true,
          selector: selectorFor(element),
        }));
      });

    return [...htmlImages, ...cssBackgroundImages];
  }

  if (mode === "landmarks") {
    const landmarkRoles = new Set(["banner", "navigation", "main", "complementary", "contentinfo", "search", "form", "region"]);
    const selector = "header, nav, main, aside, footer, form, section, [role]";
    const landmarkSelector = "header, nav, main, aside, footer, form[aria-label], form[aria-labelledby], form[role='form'], section[aria-label], section[aria-labelledby], [role='banner'], [role='navigation'], [role='main'], [role='complementary'], [role='contentinfo'], [role='search'], [role='form'], [role='region']";
    const contentSelector = [
      "a[href]",
      "button",
      "input:not([type='hidden'])",
      "select",
      "textarea",
      "summary",
      "details",
      "h1",
      "h2",
      "h3",
      "h4",
      "h5",
      "h6",
      "p",
      "li",
      "table",
      "blockquote",
      "figure",
      "[tabindex]",
      "[contenteditable='true']",
    ].join(",");

    function roleFor(element) {
      const explicitRole = normalized(element.getAttribute("role"));

      if (landmarkRoles.has(explicitRole)) {
        return explicitRole;
      }

      const tag = element.tagName.toLowerCase();

      if (tag === "header") return "banner";
      if (tag === "nav") return "navigation";
      if (tag === "main") return "main";
      if (tag === "aside") return "complementary";
      if (tag === "footer") return "contentinfo";
      if (tag === "form" && accessibleName(element).value) return "form";
      if (tag === "section" && accessibleName(element).value) return "region";

      return "";
    }

    function isHiddenForLandmarkCheck(element) {
      if (!(element instanceof Element)) {
        return true;
      }

      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          node.getAttribute("aria-hidden") === "true" ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          style.contentVisibility === "hidden"
        ) {
          return true;
        }
      }

      return false;
    }

    function isFocusable(element) {
      return !element.disabled && element.tabIndex >= 0 && element.matches(
        "a[href], button, input, select, textarea, summary, [tabindex], [contenteditable='true']"
      );
    }

    function contentLabel(element) {
      const tag = element.tagName.toLowerCase();
      const name = accessibleName(element).value;
      const text = normalized(element.innerText || element.textContent);
      const value = name || text;

      if (!value) {
        return tag;
      }

      return `${tag}: ${value.slice(0, 100)}`;
    }

    function outsideLandmarkItems() {
      const items = [];
      const seenContainers = new Set();

      Array.from(document.querySelectorAll(contentSelector)).forEach((element) => {
        if (isHiddenForLandmarkCheck(element) || element.closest(landmarkSelector)) {
          return;
        }

        const text = normalized(element.innerText || element.textContent);

        if (!text && !isFocusable(element) && !["table", "figure"].includes(element.tagName.toLowerCase())) {
          return;
        }

        const container = element.closest("body > *, #root > *, #__next > *") || element;
        const keyElement = isFocusable(element) ? element : container;

        if (!isFocusable(element) && seenContainers.has(keyElement)) {
          return;
        }

        seenContainers.add(keyElement);
        items.push({
          type: element.tagName.toLowerCase(),
          label: contentLabel(element),
          focusable: isFocusable(element),
          selector: selectorFor(element),
        });
      });

      return items.slice(0, 25);
    }

    const landmarks = Array.from(document.querySelectorAll(selector))
      .map((element) => {
        const name = accessibleName(element);

        return {
          role: roleFor(element),
          name: name.value,
          nameSource: name.source,
          selector: selectorFor(element),
        };
      })
      .filter((landmark) => landmark.role);
    const issues = [];
    const mains = landmarks.filter((landmark) => landmark.role === "main");
    const navs = landmarks.filter((landmark) => landmark.role === "navigation");

    if (mains.length === 0) {
      issues.push("main mangler.");
    }

    if (mains.length > 1) {
      issues.push("Det finnes flere main-landemerker.");
    }

    if (navs.length > 1 && navs.some((nav) => !nav.name)) {
      issues.push("Flere navigasjonslandemerker finnes, og minst ett mangler navn.");
    }

    const outsideItems = outsideLandmarkItems();

    if (outsideItems.length > 0) {
      issues.push(`${outsideItems.length} synlige innholdselementer ligger utenfor landemerker.`);
    }

    return { landmarks, issues, outsideItems };
  }

  if (mode === "focus") {
    const selector = [
      "a[href]",
      "button",
      "input:not([type='hidden'])",
      "select",
      "textarea",
      "[tabindex]",
      "[contenteditable='true']",
    ].join(",");

    return Array.from(document.querySelectorAll(selector))
      .filter((element) => !element.disabled && element.tabIndex >= 0 && !isHidden(element))
      .sort((a, b) => {
        const aTab = a.tabIndex === 0 ? Number.MAX_SAFE_INTEGER : a.tabIndex;
        const bTab = b.tabIndex === 0 ? Number.MAX_SAFE_INTEGER : b.tabIndex;
        return aTab - bTab;
      })
      .map((element) => {
        const name = accessibleName(element);

        return {
          type: element.tagName.toLowerCase(),
          name: name.value,
          nameSource: name.source,
          text: normalized(element.innerText || element.textContent),
          tabindex: element.getAttribute("tabindex") || "0",
          selector: selectorFor(element),
        };
      });
  }

  if (mode === "aria") {
    const issues = [];
    const focusableSelector = "a[href], button, input, select, textarea, [tabindex]";
    const ariaItems = Array.from(document.querySelectorAll("*"))
      .map((element) => {
        const attributes = Array.from(element.attributes || [])
          .filter((attribute) => attribute.name.startsWith("aria-") || attribute.name === "role")
          .map((attribute) => `${attribute.name}="${attribute.value}"`);

        if (!attributes.length) {
          return null;
        }

        return {
          element: element.tagName.toLowerCase(),
          selector: selectorFor(element),
          attributes,
          text: normalized(element.innerText || element.textContent).slice(0, 80),
        };
      })
      .filter(Boolean);

    document.querySelectorAll("[aria-hidden='true']").forEach((element) => {
      if (element.matches(focusableSelector) || element.querySelector(focusableSelector)) {
        issues.push(`aria-hidden brukes på eller rundt fokuserbart innhold: ${selectorFor(element)}`);
      }
    });

    document.querySelectorAll("[aria-labelledby]").forEach((element) => {
      const missing = normalized(element.getAttribute("aria-labelledby"))
        .split(/\s+/)
        .filter((id) => id && !document.getElementById(id));

      if (missing.length > 0) {
        issues.push(`aria-labelledby peker til manglende id på ${selectorFor(element)}: ${missing.join(", ")}`);
      }
    });

    document.querySelectorAll("[aria-label]").forEach((element) => {
      const ariaLabel = normalized(element.getAttribute("aria-label"));
      const visibleText = normalized(element.innerText || element.textContent);
      const role = normalized(element.getAttribute("role")).toLowerCase();
      const tag = element.tagName.toLowerCase();
      const labelInNameRoles = new Set([
        "button",
        "link",
        "checkbox",
        "radio",
        "switch",
        "tab",
        "menuitem",
        "menuitemcheckbox",
        "menuitemradio",
        "option",
        "treeitem",
      ]);
      const labelInNameElements = new Set(["a", "button"]);
      const type = (element.getAttribute("type") || "").toLowerCase();
      const isLabelInNameRelevant =
        labelInNameRoles.has(role) ||
        labelInNameElements.has(tag) ||
        (tag === "input" && ["button", "submit", "reset", "checkbox", "radio"].includes(type));

      if (isLabelInNameRelevant && ariaLabel && visibleText && !ariaLabel.toLowerCase().includes(visibleText.toLowerCase())) {
        issues.push(`aria-label inneholder ikke synlig tekst på ${selectorFor(element)}. Synlig tekst: ${visibleText}. Aria-label: ${ariaLabel}.`);
      }
    });

    document.querySelectorAll("[role]").forEach((element) => {
      const role = normalized(element.getAttribute("role"));

      if (["button", "link", "checkbox", "radio"].includes(role) && !accessibleName(element).value) {
        issues.push(`Element med role="${role}" mangler tilgjengelig navn: ${selectorFor(element)}`);
      }
    });

    return { ariaItems, issues };
  }

  if (mode === "iframes") {
    return Array.from(document.querySelectorAll("iframe")).map((iframe) => {
      const name = accessibleName(iframe);

      return {
        title: normalized(iframe.getAttribute("title")),
        name: name.value,
        nameSource: name.source,
        src: iframe.src || iframe.getAttribute("src") || "",
        selector: selectorFor(iframe),
      };
    });
  }

  return null;
}

async function getFields(page) {
  return page.evaluate(collectAccessibilityData, "fields");

  return page.evaluate(() => {
    const fieldSelector = "input, textarea, select, button";

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function isHidden(element) {
      if (element.tagName.toLowerCase() === "input" && element.type === "hidden") {
        return true;
      }

      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          style.contentVisibility === "hidden"
        ) {
          return true;
        }
      }

      return false;
    }

    function textFromIds(ids) {
      return ids
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((element) => normalized(element.innerText || element.textContent))
        .filter(Boolean)
        .join(" ");
    }

    function explicitLabel(element) {
      if (element.labels && element.labels.length > 0) {
        return Array.from(element.labels)
          .map((label) => normalized(label.innerText || label.textContent))
          .filter(Boolean)
          .join(" ");
      }

      if (element.id) {
        const label = document.querySelector(`label[for="${CSS.escape(element.id)}"]`);

        if (label) {
          return normalized(label.innerText || label.textContent);
        }
      }

      return "";
    }

    function accessibleName(element) {
      const ariaLabel = normalized(element.getAttribute("aria-label"));

      if (ariaLabel) {
        return ariaLabel;
      }

      const labelledBy = normalized(element.getAttribute("aria-labelledby"));

      if (labelledBy) {
        const label = normalized(textFromIds(labelledBy));

        if (label) {
          return label;
        }
      }

      if (element.tagName.toLowerCase() === "button") {
        return normalized(element.innerText || element.textContent || element.getAttribute("value"));
      }

      if (element.type === "button" || element.type === "submit" || element.type === "reset") {
        return normalized(element.getAttribute("value"));
      }

      if (element.type === "image") {
        return normalized(element.getAttribute("alt"));
      }

      return explicitLabel(element);
    }

    function fieldType(element) {
      const tagName = element.tagName.toLowerCase();

      if (tagName === "input") {
        return element.getAttribute("type") || "text";
      }

      return tagName;
    }

    function fieldValue(element) {
      const tagName = element.tagName.toLowerCase();
      const type = fieldType(element);

      if (type === "password") {
        return "(skjult)";
      }

      if (type === "checkbox" || type === "radio") {
        const value = element.getAttribute("value") || "";
        return `${value}${element.checked ? " (valgt)" : " (ikke valgt)"}`;
      }

      if (tagName === "select") {
        return Array.from(element.selectedOptions)
          .map((option) => normalized(option.textContent) || option.value)
          .join(", ");
      }

      if (tagName === "button") {
        return element.getAttribute("value") || "";
      }

      return element.value || element.getAttribute("value") || "";
    }

    function fieldInfo(element) {
      const tagName = element.tagName.toLowerCase();
      const kind =
        tagName === "button" ||
        ["button", "submit", "reset", "image"].includes((element.getAttribute("type") || "").toLowerCase())
          ? "button"
          : "field";

      return {
        kind,
        type: fieldType(element),
        value: fieldValue(element),
        name: accessibleName(element),
      };
    }

    function firstLegend(fieldset) {
      const legend = Array.from(fieldset.children).find(
        (child) => child.tagName && child.tagName.toLowerCase() === "legend"
      );

      return legend ? normalized(legend.innerText || legend.textContent) : "";
    }

    function directFieldsInFieldset(fieldset) {
      return Array.from(fieldset.querySelectorAll(fieldSelector)).filter(
        (field) => field.closest("fieldset") === fieldset && !isHidden(field)
      );
    }

    const groups = [];
    const groupedFields = new Set();
    const fieldsets = Array.from(document.querySelectorAll("fieldset")).filter((fieldset) => !isHidden(fieldset));

    fieldsets.forEach((fieldset) => {
      const fields = directFieldsInFieldset(fieldset);

      fields.forEach((field) => groupedFields.add(field));

      groups.push({
        type: "fieldset",
        legend: firstLegend(fieldset),
        fields: fields.map(fieldInfo),
      });
    });

    const ungroupedFields = Array.from(document.querySelectorAll(fieldSelector)).filter(
      (field) => !groupedFields.has(field) && !field.closest("fieldset") && !isHidden(field)
    );

    if (ungroupedFields.length > 0) {
      groups.unshift({
        type: "ungrouped",
        fields: ungroupedFields.map(fieldInfo),
      });
    }

    return groups;
  });
}

async function getContrast(page) {
  return page.evaluate(() => {
    const failuresAA = [];
    const failuresAAA = [];
    const seen = new Set();
    let checked = 0;

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function parseColor(color) {
      const match = String(color).match(/rgba?\(([^)]+)\)/i);

      if (!match) {
        return null;
      }

      const parts = match[1].split(",").map((part) => part.trim());
      const rgb = parts.slice(0, 3).map(Number);
      const alpha = parts.length > 3 ? Number(parts[3]) : 1;

      if (rgb.some((value) => Number.isNaN(value)) || Number.isNaN(alpha)) {
        return null;
      }

      return { r: rgb[0], g: rgb[1], b: rgb[2], a: alpha };
    }

    function blend(foreground, background) {
      const alpha = foreground.a + background.a * (1 - foreground.a);

      if (alpha === 0) {
        return { r: 255, g: 255, b: 255, a: 1 };
      }

      return {
        r: (foreground.r * foreground.a + background.r * background.a * (1 - foreground.a)) / alpha,
        g: (foreground.g * foreground.a + background.g * background.a * (1 - foreground.a)) / alpha,
        b: (foreground.b * foreground.a + background.b * background.a * (1 - foreground.a)) / alpha,
        a: alpha,
      };
    }

    function relativeLuminance(color) {
      const values = [color.r, color.g, color.b].map((channel) => {
        const value = channel / 255;
        return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
      });

      return 0.2126 * values[0] + 0.7152 * values[1] + 0.0722 * values[2];
    }

    function contrastRatio(foreground, background) {
      const first = relativeLuminance(foreground);
      const second = relativeLuminance(background);
      const lighter = Math.max(first, second);
      const darker = Math.min(first, second);

      return (lighter + 0.05) / (darker + 0.05);
    }

    function effectiveBackground(element) {
      let background = { r: 255, g: 255, b: 255, a: 1 };
      const colors = [];

      for (let node = element; node; node = node.parentElement) {
        const color = parseColor(window.getComputedStyle(node).backgroundColor);

        if (color && color.a > 0) {
          colors.push(color);
        }
      }

      colors.reverse().forEach((color) => {
        background = blend(color, background);
      });

      return background;
    }

    function isHidden(element) {
      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          style.opacity === "0" ||
          style.contentVisibility === "hidden"
        ) {
          return true;
        }
      }

      return false;
    }

    function isLargeText(style) {
      const fontSize = Number.parseFloat(style.fontSize);
      const fontWeight = Number.parseInt(style.fontWeight, 10);
      const isBold = fontWeight >= 700 || style.fontWeight === "bold";

      return fontSize >= 24 || (isBold && fontSize >= 18.66);
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function addFailure(collection, data) {
      const key = `${data.selector}|${data.text}|${data.required}`;

      if (!seen.has(key)) {
        seen.add(key);
        collection.push(data);
      }
    }

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);

    while (walker.nextNode()) {
      const textNode = walker.currentNode;
      const text = normalized(textNode.nodeValue);
      const element = textNode.parentElement;

      if (!text || !element || isHidden(element)) {
        continue;
      }

      const style = window.getComputedStyle(element);
      const foreground = parseColor(style.color);

      if (!foreground || foreground.a === 0) {
        continue;
      }

      checked += 1;

      const background = effectiveBackground(element);
      const ratio = contrastRatio(blend(foreground, background), background);
      const large = isLargeText(style);
      const aaRequired = large ? 3 : 4.5;
      const aaaRequired = large ? 4.5 : 7;
      const common = {
        text: text.length > 120 ? `${text.slice(0, 117)}...` : text,
        selector: selectorFor(element),
        ratio: Math.round(ratio * 100) / 100,
        largeText: large,
      };

      if (ratio < aaRequired) {
        addFailure(failuresAA, { ...common, required: aaRequired });
      }

      if (ratio < aaaRequired) {
        addFailure(failuresAAA, { ...common, required: aaaRequired });
      }
    }

    return {
      checked,
      aaFailures: failuresAA,
      aaaFailures: failuresAAA,
    };
  });
}

async function getLinks(page) {
  return page.evaluate(collectAccessibilityData, "links");

  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function textFromIds(ids) {
      return ids
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((element) => normalized(element.innerText || element.textContent))
        .filter(Boolean)
        .join(" ");
    }

    function accessibleName(element) {
      const ariaLabel = normalized(element.getAttribute("aria-label"));
      const labelledBy = normalized(element.getAttribute("aria-labelledby"));

      if (ariaLabel) {
        return ariaLabel;
      }

      if (labelledBy) {
        return textFromIds(labelledBy);
      }

      return normalized(element.innerText || element.textContent);
    }

    const links = Array.from(document.querySelectorAll("a[href]")).map((link) => ({
      name: accessibleName(link),
      href: link.href,
      newWindow: link.target === "_blank",
      selector: selectorFor(link),
    }));
    const issues = [];
    const byText = new Map();
    const byHref = new Map();

    links.forEach((link) => {
      if (!link.name) {
        issues.push(`Lenke mangler tekst: ${link.href}`);
      }

      if (link.newWindow && !/nytt|new/i.test(link.name)) {
        issues.push(`Lenke åpnes i nytt vindu uten at teksten sier det: ${link.name || link.href}`);
      }

      const textKey = link.name.toLowerCase();
      const hrefKey = link.href;

      if (textKey) {
        if (!byText.has(textKey)) {
          byText.set(textKey, new Set());
        }

        byText.get(textKey).add(hrefKey);
      }

      if (!byHref.has(hrefKey)) {
        byHref.set(hrefKey, new Set());
      }

      if (textKey) {
        byHref.get(hrefKey).add(link.name);
      }
    });

    byText.forEach((hrefs, text) => {
      if (hrefs.size > 1) {
        issues.push(`Samme lenketekst går til ulike URL-er: ${text}`);
      }
    });

    byHref.forEach((texts, href) => {
      if (texts.size > 1) {
        issues.push(`Samme URL har ulike lenketekster: ${href}`);
      }
    });

    return { links, issues };
  });
}

async function getBrokenLinks(page, pageUrl, options = {}) {
  const linkResult = await getLinks(page);
  const links = linkResult.links || [];
  const anchors = await page.evaluate(() => {
    const ids = new Set(Array.from(document.querySelectorAll("[id]")).map((element) => element.id));
    const names = new Set(Array.from(document.querySelectorAll("a[name]")).map((element) => element.getAttribute("name")));

    return {
      ids: Array.from(ids),
      names: Array.from(names),
    };
  });
  const anchorTargets = new Set([...anchors.ids, ...anchors.names]);
  const pageOriginUrl = new URL(pageUrl);
  pageOriginUrl.hash = "";
  const uniqueLinks = new Map();
  const checked = [];
  const broken = [];
  const skipped = [];

  links.forEach((link) => {
    if (!uniqueLinks.has(link.href)) {
      uniqueLinks.set(link.href, link);
    }
  });

  async function checkHttpLink(link) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      let response = await fetch(link.href, {
        method: "HEAD",
        redirect: "follow",
        signal: controller.signal,
      });

      if (response.status === 405 || response.status === 403) {
        response = await fetch(link.href, {
          method: "GET",
          redirect: "follow",
          signal: controller.signal,
        });
      }

      checked.push({
        ...link,
        status: response.status,
        statusText: response.statusText || "",
      });

      if (response.status >= 400 && !shouldIgnoreHttpStatus(response.status, options)) {
        broken.push({
          ...link,
          reason: `HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`,
        });
      }
    } catch (error) {
      broken.push({
        ...link,
        reason: error.name === "AbortError" ? "Tidsavbrudd" : "Kunne ikke nå lenken",
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  async function checkLink(link) {
    let parsed;

    try {
      parsed = new URL(link.href);
    } catch {
      broken.push({
        ...link,
        reason: "Ugyldig URL",
      });
      return;
    }

    if (parsed.protocol === "http:" || parsed.protocol === "https:") {
      const withoutHash = new URL(parsed.href);
      withoutHash.hash = "";

      if (withoutHash.href === pageOriginUrl.href && parsed.hash) {
        let target = parsed.hash.slice(1);

        try {
          target = decodeURIComponent(target);
        } catch {
          // Keep the raw hash if it is not valid percent-encoded text.
        }

        checked.push({
          ...link,
          status: target ? "anker" : "side",
          statusText: "",
        });

        if (target && !anchorTargets.has(target)) {
          broken.push({
            ...link,
            reason: `Mangler anker: #${target}`,
          });
        }

        return;
      }

      try {
        await validatePublicUrl(parsed.href);
      } catch {
        skipped.push({
          ...link,
          reason: "Ikke en offentlig http/https-URL",
        });
        return;
      }

      await checkHttpLink(link);
      return;
    }

    skipped.push({
      ...link,
      reason: `Hoppet over ${parsed.protocol.replace(":", "")}-lenke`,
    });
  }

  const queue = Array.from(uniqueLinks.values());
  const workers = Array.from({ length: Math.min(maxBrokenLinkWorkers, queue.length) }, async () => {
    while (queue.length > 0) {
      const link = queue.shift();
      await checkLink(link);
    }
  });

  await Promise.all(workers);

  return {
    checkedCount: checked.length,
    skippedCount: skipped.length,
    totalCount: uniqueLinks.size,
    broken,
    skipped,
  };
}

async function getImages(page) {
  const images = await page.evaluate(collectAccessibilityData, "images");

  for (const image of images) {
    if (image.src || !image.selector || image.elementType === "area") {
      continue;
    }

    try {
      const locator = page.locator(image.selector).first();
      const box = await locator.boundingBox({ timeout: 1000 });

      if (!box || box.width < 1 || box.height < 1) {
        continue;
      }

      const buffer = await locator.screenshot({ type: "png", timeout: 2000 });
      image.previewSrc = `data:image/png;base64,${buffer.toString("base64")}`;
      image.previewSource = "element-screenshot";
    } catch {
      image.previewSource = image.previewSrc ? "svg-data-url" : "none";
    }
  }

  return images;

  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.src || element.currentSrc || element.tagName.toLowerCase();
    }

    return Array.from(document.querySelectorAll("img")).map((image) => {
      const hasAlt = image.hasAttribute("alt");
      const alt = image.getAttribute("alt") || "";
      let altStatus = "mangler alt";

      if (hasAlt && alt === "") {
        altStatus = "tom alt";
      } else if (hasAlt) {
        altStatus = alt;
      }

      return {
        altStatus,
        src: image.currentSrc || image.src || "",
        role: normalized(image.getAttribute("role")),
        ariaHidden: image.getAttribute("aria-hidden") === "true",
        selector: selectorFor(image),
      };
    });
  });
}

async function getLandmarks(page) {
  return page.evaluate(collectAccessibilityData, "landmarks");

  return page.evaluate(() => {
    const landmarkRoles = new Set(["banner", "navigation", "main", "complementary", "contentinfo", "search", "form", "region"]);
    const selector = "header, nav, main, aside, footer, form, section, [role]";

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    function textFromIds(ids) {
      return ids
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((element) => normalized(element.innerText || element.textContent))
        .filter(Boolean)
        .join(" ");
    }

    function accessibleName(element) {
      return (
        normalized(element.getAttribute("aria-label")) ||
        textFromIds(normalized(element.getAttribute("aria-labelledby")))
      );
    }

    function roleFor(element) {
      const explicitRole = normalized(element.getAttribute("role"));

      if (landmarkRoles.has(explicitRole)) {
        return explicitRole;
      }

      const tag = element.tagName.toLowerCase();

      if (tag === "header") {
        return "banner";
      }

      if (tag === "nav") {
        return "navigation";
      }

      if (tag === "main") {
        return "main";
      }

      if (tag === "aside") {
        return "complementary";
      }

      if (tag === "footer") {
        return "contentinfo";
      }

      if (tag === "form" && accessibleName(element)) {
        return "form";
      }

      if (tag === "section" && accessibleName(element)) {
        return "region";
      }

      return "";
    }

    const landmarks = Array.from(document.querySelectorAll(selector))
      .map((element) => ({
        role: roleFor(element),
        name: accessibleName(element),
        selector: selectorFor(element),
      }))
      .filter((landmark) => landmark.role);
    const issues = [];
    const mains = landmarks.filter((landmark) => landmark.role === "main");
    const navs = landmarks.filter((landmark) => landmark.role === "navigation");

    if (mains.length === 0) {
      issues.push("main mangler.");
    }

    if (mains.length > 1) {
      issues.push("Det finnes flere main-landemerker.");
    }

    if (navs.length > 1 && navs.some((nav) => !nav.name)) {
      issues.push("Flere navigasjonslandemerker finnes, og minst ett mangler navn.");
    }

    return { landmarks, issues };
  });
}

async function getTitleInfo(page) {
  return page.evaluate(() => {
    const title = document.title.trim();
    const firstH1 = document.querySelector("h1")?.innerText.replace(/\s+/g, " ").trim() || "";
    let message = "OK.";

    if (!title && !firstH1) {
      message = "Dokumenttittel og h1 mangler.";
    } else if (!title) {
      message = "Dokumenttittel mangler.";
    } else if (!firstH1) {
      message = "Første h1 mangler.";
    } else if (!title.toLowerCase().includes(firstH1.toLowerCase()) && !firstH1.toLowerCase().includes(title.toLowerCase())) {
      message = "Dokumenttittel og første h1 virker ulike.";
    }

    return { title, firstH1, message };
  });
}

async function getMetaInfo(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function metaContent(selector) {
      return normalized(document.querySelector(selector)?.getAttribute("content") || "");
    }

    function linkHref(selector) {
      return document.querySelector(selector)?.href || document.querySelector(selector)?.getAttribute("href") || "";
    }

    function collectMeta(prefixSelector) {
      return Array.from(document.querySelectorAll(prefixSelector))
        .map((meta) => ({
          name: meta.getAttribute("property") || meta.getAttribute("name") || "",
          content: normalized(meta.getAttribute("content") || ""),
        }))
        .filter((meta) => meta.name || meta.content);
    }

    const title = normalized(document.title);
    const description = metaContent("meta[name='description' i]");
    const viewport = metaContent("meta[name='viewport' i]");
    const robots = metaContent("meta[name='robots' i]");
    const canonical = linkHref("link[rel~='canonical']");
    const lang = normalized(document.documentElement.getAttribute("lang") || "");
    const charset = document.characterSet || "";
    const openGraph = collectMeta("meta[property^='og:' i]");
    const twitter = collectMeta("meta[name^='twitter:' i]");
    const favicons = Array.from(document.querySelectorAll("link[rel~='icon'], link[rel='shortcut icon' i], link[rel='apple-touch-icon' i]"))
      .map((link) => ({
        rel: link.getAttribute("rel") || "",
        href: link.href || link.getAttribute("href") || "",
        sizes: link.getAttribute("sizes") || "",
        type: link.getAttribute("type") || "",
      }))
      .filter((icon) => icon.href);
    const issues = [];

    if (!title) issues.push("Dokumenttittel mangler.");
    if (title.length > 70) issues.push("Dokumenttittel er lang.");
    if (!description) issues.push("Meta description mangler.");
    if (description.length > 170) issues.push("Meta description er lang.");
    if (!viewport) issues.push("Viewport-meta mangler.");
    if (!lang) issues.push("Språk mangler på html-elementet.");
    if (!canonical) issues.push("Canonical-lenke mangler.");
    if (!openGraph.some((meta) => meta.name === "og:title")) issues.push("Open Graph-title mangler.");
    if (!openGraph.some((meta) => meta.name === "og:description")) issues.push("Open Graph-description mangler.");
    if (!openGraph.some((meta) => meta.name === "og:image")) issues.push("Open Graph-image mangler.");
    if (!favicons.length) issues.push("Favicon mangler.");

    return {
      title,
      titleLength: title.length,
      description,
      descriptionLength: description.length,
      lang,
      charset,
      viewport,
      robots,
      canonical,
      openGraph,
      twitter,
      favicons,
      issues,
    };
  });
}

async function getCookiesInfo(page, pageUrl) {
  const pageAddress = new URL(pageUrl);
  const pageHost = pageAddress.hostname.toLowerCase();
  const cookies = await page.context().cookies();
  const issues = [];
  const nowSeconds = Date.now() / 1000;

  function normalizedDomain(domain) {
    return String(domain || "").replace(/^\./, "").toLowerCase();
  }

  function relationFor(domain) {
    const cookieDomain = normalizedDomain(domain);

    if (pageHost === cookieDomain || pageHost.endsWith(`.${cookieDomain}`)) {
      return "sidedomenet";
    }

    return "annet domene (mulig tredjepart)";
  }

  function valueForReport(cookie) {
    const value = String(cookie.value || "");
    const name = String(cookie.name || "");
    const sensitiveName = /auth|session|token|jwt|login|csrf|xsrf|secret|bearer|oauth|(^|[_-])sid($|[_-])|(user|client|visitor|tracking|device)[_-]?id|(^|[_-])(id|uid)($|[_-])/i;
    const trackingName = /^(_ga|_gid|_gat|_fbp|_fbc|_gcl|amplitude|mp_)/i;
    const uuidLike = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const jwtLike = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?$/;
    const longHex = /^[0-9a-f]{16,}$/i;
    const longNumber = /^\d{12,}$/;
    const compactIdentifier = /^[A-Za-z0-9_-]{20,}$/;
    const uniqueRatio = value.length ? new Set(value).size / value.length : 0;

    if (!value) {
      return { valueHidden: false, displayValue: "", valueReason: "" };
    }

    if (cookie.httpOnly) {
      return { valueHidden: true, displayValue: "", valueReason: "HttpOnly-cookie" };
    }

    if (sensitiveName.test(name)) {
      return { valueHidden: true, displayValue: "", valueReason: "navnet tyder på sesjon, autentisering eller unik ID" };
    }

    if (trackingName.test(name)) {
      return { valueHidden: true, displayValue: "", valueReason: "mulig sporings-ID" };
    }

    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) || /^https?:\/\//i.test(value)) {
      return { valueHidden: true, displayValue: "", valueReason: "kan inneholde person- eller adresseopplysninger" };
    }

    if (/["']?(uid|user[_-]?id|client[_-]?id|visitor[_-]?id|device[_-]?id|token|session|auth)["']?\s*[:=]/i.test(value)) {
      return { valueHidden: true, displayValue: "", valueReason: "strukturert verdi med mulig unik ID eller token" };
    }

    if (value.length > 80) {
      return { valueHidden: true, displayValue: "", valueReason: "lang verdi" };
    }

    if (uuidLike.test(value) || jwtLike.test(value) || longHex.test(value) || longNumber.test(value)) {
      return { valueHidden: true, displayValue: "", valueReason: "mulig unik ID eller token" };
    }

    if (compactIdentifier.test(value) && uniqueRatio > 0.55) {
      return { valueHidden: true, displayValue: "", valueReason: "tilfeldig eller unik verdi" };
    }

    if (/[^\x20-\x7E\u00A0-\uFFFF]/.test(value)) {
      return { valueHidden: true, displayValue: "", valueReason: "inneholder kontrolltegn" };
    }

    return { valueHidden: false, displayValue: value, valueReason: "" };
  }

  const items = cookies.map((cookie) => {
    const session = !Number.isFinite(cookie.expires) || cookie.expires <= 0;
    const remainingDays = session ? null : Math.max(0, Math.ceil((cookie.expires - nowSeconds) / 86400));
    const estimatedSize = Buffer.byteLength(`${cookie.name}=${cookie.value}`, "utf8");
    const relation = relationFor(cookie.domain);
    const label = `${cookie.name} (${cookie.domain}${cookie.path || "/"})`;
    const reportedValue = valueForReport(cookie);

    if (pageAddress.protocol === "https:" && !cookie.secure) {
      issues.push(`${label} mangler Secure og kan også sendes over en ukryptert HTTP-forbindelse.`);
    }

    if (String(cookie.sameSite || "").toLowerCase() === "none" && !cookie.secure) {
      issues.push(`${label} har SameSite=None uten Secure.`);
    }

    if (/auth|session|token|jwt|login|(^|[_-])sid($|[_-])/i.test(cookie.name) && !cookie.httpOnly) {
      issues.push(`${label} kan være knyttet til innlogging eller sesjon, men mangler HttpOnly.`);
    }

    if (estimatedSize > 4096) {
      issues.push(`${label} er omtrent ${estimatedSize} byte og er større enn den vanlige grensen på 4096 byte.`);
    }

    if (remainingDays !== null && remainingDays > 400) {
      issues.push(`${label} har mer enn 400 dager igjen av levetiden.`);
    }

    return {
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path || "/",
      relation,
      session,
      expiresAt: session ? "" : new Date(cookie.expires * 1000).toISOString(),
      remainingDays,
      secure: Boolean(cookie.secure),
      httpOnly: Boolean(cookie.httpOnly),
      sameSite: cookie.sameSite || "ikke oppgitt",
      partitioned: Boolean(cookie.partitionKey),
      valueLength: String(cookie.value || "").length,
      ...reportedValue,
      estimatedSize,
    };
  }).sort((a, b) =>
    a.relation.localeCompare(b.relation, "nb") ||
    a.domain.localeCompare(b.domain, "nb") ||
    a.name.localeCompare(b.name, "nb")
  );

  return {
    items,
    issues: Array.from(new Set(issues)),
    pageDomainCount: items.filter((cookie) => cookie.relation === "sidedomenet").length,
    otherDomainCount: items.filter((cookie) => cookie.relation !== "sidedomenet").length,
    sessionCount: items.filter((cookie) => cookie.session).length,
    persistentCount: items.filter((cookie) => !cookie.session).length,
    secureCount: items.filter((cookie) => cookie.secure).length,
    httpOnlyCount: items.filter((cookie) => cookie.httpOnly).length,
  };
}

async function getReadability(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function isHidden(element) {
      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          node.getAttribute("aria-hidden") === "true"
        ) {
          return true;
        }
      }

      return false;
    }

    function visibleText(element) {
      if (!element || isHidden(element)) {
        return "";
      }

      return normalized(element.innerText || element.textContent || "");
    }

    const bodyText = visibleText(document.body);
    const words = bodyText.match(/\b[\p{L}\p{N}][\p{L}\p{N}'’-]*\b/gu) || [];
    const sentences = bodyText
      .split(/[.!?]+(?:\s|$)/)
      .map(normalized)
      .filter((sentence) => sentence.split(/\s+/).filter(Boolean).length > 3);
    const paragraphs = Array.from(document.querySelectorAll("p, li"))
      .map((element) => ({
        element,
        text: visibleText(element),
      }))
      .filter((item) => item.text);
    const longParagraphs = paragraphs
      .map((item) => ({
        tag: item.element.tagName.toLowerCase(),
        words: (item.text.match(/\b[\p{L}\p{N}][\p{L}\p{N}'’-]*\b/gu) || []).length,
        text: item.text.slice(0, 240),
        selector: selectorFor(item.element),
      }))
      .filter((item) => item.words >= 90)
      .slice(0, 20);
    const longSentences = sentences
      .map((sentence) => ({
        words: sentence.split(/\s+/).filter(Boolean).length,
        text: sentence.slice(0, 240),
      }))
      .filter((sentence) => sentence.words >= 30)
      .slice(0, 20);
    const weakLinkPatterns = /^(les mer|mer|her|klikk her|trykk her|read more|more)$/i;
    const weakLinks = Array.from(document.querySelectorAll("a[href]"))
      .map((link) => ({
        text: visibleText(link),
        href: link.href || link.getAttribute("href") || "",
        selector: selectorFor(link),
      }))
      .filter((link) => !link.text || weakLinkPatterns.test(link.text))
      .slice(0, 30);
    const uppercaseTexts = Array.from(document.querySelectorAll("h1, h2, h3, p, li, a, button"))
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        text: visibleText(element),
        selector: selectorFor(element),
      }))
      .filter((item) => item.text.length >= 18 && item.text === item.text.toLocaleUpperCase("nb-NO") && /[A-ZÆØÅ]{4}/.test(item.text))
      .slice(0, 20);
    const languageChanges = Array.from(document.querySelectorAll("[lang]"))
      .filter((element) => element !== document.documentElement)
      .map((element) => ({
        tag: element.tagName.toLowerCase(),
        lang: element.getAttribute("lang") || "",
        text: visibleText(element).slice(0, 160),
        selector: selectorFor(element),
      }))
      .slice(0, 30);
    const issues = [];

    if (!document.documentElement.getAttribute("lang")) {
      issues.push("Siden mangler språk på html-elementet.");
    }

    if (longParagraphs.length) {
      issues.push("Noen avsnitt eller listepunkter er lange.");
    }

    if (longSentences.length) {
      issues.push("Noen setninger er lange.");
    }

    if (weakLinks.length) {
      issues.push("Noen lenker har svak eller manglende lenketekst.");
    }

    if (uppercaseTexts.length) {
      issues.push("Noe tekst er skrevet med store bokstaver.");
    }

    return {
      wordCount: words.length,
      sentenceCount: sentences.length,
      paragraphCount: paragraphs.length,
      averageWordsPerSentence: sentences.length ? Math.round(words.length / sentences.length) : 0,
      longParagraphs,
      longSentences,
      weakLinks,
      uppercaseTexts,
      languageChanges,
      issues,
    };
  });
}

async function getFocus(page) {
  return page.evaluate(collectAccessibilityData, "focus");

  return page.evaluate(() => {
    const selector = [
      "a[href]",
      "button",
      "input:not([type='hidden'])",
      "select",
      "textarea",
      "[tabindex]",
      "[contenteditable='true']",
    ].join(",");

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function isHidden(element) {
      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse"
        ) {
          return true;
        }
      }

      return false;
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    function textFromIds(ids) {
      return ids
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((element) => normalized(element.innerText || element.textContent))
        .filter(Boolean)
        .join(" ");
    }

    function accessibleName(element) {
      return (
        normalized(element.getAttribute("aria-label")) ||
        textFromIds(normalized(element.getAttribute("aria-labelledby"))) ||
        normalized(element.innerText || element.textContent || element.getAttribute("alt") || element.getAttribute("value"))
      );
    }

    return Array.from(document.querySelectorAll(selector))
      .filter((element) => !element.disabled && element.tabIndex >= 0 && !isHidden(element))
      .sort((a, b) => {
        const aTab = a.tabIndex === 0 ? Number.MAX_SAFE_INTEGER : a.tabIndex;
        const bTab = b.tabIndex === 0 ? Number.MAX_SAFE_INTEGER : b.tabIndex;
        return aTab - bTab;
      })
      .map((element) => ({
        type: element.tagName.toLowerCase(),
        name: accessibleName(element),
        text: normalized(element.innerText || element.textContent),
        tabindex: element.getAttribute("tabindex") || "0",
        selector: selectorFor(element),
      }));
  });
}

async function getAriaIssues(page) {
  return page.evaluate(collectAccessibilityData, "aria");

  return page.evaluate(() => {
    const issues = [];
    const focusableSelector = "a[href], button, input, select, textarea, [tabindex]";

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function labelFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    document.querySelectorAll("[aria-hidden='true']").forEach((element) => {
      if (element.matches(focusableSelector) || element.querySelector(focusableSelector)) {
        issues.push(`aria-hidden brukes på eller rundt fokuserbart innhold: ${labelFor(element)}`);
      }
    });

    document.querySelectorAll("[aria-labelledby]").forEach((element) => {
      const missing = normalized(element.getAttribute("aria-labelledby"))
        .split(/\s+/)
        .filter((id) => id && !document.getElementById(id));

      if (missing.length > 0) {
        issues.push(`aria-labelledby peker til manglende id på ${labelFor(element)}: ${missing.join(", ")}`);
      }
    });

    document.querySelectorAll("[aria-label]").forEach((element) => {
      const ariaLabel = normalized(element.getAttribute("aria-label"));
      const visibleText = normalized(element.innerText || element.textContent);

      if (ariaLabel && visibleText && ariaLabel !== visibleText) {
        issues.push(`aria-label er ulik synlig tekst på ${labelFor(element)}. Synlig tekst: ${visibleText}. Aria-label: ${ariaLabel}.`);
      }
    });

    document.querySelectorAll("[role]").forEach((element) => {
      const role = normalized(element.getAttribute("role"));

      if (["button", "link", "checkbox", "radio"].includes(role) && !normalized(element.innerText || element.textContent || element.getAttribute("aria-label"))) {
        issues.push(`Element med role="${role}" mangler tilgjengelig navn: ${labelFor(element)}`);
      }
    });

    return issues;
  });
}

async function getTables(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return "table";
    }

    return Array.from(document.querySelectorAll("table")).map((table) => {
      const rows = table.rows.length;
      const columns = rows > 0 ? Math.max(...Array.from(table.rows).map((row) => row.cells.length)) : 0;
      const headers = Array.from(table.querySelectorAll("th"));
      const caption = normalized(table.caption?.innerText || table.caption?.textContent || "");
      const sampleRowLimit = 5;
      const sampleColumnLimit = 8;
      const sampleRows = Array.from(table.rows).slice(0, sampleRowLimit).map((row) => ({
        cells: Array.from(row.cells).slice(0, sampleColumnLimit).map((cell) => ({
          text: normalized(cell.innerText || cell.textContent).slice(0, 200),
          header: cell.tagName.toLowerCase() === "th",
          scope: normalized(cell.getAttribute("scope")),
          colspan: cell.colSpan || 1,
          rowspan: cell.rowSpan || 1,
        })),
      }));

      return {
        caption,
        rows,
        columns,
        headerCells: headers.length,
        missingScope: headers.some((header) => !header.hasAttribute("scope")),
        possibleLayout: headers.length === 0 && !caption,
        sampleRows,
        sampleRowLimit,
        sampleColumnLimit,
        truncatedRows: rows > sampleRowLimit,
        truncatedColumns: columns > sampleColumnLimit,
        selector: selectorFor(table),
      };
    });
  });
}

async function getVideos(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    function providerFromUrl(url) {
      const value = String(url || "");

      if (/youtube(?:-nocookie)?\.com|youtu\.be/i.test(value)) return "YouTube";
      if (/vimeo\.com/i.test(value)) return "Vimeo";
      if (/facebook\.com\/plugins\/video|fb\.watch/i.test(value)) return "Facebook";
      if (/wistia\.com|wistia\.net/i.test(value)) return "Wistia";
      if (/kaltura/i.test(value)) return "Kaltura";
      if (/brightcove|bcove/i.test(value)) return "Brightcove";
      if (/\.(mp4|webm|ogg|ogv|mov|m3u8)(?:[?#]|$)/i.test(value)) return "Videofil";
      return "";
    }

    const videos = [];
    const seen = new Set();

    function addVideo(item) {
      const key = `${item.type}|${item.src}|${item.title}`;

      if (seen.has(key) || (!item.src && !item.title)) {
        return;
      }

      seen.add(key);
      videos.push(item);
    }

    document.querySelectorAll("video").forEach((video) => {
      const sources = [
        video.currentSrc || video.src || video.getAttribute("src") || "",
        ...Array.from(video.querySelectorAll("source")).map((source) => source.src || source.getAttribute("src") || ""),
      ].filter(Boolean);

      (sources.length ? sources : [""]).forEach((src) => addVideo({
        type: "video",
        provider: providerFromUrl(src) || "HTML video",
        title: normalized(video.getAttribute("title") || video.getAttribute("aria-label") || video.getAttribute("poster")),
        src,
        selector: selectorFor(video),
      }));
    });

    document.querySelectorAll("iframe, embed, object").forEach((element) => {
      const src = element.src || element.data || element.getAttribute("src") || element.getAttribute("data") || "";
      const provider = providerFromUrl(src);

      if (provider || /video|player|embed/i.test(src)) {
        addVideo({
          type: element.tagName.toLowerCase(),
          provider: provider || "embed",
          title: normalized(element.getAttribute("title") || element.getAttribute("aria-label")),
          src,
          selector: selectorFor(element),
        });
      }
    });

    document.querySelectorAll("a[href]").forEach((link) => {
      const href = link.href || link.getAttribute("href") || "";
      const provider = providerFromUrl(href);

      if (provider) {
        addVideo({
          type: "lenke",
          provider,
          title: normalized(link.innerText || link.textContent || link.getAttribute("aria-label")),
          src: href,
          selector: selectorFor(link),
        });
      }
    });

    return videos;
  });
}

async function getForms(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    function fieldName(element) {
      return normalized(
        element.getAttribute("aria-label") ||
        element.getAttribute("name") ||
        element.id ||
        element.getAttribute("value") ||
        element.innerText ||
        element.textContent
      );
    }

    return Array.from(document.querySelectorAll("form")).map((form, index) => {
      const fields = Array.from(form.querySelectorAll("input, select, textarea, button")).map((field) => ({
        type: field.getAttribute("type") || field.tagName.toLowerCase(),
        name: fieldName(field),
      }));

      return {
        index: index + 1,
        action: form.action || form.getAttribute("action") || "",
        method: (form.method || form.getAttribute("method") || "get").toLowerCase(),
        fieldCount: fields.length,
        fields: fields.slice(0, 12),
        selector: selectorFor(form),
      };
    });
  });
}

async function getIframes(page) {
  return page.evaluate(collectAccessibilityData, "iframes");

  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return "iframe";
    }

    return Array.from(document.querySelectorAll("iframe")).map((iframe) => ({
      title: normalized(iframe.getAttribute("title")),
      src: iframe.src || iframe.getAttribute("src") || "",
      selector: selectorFor(iframe),
    }));
  });
}

async function getIds(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    const counts = new Map();
    const ids = Array.from(document.querySelectorAll("[id]")).map((element) => {
      const id = element.id;
      counts.set(id, (counts.get(id) || 0) + 1);

      return {
        id,
        element: element.tagName.toLowerCase(),
        text: normalized(element.innerText || element.textContent).slice(0, 80),
        selector: selectorFor(element),
      };
    });
    const duplicates = Array.from(counts.entries())
      .filter(([, count]) => count > 1)
      .map(([id, count]) => ({ id, count }));

    return {
      ids,
      duplicates,
      issues: duplicates.map((duplicate) => `ID-en "${duplicate.id}" finnes ${duplicate.count} ganger.`),
    };
  });
}

async function getAriaPointers(page) {
  return page.evaluate(() => {
    const idReferenceAttributes = [
      "aria-labelledby",
      "aria-describedby",
      "aria-controls",
      "aria-owns",
      "aria-activedescendant",
      "aria-details",
      "aria-errormessage",
      "aria-flowto",
    ];

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function isHidden(element) {
      if (!element || !(element instanceof Element)) {
        return false;
      }

      if (element.tagName.toLowerCase() === "input" && element.type === "hidden") {
        return true;
      }

      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          node.getAttribute("aria-hidden") === "true" ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          style.contentVisibility === "hidden"
        ) {
          return true;
        }
      }

      return false;
    }

    function labelText(element) {
      const labels = element.labels ? Array.from(element.labels) : [];

      if (!labels.length && element.id) {
        labels.push(...document.querySelectorAll(`label[for="${CSS.escape(element.id)}"]`));
      }

      return normalized(labels.map((label) => label.innerText || label.textContent).join(" "));
    }

    function svgTitle(element) {
      const title = Array.from(element.children || []).find((child) => child.tagName.toLowerCase() === "title");
      return title ? normalized(title.textContent) : "";
    }

    function accessibleName(element) {
      if (!(element instanceof Element)) {
        return { value: "", source: "ingen" };
      }

      const labelledBy = normalized(element.getAttribute("aria-labelledby"));

      if (labelledBy) {
        const value = normalized(labelledBy
          .split(/\s+/)
          .map((id) => document.getElementById(id))
          .filter(Boolean)
          .map((target) => target.innerText || target.textContent)
          .join(" "));

        if (value) {
          return { value, source: "aria-labelledby" };
        }
      }

      const ariaLabel = normalized(element.getAttribute("aria-label"));

      if (ariaLabel) {
        return { value: ariaLabel, source: "aria-label" };
      }

      const tag = element.tagName.toLowerCase();
      const type = (element.getAttribute("type") || "").toLowerCase();

      if (["img", "area"].includes(tag) || (tag === "input" && type === "image")) {
        if (element.hasAttribute("alt")) {
          return { value: normalized(element.getAttribute("alt")), source: "alt" };
        }
      }

      if (["input", "select", "textarea", "output", "meter", "progress"].includes(tag)) {
        const text = labelText(element);

        if (text) {
          return { value: text, source: "label" };
        }
      }

      if (tag === "input" && ["button", "submit", "reset"].includes(type)) {
        const value = normalized(element.getAttribute("value"));

        if (value) {
          return { value, source: "value" };
        }
      }

      if (tag === "svg") {
        const title = svgTitle(element);

        if (title) {
          return { value: title, source: "svg title" };
        }
      }

      if (["a", "button", "summary", "option", "legend", "label"].includes(tag)) {
        const text = normalized(element.innerText || element.textContent);

        if (text) {
          return { value: text, source: "innhold" };
        }
      }

      const title = normalized(element.getAttribute("title"));

      if (title) {
        return { value: title, source: "title" };
      }

      return { value: "", source: "ingen" };
    }

    function matchingIds(id) {
      return Array.from(document.querySelectorAll("[id]")).filter((element) => element.id === id);
    }

    const references = [];
    const issues = [];
    let referenceCount = 0;

    Array.from(document.querySelectorAll("*")).forEach((element) => {
      idReferenceAttributes.forEach((attribute) => {
        if (!element.hasAttribute(attribute)) {
          return;
        }

        const ids = normalized(element.getAttribute(attribute)).split(/\s+/).filter(Boolean);

        if (!ids.length) {
          issues.push(`${attribute} er tom på ${selectorFor(element)}.`);
          return;
        }

        referenceCount += ids.length;
        const name = accessibleName(element);
        const targets = ids.map((id) => {
          const matches = matchingIds(id);
          const first = matches[0] || null;
          const targetName = first ? accessibleName(first) : { value: "", source: "ingen" };
          const text = first ? normalized(targetName.value || first.innerText || first.textContent).slice(0, 180) : "";
          const hidden = first ? isHidden(first) : false;

          if (!first) {
            issues.push(`${attribute} på ${selectorFor(element)} peker til manglende id: ${id}.`);
          } else {
            if (matches.length > 1) {
              issues.push(`${attribute} på ${selectorFor(element)} peker til duplikat id: ${id} (${matches.length} forekomster).`);
            }

            if (!text) {
              issues.push(`${attribute} på ${selectorFor(element)} peker til et element uten tekst/navn: ${id}.`);
            }

            if (hidden) {
              issues.push(`${attribute} på ${selectorFor(element)} peker til et skjult element: ${id}.`);
            }
          }

          return {
            id,
            count: matches.length,
            element: first ? first.tagName.toLowerCase() : "",
            text,
            nameSource: targetName.source,
            hidden,
            selector: first ? selectorFor(first) : "",
          };
        });

        references.push({
          element: element.tagName.toLowerCase(),
          role: normalized(element.getAttribute("role")),
          name: name.value,
          nameSource: name.source,
          selector: selectorFor(element),
          attribute,
          ids,
          targets,
        });
      });
    });

    return {
      references,
      issues,
      summary: {
        elements: references.length,
        idReferences: referenceCount,
        issues: issues.length,
      },
    };
  });
}

async function getFonts(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function isVisible(element) {
      const rect = element.getBoundingClientRect();

      if (rect.width === 0 || rect.height === 0) {
        return false;
      }

      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          node.getAttribute("aria-hidden") === "true" ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse"
        ) {
          return false;
        }
      }

      return true;
    }

    function describeColor(red, green, blue) {
      const r = Math.max(0, Math.min(255, Math.round(red))) / 255;
      const g = Math.max(0, Math.min(255, Math.round(green))) / 255;
      const b = Math.max(0, Math.min(255, Math.round(blue))) / 255;
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      const delta = max - min;
      const lightness = (max + min) / 2;
      const saturation = delta === 0 ? 0 : delta / (1 - Math.abs(2 * lightness - 1));
      let hue = 0;

      if (delta !== 0) {
        if (max === r) {
          hue = ((g - b) / delta) % 6;
        } else if (max === g) {
          hue = (b - r) / delta + 2;
        } else {
          hue = (r - g) / delta + 4;
        }

        hue = Math.round(hue * 60);
        if (hue < 0) {
          hue += 360;
        }
      }

      if (lightness <= 0.04) {
        return "svart";
      }

      if (lightness >= 0.97 && saturation <= 0.12) {
        return "hvit";
      }

      if (saturation <= 0.08) {
        const tone = red > blue + 8 ? "varm " : blue > red + 8 ? "kald " : "nøytral ";
        if (lightness >= 0.92) return "nesten hvit";
        if (lightness >= 0.78) return `svært lys ${tone}grå`;
        if (lightness >= 0.62) return `lys ${tone}grå`;
        if (lightness >= 0.42) return `${tone}grå`;
        if (lightness >= 0.20) return `mørk ${tone}grå`;
        return "nesten svart";
      }

      const hueNames = [
        [12, "rød"],
        [28, "rødoransje"],
        [45, "oransje"],
        [65, "guloransje"],
        [85, "gul"],
        [145, "gulgrønn"],
        [170, "grønn"],
        [195, "blågrønn"],
        [215, "turkis"],
        [245, "blå"],
        [275, "blåfiolett"],
        [305, "lilla"],
        [330, "fiolett"],
        [345, "magentarød"],
        [360, "rød"],
      ];
      let hueName = hueNames.find(([limit]) => hue <= limit)?.[1] || "rød";

      if (hue >= 18 && hue <= 55 && saturation >= 0.20 && lightness < 0.43) {
        hueName = "brun";
      } else if (hue >= 35 && hue <= 75 && saturation < 0.45 && lightness >= 0.62) {
        hueName = "beige";
      } else if ((hue >= 330 || hue <= 12) && lightness >= 0.68 && saturation < 0.75) {
        hueName = "rosa";
      }

      const modifiers = [];
      if (lightness >= 0.90) modifiers.push("svært lys");
      else if (lightness >= 0.72) modifiers.push("lys");
      else if (lightness <= 0.16) modifiers.push("svært mørk");
      else if (lightness <= 0.34) modifiers.push("mørk");

      if (saturation <= 0.22) modifiers.push("svakt mettet");
      else if (saturation <= 0.42) modifiers.push("dempet");
      else if (saturation >= 0.78) modifiers.push("klar");

      return [...modifiers, hueName].join(" ");
    }

    function colorInfo(color) {
      const match = color.match(/rgba?\(([^)]+)\)/);

      if (!match) {
        return { text: color, value: color };
      }

      const parts = match[1].split(",").map((part) => part.trim());
      const red = Number(parts[0]);
      const green = Number(parts[1]);
      const blue = Number(parts[2]);
      const alpha = parts[3] === undefined ? 1 : Number(parts[3]);
      const hex = [red, green, blue]
        .map((value) => Math.max(0, Math.min(255, Math.round(value))).toString(16).padStart(2, "0"))
        .join("");
      const value = `#${hex}`;
      const name = describeColor(red, green, blue);
      const text = alpha < 1 ? `${value} (${name}), alfa ${alpha}` : `${value} (${name})`;

      return { text, value };
    }

    function backgroundFor(element) {
      for (let node = element; node; node = node.parentElement) {
        const color = window.getComputedStyle(node).backgroundColor;

        if (color && color !== "transparent" && color !== "rgba(0, 0, 0, 0)") {
          return color;
        }
      }

      return window.getComputedStyle(document.body).backgroundColor || "rgb(255, 255, 255)";
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      return element.tagName.toLowerCase();
    }

    const seen = new Map();
    const textElements = Array.from(document.querySelectorAll("body *"))
      .filter((element) => isVisible(element))
      .filter((element) => normalized(element.innerText || element.textContent))
      .filter((element) => !Array.from(element.children).some((child) => normalized(child.innerText || child.textContent) === normalized(element.innerText || element.textContent)));

    textElements.forEach((element) => {
      const style = window.getComputedStyle(element);
      const tag = element.tagName.toLowerCase();
      const color = colorInfo(style.color);
      const backgroundColor = colorInfo(backgroundFor(element));
      const item = {
        tag,
        fontFamily: style.fontFamily,
        fontSize: style.fontSize,
        fontWeight: style.fontWeight,
        fontStyle: style.fontStyle,
        color: color.text,
        colorValue: color.value,
        backgroundColor: backgroundColor.text,
        backgroundColorValue: backgroundColor.value,
        sample: normalized(element.innerText || element.textContent).slice(0, 80),
        selector: selectorFor(element),
      };
      const key = [
        item.tag,
        item.fontFamily,
        item.fontSize,
        item.fontWeight,
        item.fontStyle,
        item.color,
        item.backgroundColor,
      ].join("|");

      if (!seen.has(key)) {
        seen.set(key, item);
      }
    });

    return Array.from(seen.values()).sort((a, b) => a.tag.localeCompare(b.tag));
  });
}

async function getCssOverview(page) {
  return page.evaluate(() => {
    const links = Array.from(document.querySelectorAll("link[rel~='stylesheet']")).map((link) => ({
      href: link.href || link.getAttribute("href") || "",
      media: link.media || "",
      disabled: link.disabled,
    }));
    const styleElements = document.querySelectorAll("style").length;
    const inlineStyles = document.querySelectorAll("[style]").length;
    let readableStyleSheets = 0;
    let blockedStyleSheets = 0;
    let ruleCount = 0;

    Array.from(document.styleSheets).forEach((sheet) => {
      try {
        ruleCount += sheet.cssRules.length;
        readableStyleSheets += 1;
      } catch {
        blockedStyleSheets += 1;
      }
    });

    const issues = [];

    if (inlineStyles > 0) {
      issues.push(`${inlineStyles} elementer bruker inline style-attributt.`);
    }

    if (blockedStyleSheets > 0) {
      issues.push(`${blockedStyleSheets} CSS-filer kunne ikke leses av nettleseren, ofte på grunn av CORS.`);
    }

    return {
      summary: {
        stylesheetLinks: links.length,
        styleElements,
        inlineStyles,
        readableStyleSheets,
        blockedStyleSheets,
        ruleCount,
      },
      stylesheets: links.slice(0, 50),
      issues,
    };
  });
}

function splitCssSelectorList(selectorText) {
  const selectors = [];
  let current = "";
  let quote = "";
  let parentheses = 0;
  let brackets = 0;

  for (const character of String(selectorText || "")) {
    if (quote) {
      current += character;

      if (character === quote) {
        quote = "";
      }

      continue;
    }

    if (character === "'" || character === '"') {
      quote = character;
      current += character;
      continue;
    }

    if (character === "(") parentheses += 1;
    if (character === ")") parentheses = Math.max(0, parentheses - 1);
    if (character === "[") brackets += 1;
    if (character === "]") brackets = Math.max(0, brackets - 1);

    if (character === "," && parentheses === 0 && brackets === 0) {
      selectors.push(current.trim());
      current = "";
      continue;
    }

    current += character;
  }

  if (current.trim()) {
    selectors.push(current.trim());
  }

  return selectors;
}

function cssSelectorMatchType(selectorText, searchSelector) {
  const normalizedSearch = String(searchSelector || "").replace(/\s+/g, " ").trim();
  const selectorParts = splitCssSelectorList(selectorText)
    .map((selector) => selector.replace(/\s+/g, " ").trim());

  if (selectorParts.includes(normalizedSearch)) {
    return "exact";
  }

  const escaped = normalizedSearch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  let pattern;

  if (/^[.#][-_a-zA-Z0-9]+$/.test(normalizedSearch)) {
    pattern = new RegExp(`${escaped}(?![-_a-zA-Z0-9])`);
  } else if (/^[-_a-zA-Z][-_a-zA-Z0-9]*$/.test(normalizedSearch)) {
    pattern = new RegExp(`(^|[\\s>+~,(])${escaped}(?=($|[\\s.#:[>+~),]))`, "i");
  }

  if (pattern ? pattern.test(selectorText) : selectorText.includes(normalizedSearch)) {
    return "related";
  }

  return "";
}

async function fetchCssForRuleSearch(startUrl, referer = "") {
  let currentUrl = startUrl;

  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    const validatedUrl = await validatePublicUrl(currentUrl);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);

    try {
      const response = await fetch(validatedUrl, {
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
          "Accept": "text/css,*/*;q=0.1",
          ...(referer ? { Referer: referer } : {}),
        },
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");

        if (!location) {
          throw new Error("CSS-filen omdirigerte uten en ny adresse.");
        }

        currentUrl = new URL(location, validatedUrl).href;
        continue;
      }

      if (!response.ok) {
        throw new Error(`CSS-filen svarte med HTTP ${response.status}.`);
      }

      const contentType = response.headers.get("content-type") || "";

      if (/text\/html|application\/xhtml\+xml/i.test(contentType)) {
        throw new Error("Adressen returnerte HTML i stedet for CSS.");
      }

      const declaredLength = Number(response.headers.get("content-length") || 0);

      if (declaredLength > 2_000_000) {
        throw new Error("CSS-filen er større enn 2 MB.");
      }

      const text = await response.text();

      if (Buffer.byteLength(text, "utf8") > 2_000_000) {
        throw new Error("CSS-filen er større enn 2 MB.");
      }

      return { url: response.url || validatedUrl, text };
    } finally {
      clearTimeout(timeout);
    }
  }

  throw new Error("CSS-filen har for mange omdirigeringer.");
}

function parseCssRulesFromText(cssText, sourceUrl, searchSelector) {
  const rules = [];
  const imports = [];
  let truncated = false;
  let ast;

  try {
    ast = csstree.parse(cssText, {
      positions: true,
      filename: sourceUrl,
      parseValue: false,
    });
  } catch (error) {
    return {
      rules,
      imports,
      error: `CSS-parseren kunne ikke lese filen: ${String(error.message || error)}`,
    };
  }

  function walkNodes(children, conditions = []) {
    if (!children) {
      return;
    }

    children.forEach((node) => {
      if (node.type === "Atrule" && String(node.name).toLowerCase() === "import" && node.prelude) {
        let importValue = "";

        csstree.walk(node.prelude, (part) => {
          if (!importValue && (part.type === "Url" || part.type === "String")) {
            importValue = part.value || "";
          }
        });

        if (importValue) {
          try {
            imports.push(new URL(importValue, sourceUrl).href);
          } catch {
          }
        }
      }

      if (node.type === "Atrule" && node.block?.children) {
        const prelude = node.prelude ? csstree.generate(node.prelude) : "";
        const condition = `@${node.name}${prelude ? ` ${prelude}` : ""}`;
        walkNodes(node.block.children, [...conditions, condition]);
        return;
      }

      if (node.type !== "Rule" || !node.prelude) {
        return;
      }

      const selectorText = csstree.generate(node.prelude);
      const matchType = cssSelectorMatchType(selectorText, searchSelector);

      if (matchType) {
        const declarations = [];

        if (node.block?.children) {
          node.block.children.forEach((child) => {
            if (child.type === "Declaration") {
              declarations.push({
                property: child.property || "",
                value: child.value ? csstree.generate(child.value) : "",
                priority: child.important ? "important" : "",
              });
            }
          });
        }

        if (rules.length >= 250) {
          truncated = true;
          return;
        }

        rules.push({
          selector: selectorText,
          matchType,
          cssText: csstree.generate(node),
          declarations,
          source: sourceUrl,
          sourceType: "ekstern CSS lest av serveren",
          line: node.loc?.start?.line || 0,
          column: node.loc?.start?.column || 0,
          conditions,
          active: null,
          elementCount: null,
          order: 0,
        });
      }

      if (node.block?.children) {
        const nestedRules = [];

        node.block.children.forEach((child) => {
          if (child.type === "Rule" || child.type === "Atrule") {
            nestedRules.push(child);
          }
        });

        if (nestedRules.length) {
          walkNodes(nestedRules, conditions);
        }
      }
    });
  }

  walkNodes(ast.children);

  return { rules, imports: Array.from(new Set(imports)), error: "", truncated };
}

async function getCssRules(page, selector) {
  const browserResult = await page.evaluate((searchSelector) => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function splitSelectorList(selectorText) {
      const selectors = [];
      let current = "";
      let quote = "";
      let parentheses = 0;
      let brackets = 0;

      for (const character of String(selectorText || "")) {
        if (quote) {
          current += character;
          if (character === quote) quote = "";
          continue;
        }

        if (character === "'" || character === '"') {
          quote = character;
          current += character;
          continue;
        }

        if (character === "(") parentheses += 1;
        if (character === ")") parentheses = Math.max(0, parentheses - 1);
        if (character === "[") brackets += 1;
        if (character === "]") brackets = Math.max(0, brackets - 1);

        if (character === "," && parentheses === 0 && brackets === 0) {
          selectors.push(current.trim());
          current = "";
          continue;
        }

        current += character;
      }

      if (current.trim()) selectors.push(current.trim());
      return selectors;
    }

    function matchTypeFor(selectorText) {
      const normalizedSearch = normalized(searchSelector);
      const selectorParts = splitSelectorList(selectorText).map(normalized);

      if (selectorParts.includes(normalizedSearch)) {
        return "exact";
      }

      const escaped = normalizedSearch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      let pattern;

      if (/^[.#][-_a-zA-Z0-9]+$/.test(normalizedSearch)) {
        pattern = new RegExp(`${escaped}(?![-_a-zA-Z0-9])`);
      } else if (/^[-_a-zA-Z][-_a-zA-Z0-9]*$/.test(normalizedSearch)) {
        pattern = new RegExp(`(^|[\\s>+~,(])${escaped}(?=($|[\\s.#:[>+~),]))`, "i");
      }

      return (pattern ? pattern.test(selectorText) : selectorText.includes(normalizedSearch))
        ? "related"
        : "";
    }

    function queryCount(root, selectorText) {
      try {
        return root.querySelectorAll(selectorText).length;
      } catch {
        return null;
      }
    }

    function conditionFor(rule) {
      const name = rule.constructor?.name || "";
      const text = rule.conditionText || rule.name || "";
      let active = null;

      if (name === "CSSMediaRule") {
        active = window.matchMedia(rule.conditionText).matches;
      } else if (name === "CSSSupportsRule") {
        try {
          active = CSS.supports(rule.conditionText);
        } catch {
          active = null;
        }
      } else if (/CSSLayer|CSSScope|CSSContainer/i.test(name)) {
        active = true;
      }

      return {
        type: name.replace(/^CSS|Rule$/g, "") || "gruppe",
        text,
        active,
      };
    }

    function sourceFor(sheet, index, scopeName) {
      if (sheet.href) return sheet.href;
      if (sheet.ownerNode?.tagName?.toLowerCase() === "style") {
        const id = sheet.ownerNode.id ? `#${sheet.ownerNode.id}` : "";
        return `style-element ${index + 1}${id}${scopeName ? ` i ${scopeName}` : ""}`;
      }
      return `adopted stylesheet ${index + 1}${scopeName ? ` i ${scopeName}` : ""}`;
    }

    const result = {
      selector: normalized(searchSelector),
      elementCount: 0,
      selectorValidForElements: true,
      rules: [],
      readableStyleSheets: 0,
      blockedStyleSheets: [],
      styleSheetCount: 0,
      truncated: false,
    };

    try {
      result.elementCount = document.querySelectorAll(searchSelector).length;
    } catch {
      result.selectorValidForElements = false;
    }

    const sheetEntries = [];
    const seenSheets = new WeakSet();
    let ruleOrder = 0;

    function addSheet(sheet, root, scopeName) {
      if (!sheet || seenSheets.has(sheet)) return;
      seenSheets.add(sheet);
      sheetEntries.push({ sheet, root, scopeName });
    }

    Array.from(document.styleSheets).forEach((sheet) => addSheet(sheet, document, ""));
    Array.from(document.adoptedStyleSheets || []).forEach((sheet) => addSheet(sheet, document, "document"));

    Array.from(document.querySelectorAll("*")).forEach((host) => {
      if (!host.shadowRoot) return;
      const scopeName = host.id ? `shadow DOM #${host.id}` : `shadow DOM ${host.tagName.toLowerCase()}`;
      Array.from(host.shadowRoot.querySelectorAll("style, link[rel~='stylesheet']")).forEach((node) => {
        if (node.sheet) addSheet(node.sheet, host.shadowRoot, scopeName);
      });
      Array.from(host.shadowRoot.adoptedStyleSheets || []).forEach((sheet) => addSheet(sheet, host.shadowRoot, scopeName));
    });

    function walkRules(rules, entry, conditions = []) {
      Array.from(rules || []).forEach((rule) => {
        ruleOrder += 1;

        if (typeof rule.selectorText === "string") {
          const matchType = matchTypeFor(rule.selectorText);

          if (matchType && result.rules.length < 200) {
            const declarations = rule.style
              ? Array.from(rule.style).map((property) => ({
                  property,
                  value: rule.style.getPropertyValue(property).trim(),
                  priority: rule.style.getPropertyPriority(property),
                }))
              : [];

            result.rules.push({
              selector: rule.selectorText,
              matchType,
              cssText: rule.cssText || "",
              declarations,
              source: sourceFor(entry.sheet, entry.index, entry.scopeName),
              sourceType: entry.sheet.href ? "ekstern CSS lest av nettleseren" : "CSS i dokumentet",
              line: 0,
              column: 0,
              conditions,
              active: !entry.sheet.disabled && conditions.every((condition) => condition.active !== false),
              elementCount: queryCount(entry.root, rule.selectorText),
              order: ruleOrder,
            });
          } else if (matchType) {
            result.truncated = true;
          }
        }

        if (rule.styleSheet) {
          try {
            walkRules(rule.styleSheet.cssRules, { ...entry, sheet: rule.styleSheet }, [
              ...conditions,
              { type: "import", text: rule.media?.mediaText || "", active: true },
            ]);
          } catch {
          }
        } else if (rule.cssRules) {
          const condition = conditionFor(rule);
          walkRules(rule.cssRules, entry, [...conditions, condition]);
        }
      });
    }

    sheetEntries.forEach((entry, index) => {
      entry.index = index;
      result.styleSheetCount += 1;

      try {
        const cssRules = entry.sheet.cssRules;
        result.readableStyleSheets += 1;
        const sheetConditions = entry.sheet.media?.mediaText
          ? [{
              type: "media",
              text: entry.sheet.media.mediaText,
              active: window.matchMedia(entry.sheet.media.mediaText).matches,
            }]
          : [];
        walkRules(cssRules, entry, sheetConditions);
      } catch {
        result.blockedStyleSheets.push({
          href: entry.sheet.href || "",
          source: sourceFor(entry.sheet, index, entry.scopeName),
        });
      }
    });

    return result;
  }, selector);

  const fallbackRules = [];
  const fallbackErrors = [];
  let fallbackTruncated = false;
  const fetched = new Set();
  const successfullyFetched = new Set();
  const queue = browserResult.blockedStyleSheets
    .map((sheet) => sheet.href)
    .filter(Boolean)
    .slice(0, 20);
  let totalFetchedBytes = 0;

  while (queue.length && fetched.size < 30 && totalFetchedBytes < 8_000_000) {
    const href = queue.shift();

    if (!href || fetched.has(href)) {
      continue;
    }

    fetched.add(href);

    try {
      const fetchedCss = await fetchCssForRuleSearch(href, page.url());
      successfullyFetched.add(href);
      totalFetchedBytes += Buffer.byteLength(fetchedCss.text, "utf8");
      const parsed = parseCssRulesFromText(fetchedCss.text, fetchedCss.url, selector);
      fallbackTruncated = fallbackTruncated || parsed.truncated;

      if (parsed.error) {
        fallbackErrors.push(`${fetchedCss.url}: ${parsed.error}`);
      }

      parsed.rules.forEach((rule) => {
        if (fallbackRules.length < 200) {
          fallbackRules.push(rule);
        }
      });

      parsed.imports.forEach((importUrl) => {
        if (!fetched.has(importUrl) && queue.length < 30) {
          queue.push(importUrl);
        }
      });
    } catch (error) {
      fallbackErrors.push(`${href}: ${friendlyErrorMessage(error, "CSS-filen kunne ikke hentes.")}`);
    }
  }

  const combinedRules = [...browserResult.rules, ...fallbackRules]
    .map((rule, index) => ({ ...rule, order: rule.order || browserResult.rules.length + index + 1 }))
    .sort((a, b) => a.order - b.order);
  const rules = combinedRules.slice(0, 200);
  const resolvedBlocked = browserResult.blockedStyleSheets
    .filter((sheet) => successfullyFetched.has(sheet.href))
    .length;

  return {
    selector: browserResult.selector,
    elementCount: browserResult.elementCount,
    selectorValidForElements: browserResult.selectorValidForElements,
    rules,
    exactCount: rules.filter((rule) => rule.matchType === "exact").length,
    relatedCount: rules.filter((rule) => rule.matchType === "related").length,
    styleSheetCount: browserResult.styleSheetCount,
    readableStyleSheets: browserResult.readableStyleSheets,
    blockedStyleSheets: browserResult.blockedStyleSheets.length,
    serverReadStyleSheets: successfullyFetched.size,
    unresolvedBlocked: Math.max(0, browserResult.blockedStyleSheets.length - resolvedBlocked),
    truncated: browserResult.truncated || fallbackTruncated || combinedRules.length > rules.length,
    errors: fallbackErrors.slice(0, 20),
  };
}

async function getCssHidden(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) return `#${CSS.escape(element.id)}`;
      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function isFocusable(element) {
      return element.matches("a[href], button, input, select, textarea, summary, [tabindex]");
    }

    const items = [];

    Array.from(document.body.querySelectorAll("*")).forEach((element) => {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();
      const reasons = [];

      if (element.hasAttribute("hidden")) reasons.push("hidden-attributt");
      if (element.getAttribute("aria-hidden") === "true") reasons.push("aria-hidden");
      if (style.display === "none") reasons.push("display:none");
      if (style.visibility === "hidden" || style.visibility === "collapse") reasons.push(`visibility:${style.visibility}`);
      if (Number(style.opacity) === 0) reasons.push("opacity:0");
      if (style.clip !== "auto" || style.clipPath !== "none") reasons.push("clip/clip-path");
      if (rect.width === 1 && rect.height === 1 && style.position === "absolute") reasons.push("typisk visuelt skjult 1x1");
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth + 5000 || rect.top > window.innerHeight + 5000) {
        reasons.push("plassert utenfor synlig område");
      }

      if (!reasons.length) {
        return;
      }

      items.push({
        element: element.tagName.toLowerCase(),
        selector: selectorFor(element),
        text: normalized(element.innerText || element.textContent).slice(0, 120),
        focusable: isFocusable(element) || Boolean(element.querySelector("a[href], button, input, select, textarea, summary, [tabindex]")),
        reasons,
      });
    });

    return {
      total: items.length,
      items: items.slice(0, 120),
      truncated: items.length > 120,
    };
  });
}

async function getCssFocusStyles(page) {
  function changed(before, after) {
    return Object.keys(before).filter((key) => before[key] !== after[key]);
  }

  function focusEvidence(before, after) {
    const outlineVisible = after.outlineStyle !== "none" && after.outlineWidth !== "0px";
    const boxShadowVisible = after.boxShadow !== "none" && after.boxShadow !== before.boxShadow;
    const borderChanged =
      after.borderColor !== before.borderColor ||
      after.borderWidth !== before.borderWidth ||
      after.borderStyle !== before.borderStyle;
    const backgroundChanged = after.backgroundColor !== before.backgroundColor;
    const colorChanged = after.color !== before.color;
    const textDecorationChanged = after.textDecorationLine !== before.textDecorationLine && after.textDecorationLine !== "none";
    const evidence = [];

    if (outlineVisible) evidence.push("outline");
    if (boxShadowVisible) evidence.push("box-shadow");
    if (borderChanged) evidence.push("border");
    if (backgroundChanged) evidence.push("bakgrunnsfarge");
    if (colorChanged) evidence.push("tekstfarge");
    if (textDecorationChanged) evidence.push("tekstdekorasjon");

    return evidence;
  }

  const initial = await page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) return `#${CSS.escape(element.id)}`;
      return element.tagName.toLowerCase();
    }

    function visible(element) {
      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);
      return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    }

    function snapshot(element) {
      const style = window.getComputedStyle(element);
      return {
        color: style.color,
        outlineStyle: style.outlineStyle,
        outlineWidth: style.outlineWidth,
        outlineColor: style.outlineColor,
        boxShadow: style.boxShadow,
        borderStyle: style.borderStyle,
        borderWidth: style.borderWidth,
        borderColor: style.borderColor,
        backgroundColor: style.backgroundColor,
        textDecorationLine: style.textDecorationLine,
      };
    }

    const elements = Array.from(document.querySelectorAll("a[href], button, input, select, textarea, summary, [tabindex]"))
      .filter((element) => visible(element) && !element.disabled)
      .slice(0, 80);
    const items = elements.map((element, index) => {
      const id = `wq-focus-${index}`;
      element.setAttribute("data-webquest-focus-id", id);

      return {
        id,
        element: element.tagName.toLowerCase(),
        selector: selectorFor(element),
        text: normalized(element.innerText || element.value || element.getAttribute("aria-label") || element.textContent).slice(0, 100),
        before: snapshot(element),
      };
    });

    document.body.setAttribute("tabindex", "-1");
    document.body.focus({ preventScroll: true });

    return {
      items,
      truncated: document.querySelectorAll("a[href], button, input, select, textarea, summary, [tabindex]").length > 80,
    };
  });

  const focusedByKeyboard = new Map();
  const maxTabs = Math.min(Math.max(initial.items.length + 10, 20), 120);

  for (let index = 0; index < maxTabs; index += 1) {
    await page.keyboard.press("Tab");
    await new Promise((resolve) => setTimeout(resolve, 40));

    const active = await page.evaluate(() => {
      function snapshot(element) {
        const style = window.getComputedStyle(element);
        return {
          color: style.color,
          outlineStyle: style.outlineStyle,
          outlineWidth: style.outlineWidth,
          outlineColor: style.outlineColor,
          boxShadow: style.boxShadow,
          borderStyle: style.borderStyle,
          borderWidth: style.borderWidth,
          borderColor: style.borderColor,
          backgroundColor: style.backgroundColor,
          textDecorationLine: style.textDecorationLine,
        };
      }

      const element = document.activeElement?.closest?.("[data-webquest-focus-id]");

      if (!element) {
        return null;
      }

      return {
        id: element.getAttribute("data-webquest-focus-id"),
        after: snapshot(element),
      };
    });

    if (active?.id && !focusedByKeyboard.has(active.id)) {
      focusedByKeyboard.set(active.id, active.after);
    }
  }

  const fallback = await page.evaluate(async (ids) => {
    function snapshot(element) {
      const style = window.getComputedStyle(element);
      return {
        color: style.color,
        outlineStyle: style.outlineStyle,
        outlineWidth: style.outlineWidth,
        outlineColor: style.outlineColor,
        boxShadow: style.boxShadow,
        borderStyle: style.borderStyle,
        borderWidth: style.borderWidth,
        borderColor: style.borderColor,
        backgroundColor: style.backgroundColor,
        textDecorationLine: style.textDecorationLine,
      };
    }

    const results = {};

    for (const id of ids) {
      const element = document.querySelector(`[data-webquest-focus-id="${CSS.escape(id)}"]`);

      if (!element) {
        continue;
      }

      element.focus({ preventScroll: true });
      await new Promise((resolve) => requestAnimationFrame(resolve));
      results[id] = snapshot(element);
    }

    return results;
  }, initial.items.filter((item) => !focusedByKeyboard.has(item.id)).map((item) => item.id));

  const items = initial.items.map((item) => {
    const keyboardAfter = focusedByKeyboard.get(item.id);
    const after = keyboardAfter || fallback[item.id] || item.before;
    const visibleFocusEvidence = focusEvidence(item.before, after);

    return {
      element: item.element,
      selector: item.selector,
      text: item.text,
      hasVisibleFocus: visibleFocusEvidence.length > 0,
      visibleFocusEvidence,
      focusMethod: keyboardAfter ? "tastatur" : "programmatisk reserve",
      changedProperties: changed(item.before, after),
      outline: `${after.outlineWidth} ${after.outlineStyle} ${after.outlineColor}`,
      boxShadow: after.boxShadow,
      color: after.color,
      backgroundColor: after.backgroundColor,
    };
  });

  const missing = items.filter((item) => !item.hasVisibleFocus).length;

  return {
    checked: items.length,
    missing,
    items,
    truncated: initial.truncated,
  };
}

async function getCssResponsive(page, url) {
  const viewports = [
    { name: "mobil smal", width: 320, height: 800 },
    { name: "mobil", width: 390, height: 844 },
    { name: "nettbrett", width: 768, height: 900 },
    { name: "desktop", width: 1366, height: 900 },
  ];
  const results = [];

  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await gotoForAnalysis(page, url, 30000);
    results.push(await page.evaluate((viewportName) => {
      function normalized(text) {
        return String(text || "").replace(/\s+/g, " ").trim();
      }

      const overflowing = Array.from(document.querySelectorAll("body *"))
        .map((element) => {
          const rect = element.getBoundingClientRect();
          return {
            element: element.tagName.toLowerCase(),
            selector: element.id ? `#${CSS.escape(element.id)}` : element.tagName.toLowerCase(),
            text: normalized(element.innerText || element.textContent).slice(0, 80),
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          };
        })
        .filter((item) => item.width > 0 && (item.right > window.innerWidth + 1 || item.left < -1))
        .slice(0, 30);

      return {
        name: viewportName,
        width: window.innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
        horizontalScroll: document.documentElement.scrollWidth > window.innerWidth + 1 || document.body.scrollWidth > window.innerWidth + 1,
        overflowing,
      };
    }, viewport.name));
  }

  return { viewports: results };
}

async function getCssColors(page) {
  return page.evaluate(() => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function parseColor(value) {
      const text = String(value || "").trim();

      if (!text || text === "transparent") {
        return null;
      }

      const match = text.match(/rgba?\(([^)]+)\)/i);

      if (!match) {
        return null;
      }

      const parts = match[1].split(",").map((part) => part.trim());
      const red = Number(parts[0]);
      const green = Number(parts[1]);
      const blue = Number(parts[2]);
      const alpha = parts[3] === undefined ? 1 : Number(parts[3]);

      if (![red, green, blue, alpha].every(Number.isFinite)) {
        return null;
      }

      return {
        r: Math.max(0, Math.min(255, red)),
        g: Math.max(0, Math.min(255, green)),
        b: Math.max(0, Math.min(255, blue)),
        a: Math.max(0, Math.min(1, alpha)),
      };
    }

    function blend(top, bottom) {
      const alpha = top.a + bottom.a * (1 - top.a);

      if (alpha === 0) {
        return { r: 255, g: 255, b: 255, a: 1 };
      }

      return {
        r: Math.round((top.r * top.a + bottom.r * bottom.a * (1 - top.a)) / alpha),
        g: Math.round((top.g * top.a + bottom.g * bottom.a * (1 - top.a)) / alpha),
        b: Math.round((top.b * top.a + bottom.b * bottom.a * (1 - top.a)) / alpha),
        a: alpha,
      };
    }

    function describeColor(red, green, blue) {
      const r = Math.max(0, Math.min(255, Math.round(red))) / 255;
      const g = Math.max(0, Math.min(255, Math.round(green))) / 255;
      const b = Math.max(0, Math.min(255, Math.round(blue))) / 255;
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      const delta = max - min;
      const lightness = (max + min) / 2;
      const saturation = delta === 0 ? 0 : delta / (1 - Math.abs(2 * lightness - 1));
      let hue = 0;

      if (delta !== 0) {
        if (max === r) {
          hue = ((g - b) / delta) % 6;
        } else if (max === g) {
          hue = (b - r) / delta + 2;
        } else {
          hue = (r - g) / delta + 4;
        }

        hue = Math.round(hue * 60);
        if (hue < 0) {
          hue += 360;
        }
      }

      if (lightness <= 0.04) {
        return "svart";
      }

      if (lightness >= 0.97 && saturation <= 0.12) {
        return "hvit";
      }

      if (saturation <= 0.08) {
        const tone = red > blue + 8 ? "varm " : blue > red + 8 ? "kald " : "nøytral ";
        if (lightness >= 0.92) return "nesten hvit";
        if (lightness >= 0.78) return `svært lys ${tone}grå`;
        if (lightness >= 0.62) return `lys ${tone}grå`;
        if (lightness >= 0.42) return `${tone}grå`;
        if (lightness >= 0.20) return `mørk ${tone}grå`;
        return "nesten svart";
      }

      const hueNames = [
        [12, "rød"],
        [28, "rødoransje"],
        [45, "oransje"],
        [65, "guloransje"],
        [85, "gul"],
        [145, "gulgrønn"],
        [170, "grønn"],
        [195, "blågrønn"],
        [215, "turkis"],
        [245, "blå"],
        [275, "blåfiolett"],
        [305, "lilla"],
        [330, "fiolett"],
        [345, "magentarød"],
        [360, "rød"],
      ];
      let hueName = hueNames.find(([limit]) => hue <= limit)?.[1] || "rød";

      if (hue >= 18 && hue <= 55 && saturation >= 0.20 && lightness < 0.43) {
        hueName = "brun";
      } else if (hue >= 35 && hue <= 75 && saturation < 0.45 && lightness >= 0.62) {
        hueName = "beige";
      } else if ((hue >= 330 || hue <= 12) && lightness >= 0.68 && saturation < 0.75) {
        hueName = "rosa";
      }

      const modifiers = [];
      if (lightness >= 0.90) modifiers.push("svært lys");
      else if (lightness >= 0.72) modifiers.push("lys");
      else if (lightness <= 0.16) modifiers.push("svært mørk");
      else if (lightness <= 0.34) modifiers.push("mørk");

      if (saturation <= 0.22) modifiers.push("svakt mettet");
      else if (saturation <= 0.42) modifiers.push("dempet");
      else if (saturation >= 0.78) modifiers.push("klar");

      return [...modifiers, hueName].join(" ");
    }

    function colorText(color) {
      const red = Math.round(color.r);
      const green = Math.round(color.g);
      const blue = Math.round(color.b);
      const hex = [red, green, blue]
        .map((value) => Math.max(0, Math.min(255, Math.round(value))).toString(16).padStart(2, "0"))
        .join("");
      const name = describeColor(red, green, blue);

      return `#${hex} (${name})`;
    }

    function effectiveBackground(element) {
      let background = { r: 255, g: 255, b: 255, a: 1 };
      const colors = [];

      for (let node = element; node; node = node.parentElement) {
        const color = parseColor(window.getComputedStyle(node).backgroundColor);

        if (color && color.a > 0) {
          colors.push(color);
        }
      }

      colors.reverse().forEach((color) => {
        background = blend(color, background);
      });

      return background;
    }

    function visible(element) {
      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);
      return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
    }

    const map = new Map();

    Array.from(document.body.querySelectorAll("*"))
      .filter((element) => visible(element) && normalized(element.innerText || element.textContent))
      .forEach((element) => {
        const style = window.getComputedStyle(element);
        const background = effectiveBackground(element);
        const foreground = parseColor(style.color);

        if (!foreground || foreground.a === 0) {
          return;
        }

        const effectiveForeground = blend(foreground, background);
        const foregroundText = colorText(effectiveForeground);
        const backgroundText = colorText(background);
        const key = `${foregroundText}|${backgroundText}`;

        if (!map.has(key)) {
          map.set(key, {
            color: foregroundText,
            backgroundColor: backgroundText,
            count: 0,
            examples: [],
          });
        }

        const item = map.get(key);
        item.count += 1;

        if (item.examples.length < 3) {
          item.examples.push(`${element.tagName.toLowerCase()}: ${normalized(element.innerText || element.textContent).slice(0, 60)}`);
        }
      });

    return Array.from(map.values()).sort((a, b) => b.count - a.count).slice(0, 80);
  });
}

async function getCssVariables(page) {
  return page.evaluate(() => {
    const variables = new Map();

    Array.from(document.styleSheets).forEach((sheet) => {
      let rules = [];

      try {
        rules = Array.from(sheet.cssRules || []);
      } catch {
        return;
      }

      rules.forEach((rule) => {
        const style = rule.style;

        if (!style) {
          return;
        }

        Array.from(style).forEach((property) => {
          if (!property.startsWith("--")) {
            return;
          }

          if (!variables.has(property)) {
            variables.set(property, {
              name: property,
              value: style.getPropertyValue(property).trim(),
              count: 0,
              selectors: [],
            });
          }

          const item = variables.get(property);
          item.count += 1;

          if (item.selectors.length < 5 && rule.selectorText) {
            item.selectors.push(rule.selectorText);
          }
        });
      });
    });

    return Array.from(variables.values()).sort((a, b) => a.name.localeCompare(b.name)).slice(0, 200);
  });
}

async function getCssElement(page, selector) {
  return page.evaluate((selectorValue) => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    let matches;

    try {
      matches = document.querySelectorAll(selectorValue);
    } catch {
      return {
        selector: selectorValue,
        count: 0,
        items: [],
        error: "Ugyldig CSS-selector.",
      };
    }

    const elements = Array.from(matches).slice(0, 20);
    const properties = [
      "display", "position", "zIndex", "boxSizing", "width", "height", "margin", "padding",
      "fontFamily", "fontSize", "fontWeight", "lineHeight", "color", "backgroundColor",
      "border", "outline", "boxShadow", "overflow", "overflowX", "overflowY",
      "visibility", "opacity", "clipPath",
    ];

    return {
      selector: selectorValue,
      count: matches.length,
      items: elements.map((element) => {
        const style = window.getComputedStyle(element);
        const computed = {};

        properties.forEach((property) => {
          computed[property] = style[property];
        });

        return {
          element: element.tagName.toLowerCase(),
          id: element.id || "",
          classes: typeof element.className === "string" ? element.className : "",
          text: normalized(element.innerText || element.textContent).slice(0, 120),
          computed,
        };
      }),
    };
  }, selector);
}

async function getElementExtracts(page, selector) {
  const result = await page.evaluate((selectorValue) => {
    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 5; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    let matches;

    try {
      matches = document.querySelectorAll(selectorValue);
    } catch {
      return {
        selector: selectorValue,
        count: 0,
        items: [],
        error: "Ugyldig CSS-selector.",
      };
    }

    const items = Array.from(matches).slice(0, 10).map((element, index) => {
      const rect = element.getBoundingClientRect();
      const style = window.getComputedStyle(element);

      return {
        index,
        element: element.tagName.toLowerCase(),
        id: element.id || "",
        classes: typeof element.className === "string" ? element.className : "",
        text: normalized(element.innerText || element.textContent).slice(0, 250),
        selector: selectorFor(element),
        html: element.outerHTML.slice(0, 2500),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
        visible: rect.width > 0 &&
          rect.height > 0 &&
          style.display !== "none" &&
          style.visibility !== "hidden" &&
          style.visibility !== "collapse",
      };
    });

    return {
      selector: selectorValue,
      count: matches.length,
      items,
      truncated: matches.length > items.length,
    };
  }, selector);

  if (result.error) {
    return result;
  }

  for (const item of result.items) {
    if (!item.visible) {
      item.screenshotError = "Elementet er skjult eller har ingen synlig størrelse.";
      continue;
    }

    try {
      const locator = page.locator(selector).nth(item.index);
      await locator.scrollIntoViewIfNeeded({ timeout: 3000 });
      const buffer = await locator.screenshot({ type: "png", timeout: 5000 });
      item.imageDataUrl = `data:image/png;base64,${buffer.toString("base64")}`;
    } catch {
      item.screenshotError = "Kunne ikke lage skjermbilde av elementet.";
    }
  }

  return result;
}

async function getWcag(page) {
  await page.addScriptTag({ content: axe.source });

  return page.evaluate(async () => {
    function wcagLevels(tags) {
      const levels = new Set();

      tags.forEach((tag) => {
        if (tag === "wcag2a" || tag === "wcag21a" || tag === "wcag22a") levels.add("A");
        if (tag === "wcag2aa" || tag === "wcag21aa" || tag === "wcag22aa") levels.add("AA");
        if (tag === "wcag2aaa" || tag === "wcag21aaa" || tag === "wcag22aaa") levels.add("AAA");
      });

      if (levels.size === 0 && tags.includes("best-practice")) {
        levels.add("Best practice");
      }

      if (levels.size === 0) {
        levels.add("Ukjent");
      }

      return Array.from(levels);
    }

    function selectorForNode(node) {
      return (node.target || []).join(", ");
    }

    function simplifyRule(rule) {
      return {
        id: rule.id,
        impact: rule.impact || "",
        help: rule.help || "",
        description: rule.description || "",
        helpUrl: rule.helpUrl || "",
        tags: rule.tags || [],
        levels: wcagLevels(rule.tags || []),
        count: (rule.nodes || []).length,
        examples: (rule.nodes || []).slice(0, 3).map((node) => ({
          target: selectorForNode(node),
          summary: node.failureSummary || node.any?.[0]?.message || node.none?.[0]?.message || "",
        })),
      };
    }

    const results = await window.axe.run(document, {
      resultTypes: ["violations", "incomplete", "passes"],
      runOnly: {
        type: "tag",
        values: [
          "wcag2a",
          "wcag2aa",
          "wcag2aaa",
          "wcag21a",
          "wcag21aa",
          "wcag21aaa",
          "wcag22a",
          "wcag22aa",
          "wcag22aaa",
          "best-practice",
        ],
      },
    });
    const violations = results.violations.map(simplifyRule);
    const incomplete = results.incomplete.map(simplifyRule);
    const passes = results.passes.map(simplifyRule);
    const groups = {};

    ["A", "AA", "AAA", "Best practice", "Ukjent"].forEach((level) => {
      groups[level] = violations.filter((rule) => rule.levels.includes(level));
    });

    return {
      summary: {
        violations: violations.length,
        incomplete: incomplete.length,
        passes: passes.length,
      },
      groups,
      incomplete,
    };
  });
}

async function getSource(url) {
  const response = await fetch(url, {
    method: "GET",
    redirect: "follow",
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
    },
  });

  if (!response.ok) {
    throw new Error(`Kildekoden kunne ikke hentes. HTTP ${response.status}.`);
  }

  return response.text();
}

function normalizeEmail(value) {
  const cleaned = String(value || "")
    .replace(/^mailto:/i, "")
    .split("?")[0]
    .replace(/[<>()\[\],;:]+$/g, "")
    .replace(/\s+/g, " ")
    .trim();

  try {
    return decodeURIComponent(cleaned);
  } catch {
    return cleaned;
  }
}

function stripHtmlText(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&#64;|&commat;/gi, "@")
    .replace(/\s+/g, " ")
    .trim();
}

function stripTags(html) {
  return stripHtmlText(html);
}

function decodeHtmlEntities(text) {
  return String(text || "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, code) => {
      const value = Number(code);
      return Number.isFinite(value) ? String.fromCodePoint(value) : "";
    })
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => {
      const value = Number.parseInt(code, 16);
      return Number.isFinite(value) ? String.fromCodePoint(value) : "";
    });
}

function attributesFromHtml(tag) {
  const attributes = {};
  const source = String(tag || "");
  const pattern = /([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let match;

  while ((match = pattern.exec(source))) {
    const name = match[1].toLowerCase();

    if (name === source.split(/\s+/)[0]?.replace(/^</, "").toLowerCase()) {
      continue;
    }

    attributes[name] = decodeHtmlEntities(match[2] ?? match[3] ?? match[4] ?? "");
  }

  return attributes;
}

function absoluteUrl(value, baseUrl) {
  const raw = String(value || "").trim();

  if (!raw) {
    return "";
  }

  try {
    return new URL(raw, baseUrl).href;
  } catch {
    return raw;
  }
}

function extractEmailsFromHtml(html, pageUrl) {
  const source = String(html || "");
  const emailPattern = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  const results = [];
  const seen = new Set();

  function addEmail(item) {
    const email = normalizeEmail(item.email);

    if (!email || !/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(email)) {
      return;
    }

    const key = `${email.toLowerCase()}|${item.source}|${item.pageUrl}`;

    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    results.push({
      source: item.source,
      linkText: item.linkText || "",
      nameSource: item.nameSource || "",
      email,
      href: item.href || "",
      selector: item.selector || "",
      pageUrl,
    });
  }

  const mailtoPattern = /<a\b[^>]*\bhref\s*=\s*(["'])\s*mailto:([\s\S]*?)\1[^>]*>([\s\S]*?)<\/a>/gi;

  for (const match of source.matchAll(mailtoPattern)) {
    const href = `mailto:${match[2] || ""}`;
    const linkText = stripHtmlText(match[3] || "");
    const addresses = normalizeEmail(href).split(/[;,]/).map(normalizeEmail).filter(Boolean);

    addresses.forEach((email) => addEmail({
      source: "mailto",
      linkText,
      nameSource: linkText ? "innhold" : "",
      email,
      href,
    }));
  }

  const textWithoutMailtoLinks = source.replace(mailtoPattern, " ");
  const text = stripHtmlText(textWithoutMailtoLinks);

  for (const match of text.matchAll(emailPattern)) {
    addEmail({
      source: "tekst",
      email: match[0],
    });
  }

  return results;
}

function providerFromUrl(url) {
  const value = String(url || "");

  if (/youtube(?:-nocookie)?\.com|youtu\.be/i.test(value)) return "YouTube";
  if (/vimeo\.com/i.test(value)) return "Vimeo";
  if (/player\.vimeo\.com/i.test(value)) return "Vimeo";
  if (/facebook\.com\/plugins\/video|fb\.watch/i.test(value)) return "Facebook";
  if (/wistia\.com|wistia\.net/i.test(value)) return "Wistia";
  if (/kaltura/i.test(value)) return "Kaltura";
  if (/brightcove|bcove/i.test(value)) return "Brightcove";
  if (/\.(mp4|webm|ogg|ogv|mov|m3u8)(?:[?#]|$)/i.test(value)) return "Videofil";
  return "";
}

function extractVideosFromHtml(html, pageUrl) {
  const source = String(html || "");
  const videos = [];
  const seen = new Set();

  function addVideo(item) {
    const src = String(item.src || "").trim();
    const title = stripTags(item.title || "");
    const key = `${item.type}|${src}|${title}`;

    if (!src && !title) {
      return;
    }

    if (seen.has(key)) {
      return;
    }

    seen.add(key);
    videos.push({
      type: item.type || "video",
      provider: item.provider || providerFromUrl(src) || "ukjent",
      title,
      src,
      pageUrl,
    });
  }

  for (const match of source.matchAll(/<video\b[\s\S]*?<\/video>|<video\b[^>]*>/gi)) {
    const block = match[0];
    const attrs = attributesFromHtml(block);
    const sources = [];

    if (attrs.src) {
      sources.push(attrs.src);
    }

    for (const sourceMatch of block.matchAll(/<source\b[^>]*>/gi)) {
      const sourceAttrs = attributesFromHtml(sourceMatch[0]);
      if (sourceAttrs.src) {
        sources.push(sourceAttrs.src);
      }
    }

    if (!sources.length) {
      sources.push("");
    }

    sources.forEach((src) => {
      const absoluteSrc = absoluteUrl(src, pageUrl);
      addVideo({
        type: "video",
        provider: providerFromUrl(absoluteSrc) || "HTML video",
        title: attrs.title || attrs["aria-label"] || attrs.poster || "",
        src: absoluteSrc,
      });
    });
  }

  for (const match of source.matchAll(/<(iframe|embed|object)\b[^>]*>/gi)) {
    const attrs = attributesFromHtml(match[0]);
    const rawSrc = attrs.src || attrs.data || "";
    const src = absoluteUrl(rawSrc, pageUrl);
    const provider = providerFromUrl(src);

    if (provider || /video|player|embed/i.test(src)) {
      addVideo({
        type: match[1].toLowerCase(),
        provider: provider || "embed",
        title: attrs.title || attrs["aria-label"] || "",
        src,
      });
    }
  }

  for (const match of source.matchAll(/https?:\/\/[^\s"'<>]+\.(?:mp4|webm|ogg|ogv|mov|m3u8)(?:[?#][^\s"'<>]*)?/gi)) {
    addVideo({
      type: "lenke",
      provider: "Videofil",
      title: "",
      src: match[0],
    });
  }

  return videos;
}

function extractTablesFromHtml(html, pageUrl) {
  return Array.from(String(html || "").matchAll(/<table\b[\s\S]*?<\/table>/gi)).map((match, index) => {
    const table = match[0];
    const captionMatch = table.match(/<caption\b[^>]*>([\s\S]*?)<\/caption>/i);
    const rows = (table.match(/<tr\b/gi) || []).length;
    const headerCells = (table.match(/<th\b/gi) || []).length;
    const firstRows = Array.from(table.matchAll(/<tr\b[\s\S]*?<\/tr>/gi)).slice(0, 8);
    const columns = firstRows.reduce((max, rowMatch) => {
      const count = (rowMatch[0].match(/<(?:td|th)\b/gi) || []).length;
      return Math.max(max, count);
    }, 0);

    return {
      pageUrl,
      index: index + 1,
      caption: captionMatch ? stripTags(captionMatch[1]) : "",
      rows,
      columns,
      headerCells,
      missingCaption: !captionMatch,
      missingScope: /<th\b(?![^>]*\bscope\s*=)/i.test(table),
      possibleLayout: headerCells === 0 && !captionMatch,
    };
  });
}

function extractFormsFromHtml(html, pageUrl) {
  return Array.from(String(html || "").matchAll(/<form\b[\s\S]*?<\/form>/gi)).map((match, index) => {
    const form = match[0];
    const attrs = attributesFromHtml(form);
    const fields = [];

    for (const fieldMatch of form.matchAll(/<(input|select|textarea|button)\b[^>]*>/gi)) {
      const tag = fieldMatch[1].toLowerCase();
      const fieldAttrs = attributesFromHtml(fieldMatch[0]);
      fields.push({
        type: fieldAttrs.type || tag,
        name: fieldAttrs.name || fieldAttrs.id || fieldAttrs["aria-label"] || fieldAttrs.value || "",
      });
    }

    return {
      pageUrl,
      index: index + 1,
      action: absoluteUrl(attrs.action, pageUrl),
      method: (attrs.method || "get").toLowerCase(),
      fieldCount: fields.length,
      fields: fields.slice(0, 12),
    };
  });
}

function hostVariants(hostname) {
  const host = String(hostname || "").toLowerCase();

  if (!host) {
    return [];
  }

  return host.startsWith("www.")
    ? [host, host.slice(4)]
    : [host, `www.${host}`];
}

function extractHtmlLinks(html, baseUrl, allowedHosts) {
  const links = [];
  const seen = new Set();
  const hosts = allowedHosts instanceof Set ? allowedHosts : new Set(hostVariants(allowedHosts));
  const hrefPattern = /<a\b[^>]*\bhref\s*=\s*(["'])([\s\S]*?)\1/gi;
  const skipExtensions = /\.(?:7z|avi|bmp|css|csv|docx?|eot|gif|gz|ico|jpe?g|js|json|mp3|mp4|mpeg|odt|ogg|pdf|png|pptx?|rar|rss|svg|tar|tiff?|ttf|txt|wav|webm|webp|woff2?|xlsx?|xml|zip)$/i;

  for (const match of html.matchAll(hrefPattern)) {
    const rawHref = String(match[2] || "").trim();

    if (!rawHref || /^(?:mailto:|tel:|javascript:|data:|sms:)/i.test(rawHref)) {
      continue;
    }

    let href;

    try {
      href = new URL(rawHref, baseUrl);
    } catch {
      continue;
    }

    href.hash = "";

    if (!["http:", "https:"].includes(href.protocol) || !hosts.has(href.hostname.toLowerCase())) {
      continue;
    }

    if (skipExtensions.test(href.pathname)) {
      continue;
    }

    const value = href.href;

    if (!seen.has(value)) {
      seen.add(value);
      links.push(value);
    }
  }

  return links;
}

function extractLinksForBrokenCheck(html, baseUrl) {
  const links = [];
  const seen = new Set();
  const anchorTargets = new Set();

  for (const match of String(html || "").matchAll(/\bid\s*=\s*(["'])([\s\S]*?)\1/gi)) {
    anchorTargets.add(decodeHtmlEntities(match[2] || ""));
  }

  for (const match of String(html || "").matchAll(/<a\b[^>]*\bname\s*=\s*(["'])([\s\S]*?)\1/gi)) {
    anchorTargets.add(decodeHtmlEntities(match[2] || ""));
  }

  for (const match of String(html || "").matchAll(/<a\b[^>]*\bhref\s*=\s*(["'])([\s\S]*?)\1[^>]*>([\s\S]*?)<\/a>|<a\b[^>]*\bhref\s*=\s*(["'])([\s\S]*?)\4[^>]*>/gi)) {
    const rawHref = String(match[2] || match[5] || "").trim();

    if (!rawHref) {
      continue;
    }

    let href;

    try {
      href = new URL(rawHref, baseUrl).href;
    } catch {
      href = rawHref;
    }

    const text = stripTags(match[3] || "");
    const key = href;

    if (!seen.has(key)) {
      seen.add(key);
      links.push({
        href,
        name: text,
      });
    }
  }

  return { links, anchorTargets };
}

async function checkCrawlHttpLink(link, options = {}) {
  if (options.job?.cancelled) {
    return null;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  if (options.job) {
    options.job.currentController = controller;
  }

  try {
    let response = await fetch(link.href, {
      method: "HEAD",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
      },
    });

    if ([403, 405, 501].includes(response.status)) {
      response = await fetch(link.href, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
        },
      });
    }

    if (response.status >= 400 && !shouldIgnoreHttpStatus(response.status, options)) {
      return {
        ...link,
        reason: `HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}`,
      };
    }

    return null;
  } catch (error) {
    if (options.job?.cancelled) {
      return null;
    }

    return {
      ...link,
      reason: error.name === "AbortError" ? "Tidsavbrudd" : "Kunne ikke nå lenken",
    };
  } finally {
    clearTimeout(timeout);

    if (options.job?.currentController === controller) {
      options.job.currentController = null;
    }
  }
}

async function extractBrokenLinksFromHtml(html, pageUrl, options = {}) {
  const { links, anchorTargets } = extractLinksForBrokenCheck(html, pageUrl);
  const pageUrlWithoutHash = new URL(pageUrl);
  const broken = [];

  pageUrlWithoutHash.hash = "";

  for (const link of links.slice(0, 80)) {
    if (options.job?.cancelled) {
      break;
    }

    let parsed;

    try {
      parsed = new URL(link.href, pageUrl);
    } catch {
      broken.push({ ...link, reason: "Ugyldig URL", pageUrl });
      continue;
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      continue;
    }

    const withoutHash = new URL(parsed.href);
    withoutHash.hash = "";

    if (withoutHash.href === pageUrlWithoutHash.href && parsed.hash) {
      let target = parsed.hash.slice(1);

      try {
        target = decodeURIComponent(target);
      } catch {
      }

      if (target && !anchorTargets.has(target)) {
        broken.push({
          ...link,
          href: parsed.href,
          reason: `Mangler anker: #${target}`,
          pageUrl,
        });
      }

      continue;
    }

    try {
      await validatePublicUrl(parsed.href);
    } catch {
      continue;
    }

    const brokenLink = await checkCrawlHttpLink({
      ...link,
      href: parsed.href,
      pageUrl,
    }, options);

    if (brokenLink) {
      broken.push(brokenLink);
    }
  }

  return broken;
}

async function fetchHtmlForCrawl(url, options = {}) {
  const controller = options.controller || new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
        "Accept": "text/html,application/xhtml+xml",
      },
    });
    const contentType = response.headers.get("content-type") || "";

    if (!response.ok || !/text\/html|application\/xhtml\+xml/i.test(contentType)) {
      return { ok: false, finalUrl: response.url || url, html: "", status: response.status };
    }

    return {
      ok: true,
      finalUrl: response.url || url,
      html: await response.text(),
      status: response.status,
    };
  } finally {
    clearTimeout(timeout);
  }
}

const domainExtractors = {
  pagecount: {
    label: "Antall sider",
    extract: () => [],
  },
  emails: {
    label: "E-postadresser",
    extract: extractEmailsFromHtml,
  },
  videos: {
    label: "Videoer",
    extract: extractVideosFromHtml,
  },
  tables: {
    label: "Tabeller",
    extract: extractTablesFromHtml,
  },
  forms: {
    label: "Skjemaer",
    extract: extractFormsFromHtml,
  },
  brokenlinks: {
    label: "Brutte lenker",
    extract: extractBrokenLinksFromHtml,
  },
};

function normalizeDomainPageCount(value) {
  const parsed = Number.parseInt(String(value || ""), 10);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    return defaultDomainPages;
  }

  return Math.min(parsed, maxDomainPages);
}

function emptyDomainResult(type, startUrl, maxPages = defaultDomainPages) {
  return {
    type,
    label: domainExtractors[type]?.label || type,
    startUrl,
    pagesChecked: 0,
    pagesReached: 0,
    pagesQueued: 0,
    maxPages,
    maxSeconds: defaultDomainSeconds,
    secondsUsed: 0,
    stoppedByTime: false,
    aborted: false,
    truncated: false,
    totalFindings: 0,
    pages: [],
    errorCount: 0,
    errors: [],
  };
}

function addDomainError(result, message) {
  result.errorCount += 1;

  if (result.type !== "pagecount" || result.errors.length < 20) {
    result.errors.push(message);
  }
}

function finalizeDomainResult(result, started, queueLength = 0) {
  result.pagesQueued = queueLength;
  result.secondsUsed = Math.round((Date.now() - started) / 1000);
  result.totalFindings = result.type === "pagecount"
    ? result.pagesReached
    : result.pages.reduce((sum, page) => sum + (page.count || 0), 0);
  result.truncated = queueLength > 0 || result.stoppedByTime || result.pagesChecked >= result.maxPages;
  return result;
}

async function crawlDomain(startUrl, type, options = {}) {
  const root = new URL(startUrl);
  root.hash = "";
  const allowedHosts = new Set(hostVariants(root.hostname));
  const extractor = domainExtractors[type];
  const maxPages = normalizeDomainPageCount(options.maxPages);
  const maxSeconds = Math.max(5, Number(options.maxSeconds || defaultDomainSeconds));
  const started = Date.now();
  const queue = [root.href];
  let queueIndex = 0;
  const queued = new Set(queue);
  const visited = new Set();
  const reachedPages = new Set();
  const seenBrokenLinks = new Set();
  const result = options.job?.result || emptyDomainResult(type, root.href, maxPages);

  result.maxSeconds = maxSeconds;

  if (!extractor) {
    throw new Error("Ukjent domenejobb.");
  }

  while (queueIndex < queue.length && visited.size < maxPages) {
    if (options.job?.cancelled) {
      result.aborted = true;
      break;
    }

    if ((Date.now() - started) / 1000 >= maxSeconds) {
      result.stoppedByTime = true;
      break;
    }

    const url = queue[queueIndex];
    queueIndex += 1;

    if (!url || visited.has(url)) {
      continue;
    }

    visited.add(url);
    result.pagesChecked = visited.size;

    try {
      const controller = new AbortController();

      if (options.job) {
        options.job.currentController = controller;
      }

      const pageResult = await fetchHtmlForCrawl(url, { controller });

      if (options.job) {
        options.job.currentController = null;
      }

      if (!pageResult.ok) {
        addDomainError(result, `${url}: HTTP ${pageResult.status || "ukjent"}`);
        continue;
      }

      try {
        hostVariants(new URL(pageResult.finalUrl).hostname).forEach((host) => allowedHosts.add(host));
      } catch {
      }

      try {
        const reachedUrl = new URL(pageResult.finalUrl);
        reachedUrl.hash = "";
        reachedPages.add(reachedUrl.href);
      } catch {
        reachedPages.add(pageResult.finalUrl);
      }

      result.pagesReached = reachedPages.size;

      let items = await extractor.extract(pageResult.html, pageResult.finalUrl, options);

      if (type === "brokenlinks") {
        items = items.filter((item) => {
          const key = `${String(item.href || "").toLowerCase()}|${item.reason || ""}`;

          if (seenBrokenLinks.has(key)) {
            return false;
          }

          seenBrokenLinks.add(key);
          return true;
        });
      }

      if (items.length) {
        result.pages.push({
          url: pageResult.finalUrl,
          count: items.length,
          items,
        });
      }

      extractHtmlLinks(pageResult.html, pageResult.finalUrl, allowedHosts).forEach((href) => {
        if (!queued.has(href) && !visited.has(href) && queued.size < maxPages * 4) {
          queued.add(href);
          queue.push(href);
        }
      });
    } catch (error) {
      if (options.job) {
        options.job.currentController = null;
      }

      if (!options.job?.cancelled) {
        addDomainError(result, `${url}: ${friendlyErrorMessage(error, "Kunne ikke hente siden.")}`);
      }
    }

    finalizeDomainResult(result, started, queue.length - queueIndex);
  }

  return finalizeDomainResult(result, started, queue.length - queueIndex);
}

function publicDomainJob(job) {
  return {
    jobId: job.id,
    status: job.status,
    command: job.command,
    type: job.type,
    done: ["completed", "cancelled", "failed"].includes(job.status),
    error: job.error || "",
    result: job.result,
  };
}

function cleanupDomainJobs() {
  const now = Date.now();

  domainJobs.forEach((job, id) => {
    if (["completed", "cancelled", "failed"].includes(job.status) && now - job.finishedAt > domainJobTtlMs) {
      domainJobs.delete(id);
    }
  });
}

function normalizeDomainSeconds(value) {
  const parsed = Number.parseInt(String(value || ""), 10);

  if (!Number.isFinite(parsed) || parsed <= 0) {
    return defaultDomainSeconds;
  }

  return Math.min(Math.max(5, parsed), maxDomainSeconds);
}

function startDomainJob({ type, url, maxPages, maxSeconds, ignore401 = false, ignore403 = false }) {
  cleanupDomainJobs();

  const id = crypto.randomUUID();
  const safeMaxPages = normalizeDomainPageCount(maxPages);
  const safeMaxSeconds = normalizeDomainSeconds(maxSeconds);
  const job = {
    id,
    command: `${type}domain`,
    type,
    status: "running",
    cancelled: false,
    currentController: null,
    startedAt: Date.now(),
    finishedAt: 0,
    error: "",
    result: emptyDomainResult(type, url, safeMaxPages),
  };

  job.result.maxSeconds = safeMaxSeconds;
  domainJobs.set(id, job);

  job.completion = crawlDomain(url, type, {
    maxPages: safeMaxPages,
    maxSeconds: safeMaxSeconds,
    ignore401,
    ignore403,
    job,
  })
    .then((result) => {
      job.result = result;
      job.status = job.cancelled ? "cancelled" : "completed";
    })
    .catch((error) => {
      job.status = job.cancelled ? "cancelled" : "failed";
      job.error = friendlyErrorMessage(error, "Domenejobben feilet.");
      job.result.aborted = job.cancelled;
    })
    .finally(() => {
      job.finishedAt = Date.now();
      job.currentController = null;
      finalizeDomainResult(job.result, job.startedAt, job.result.pagesQueued || 0);
    });

  return job;
}

async function cancelDomainJob(jobId) {
  const job = domainJobs.get(jobId);

  if (!job) {
    return null;
  }

  job.cancelled = true;
  job.result.aborted = true;

  if (job.currentController) {
    job.currentController.abort();
  }

  if (job.completion) {
    await job.completion;
  }

  return job;
}

function formatHtmlSource(source) {
  const html = String(source || "").trim();

  if (!html) {
    return "";
  }

  const voidTags = new Set([
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
  ]);
  const rawTextTags = new Set(["script", "style", "pre", "textarea"]);
  const tokenPattern = /<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>|<!doctype[^>]*>|<\?[\s\S]*?\?>|<\/?[a-zA-Z][^>]*>/gi;
  const lines = [];
  let indent = 0;
  let position = 0;
  let rawTextTag = "";

  const pushLine = (text, level = indent) => {
    const value = String(text || "").trim();

    if (value) {
      lines.push(`${"  ".repeat(Math.max(0, level))}${value}`);
    }
  };

  const pushText = (text) => {
    const value = String(text || "").replace(/\s+/g, " ").trim();

    if (value) {
      pushLine(value);
    }
  };

  for (const match of html.matchAll(tokenPattern)) {
    const token = match[0];
    const before = html.slice(position, match.index);

    if (rawTextTag) {
      const closingPattern = new RegExp(`^</${rawTextTag}\\s*>$`, "i");

      if (closingPattern.test(token)) {
        String(before || "")
          .split(/\r?\n/)
          .map((line) => line.trimEnd())
          .filter((line) => line.trim())
          .forEach((line) => lines.push(`${"  ".repeat(indent)}${line.trimStart()}`));
        indent = Math.max(0, indent - 1);
        pushLine(token);
        rawTextTag = "";
      }

      position = match.index + token.length;
      continue;
    }

    pushText(before);

    const closing = /^<\//.test(token);
    const tagMatch = token.match(/^<\/?\s*([a-zA-Z0-9:-]+)/);
    const tagName = tagMatch ? tagMatch[1].toLowerCase() : "";
    const selfClosing = /\/>$/.test(token) || voidTags.has(tagName) || /^<!|^<\?/.test(token);

    if (closing) {
      indent = Math.max(0, indent - 1);
      pushLine(token);
    } else {
      pushLine(token);

      if (!selfClosing) {
        indent += 1;

        if (rawTextTags.has(tagName)) {
          rawTextTag = tagName;
        }
      }
    }

    position = match.index + token.length;
  }

  pushText(html.slice(position));
  return lines.join("\n");
}

function sourceExcerpt(source, line, column, size = 1) {
  if (!source || !line) {
    return "";
  }

  const lines = source.split(/\r?\n/);
  const text = lines[line - 1] || "";
  const start = Math.max(0, (column || 1) - 41);
  const end = Math.min(text.length, (column || 1) + Math.max(size, 1) + 40);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < text.length ? "..." : "";

  return `${prefix}${text.slice(start, end)}${suffix}`.trim();
}

async function getHtmlValidation(url) {
  const source = await getSource(url);
  const report = await htmlValidator.validateString(source, url);
  const messages = (report.results || [])
    .flatMap((result) => result.messages || [])
    .map((message) => ({
      type: message.severity === 2 ? "feil" : "advarsel",
      ruleId: message.ruleId || "",
      message: message.message || "",
      line: message.line || 0,
      column: message.column || 0,
      selector: message.selector || "",
      ruleUrl: message.ruleUrl || "",
      excerpt: sourceExcerpt(source, message.line, message.column, message.size),
    }));

  return {
    valid: report.valid,
    errorCount: report.errorCount || 0,
    warningCount: report.warningCount || 0,
    messageCount: messages.length,
    checkedCharacters: source.length,
    messages: messages.slice(0, 100),
    truncated: messages.length > 100,
  };
}

async function getDom(page) {
  return page.content();
}

function createCrcTable() {
  const table = new Uint32Array(256);

  for (let index = 0; index < 256; index += 1) {
    let value = index;

    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }

    table[index] = value >>> 0;
  }

  return table;
}

function crc32(buffer) {
  let crc = 0xffffffff;

  for (const byte of buffer) {
    crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }

  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date = new Date()) {
  const dosTime =
    (date.getHours() << 11) |
    (date.getMinutes() << 5) |
    Math.floor(date.getSeconds() / 2);
  const dosDate =
    ((date.getFullYear() - 1980) << 9) |
    ((date.getMonth() + 1) << 5) |
    date.getDate();

  return { dosTime, dosDate };
}

function createZip(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;
  const { dosTime, dosDate } = dosDateTime();

  files.forEach((file) => {
    const name = Buffer.from(file.name, "utf8");
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    const crc = crc32(data);
    const local = Buffer.alloc(30);

    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(dosTime, 10);
    local.writeUInt16LE(dosDate, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(dosTime, 12);
    central.writeUInt16LE(dosDate, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);

    offset += local.length + name.length + data.length;
  });

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirectory, end]);
}

function slugPart(text, fallback = "side") {
  const slug = String(text || "")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/æ/g, "ae")
    .replace(/ø/g, "o")
    .replace(/å/g, "a")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);

  return slug || fallback;
}

function timestampPart(date = new Date()) {
  const parts = new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Europe/Oslo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(date);
  const value = (type) => parts.find((part) => part.type === type)?.value || "00";

  return `${value("year")}${value("month")}${value("day")}-${value("hour")}${value("minute")}${value("second")}`;
}

async function createSaveArchive(url, options = {}) {
  const browser = await getBrowser();
  const viewport = options.viewport || defaultViewport;
  const context = await browser.newContext(browserContextOptions({ viewport }));
  const page = await context.newPage();

  try {
    await gotoForAnalysis(page, url, 45000);
    const cookieResult = await handleCookieChoice(page, options);

    if (cookieResult) {
      return cookieResult;
    }

    await page.emulateMedia({ media: "screen" }).catch(() => {});

    const title = await page.title().catch(() => "");
    const finalUrl = page.url();
    const host = new URL(finalUrl).hostname.replace(/^www\./, "");
    const baseName = `${timestampPart()}-${slugPart(host)}-${slugPart(title, "uten-tittel")}`.slice(0, 140);
    session = await context.newCDPSession(page);
    const snapshot = await session.send("Page.captureSnapshot", { format: "mhtml" });
    const pdfOptions = {
      format: "A4",
      printBackground: true,
      preferCSSPageSize: true,
      tagged: true,
      outline: true,
      margin: {
        top: "12mm",
        right: "12mm",
        bottom: "12mm",
        left: "12mm",
      },
    };
    let pdf;

    try {
      pdf = await page.pdf(pdfOptions);
    } catch {
      pdf = await page.pdf({
        format: "A4",
        printBackground: true,
        preferCSSPageSize: true,
        margin: pdfOptions.margin,
      });
    }

    const info = [
      `URL: ${url}`,
      `Faktisk URL: ${finalUrl}`,
      `Tittel: ${title || "mangler"}`,
      "MHTML er en arkivversjon av siden.",
      "PDF er laget med Chromium. Tagget PDF forsøkes der Chromium/Playwright støtter det.",
    ].join("\r\n");
    const zip = createZip([
      { name: `${baseName}.mht`, data: Buffer.from(snapshot.data || "", "utf8") },
      { name: `${baseName}.pdf`, data: Buffer.from(pdf) },
      { name: `${baseName}-info.txt`, data: Buffer.from(info, "utf8") },
    ]);

    return {
      filename: `${baseName}.zip`,
      zip,
    };
  } finally {
    if (session) {
      await session.detach().catch(() => {});
    }

    await context.close().catch(() => {});
  }
}

async function getScreenReaderReport(page, mode = "reader") {
  return page.evaluate((reportMode) => {
    const maxLines = 900;
    const lines = [];
    const landmarkRoles = new Set(["banner", "navigation", "main", "complementary", "contentinfo", "search", "form", "region"]);
    const controlRoles = new Set(["button", "link", "checkbox", "radio", "textbox", "combobox", "switch", "tab", "menuitem", "option"]);
    const labels = {
      banner: "banner",
      navigation: "navigasjon",
      main: "hovedinnhold",
      complementary: "tilleggsinnhold",
      contentinfo: "bunntekst",
      search: "søk",
      form: "skjema",
      region: "region",
      heading: "overskrift",
      link: "lenke",
      button: "knapp",
      img: "bilde",
      image: "bilde",
      list: "liste",
      listitem: "listepunkt",
      table: "tabell",
      textbox: "tekstfelt",
      checkbox: "avkrysningsboks",
      radio: "radioknapp",
      combobox: "kombinasjonsboks",
      switch: "bryter",
    };

    function normalized(text) {
      return String(text || "").replace(/\s+/g, " ").trim();
    }

    function isHidden(element) {
      if (!element || !(element instanceof Element)) {
        return true;
      }

      for (let node = element; node; node = node.parentElement) {
        const style = window.getComputedStyle(node);

        if (
          node.hasAttribute("hidden") ||
          node.getAttribute("aria-hidden") === "true" ||
          style.display === "none" ||
          style.visibility === "hidden" ||
          style.visibility === "collapse" ||
          style.contentVisibility === "hidden"
        ) {
          return true;
        }
      }

      return false;
    }

    function selectorFor(element) {
      if (element.id) {
        return `#${CSS.escape(element.id)}`;
      }

      const parts = [];

      for (let node = element; node && node.nodeType === Node.ELEMENT_NODE && parts.length < 4; node = node.parentElement) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;

        if (!parent) {
          parts.unshift(tag);
          break;
        }

        const sameTag = Array.from(parent.children).filter((child) => child.tagName === node.tagName);
        const index = sameTag.indexOf(node) + 1;
        parts.unshift(sameTag.length > 1 ? `${tag}:nth-of-type(${index})` : tag);
      }

      return parts.join(" > ");
    }

    function textFromSubtree(element) {
      if (!element || isHidden(element)) {
        return "";
      }

      return normalized(element.innerText || element.textContent);
    }

    function textFromIds(ids) {
      return normalized(ids
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .filter(Boolean)
        .map((element) => textFromSubtree(element))
        .join(" "));
    }

    function labelText(element) {
      const labelsForElement = element.labels ? Array.from(element.labels) : [];

      if (!labelsForElement.length && element.id) {
        labelsForElement.push(...document.querySelectorAll(`label[for="${CSS.escape(element.id)}"]`));
      }

      return normalized(labelsForElement.map((label) => textFromSubtree(label)).join(" "));
    }

    function svgTitle(element) {
      const title = Array.from(element.children || []).find((child) => child.tagName.toLowerCase() === "title");
      return title ? normalized(title.textContent) : "";
    }

    function canNameFromContent(element) {
      const tag = element.tagName.toLowerCase();
      const role = normalized(element.getAttribute("role")).toLowerCase();

      return ["a", "button", "summary", "option", "legend", "label"].includes(tag) ||
        controlRoles.has(role);
    }

    function accessibleName(element) {
      if (!(element instanceof Element) || isHidden(element)) {
        return "";
      }

      const labelledBy = normalized(element.getAttribute("aria-labelledby"));
      const ariaLabel = normalized(element.getAttribute("aria-label"));
      const tag = element.tagName.toLowerCase();
      const type = (element.getAttribute("type") || "").toLowerCase();

      if (labelledBy) {
        const text = textFromIds(labelledBy);
        if (text) return text;
      }

      if (ariaLabel) return ariaLabel;

      if (["img", "area"].includes(tag) || (tag === "input" && type === "image")) {
        if (element.hasAttribute("alt")) return normalized(element.getAttribute("alt"));
      }

      if (["input", "select", "textarea", "output", "meter", "progress"].includes(tag)) {
        const text = labelText(element);
        if (text) return text;
      }

      if (tag === "input" && ["button", "submit", "reset"].includes(type)) {
        const value = normalized(element.getAttribute("value"));
        if (value) return value;
      }

      if (tag === "svg") {
        const title = svgTitle(element);
        if (title) return title;
      }

      if (canNameFromContent(element)) {
        const text = textFromSubtree(element);
        if (text) return text;
      }

      return normalized(element.getAttribute("title"));
    }

    function implicitRole(element) {
      const explicitRole = normalized(element.getAttribute("role")).toLowerCase();
      const tag = element.tagName.toLowerCase();
      const type = (element.getAttribute("type") || "").toLowerCase();

      if (explicitRole && !["none", "presentation"].includes(explicitRole)) return explicitRole;
      if (tag === "header") return "banner";
      if (tag === "nav") return "navigation";
      if (tag === "main") return "main";
      if (tag === "aside") return "complementary";
      if (tag === "footer") return "contentinfo";
      if (tag === "section" && accessibleName(element)) return "region";
      if (tag === "form") return "form";
      if (/^h[1-6]$/.test(tag)) return "heading";
      if (tag === "a" && element.hasAttribute("href")) return "link";
      if (tag === "button") return "button";
      if (tag === "img" || tag === "svg") return "img";
      if (["ul", "ol"].includes(tag)) return "list";
      if (tag === "li") return "listitem";
      if (tag === "table") return "table";
      if (["textarea", "select"].includes(tag)) return tag === "select" ? "combobox" : "textbox";
      if (tag === "input") {
        if (["button", "submit", "reset"].includes(type)) return "button";
        if (type === "checkbox") return "checkbox";
        if (type === "radio") return "radio";
        return "textbox";
      }

      return "";
    }

    function stateText(element) {
      const states = [];

      if (element.matches?.("input[type='checkbox'], input[type='radio']")) {
        states.push(element.checked ? "avkrysset" : "ikke avkrysset");
      }

      if (element.getAttribute("aria-expanded")) states.push(`utvidet=${element.getAttribute("aria-expanded")}`);
      if (element.getAttribute("aria-selected") === "true") states.push("valgt");
      if (element.hasAttribute("disabled") || element.getAttribute("aria-disabled") === "true") states.push("deaktivert");
      if (element.hasAttribute("required") || element.getAttribute("aria-required") === "true") states.push("påkrevd");
      if (element.getAttribute("aria-invalid") && element.getAttribute("aria-invalid") !== "false") states.push("ugyldig");

      return states.length ? ` (${states.join(", ")})` : "";
    }

    function addLine(line) {
      const text = reportMode === "structure" ? String(line || "").replace(/\s+$/, "") : normalized(line);

      if (!text || text === lines[lines.length - 1] || lines.length >= maxLines) {
        return;
      }

      lines.push(text);
    }

    function readerLine(element, role) {
      const tag = element.tagName.toLowerCase();
      const name = accessibleName(element);
      const text = textFromSubtree(element);
      const label = labels[role] || role || tag;

      if (role === "heading") {
        return `Overskrift nivå ${tag.slice(1)}: ${text || name || "uten tekst"}`;
      }

      if (landmarkRoles.has(role)) {
        return name ? `Landemerke ${label}: ${name}` : `Landemerke ${label}`;
      }

      if (role === "link") return `Lenke: ${name || text || "uten navn"}`;
      if (role === "button") return `Knapp: ${name || text || "uten navn"}${stateText(element)}`;
      if (role === "img") return `Bilde: ${name || "uten tekstalternativ"}`;
      if (role === "list") return `${label}${element.children.length ? ` med ${element.children.length} punkter` : ""}`;
      if (role === "listitem") return `Listepunkt: ${text || name || ""}`;
      if (role === "table") return `Tabell${element.rows?.length ? ` med ${element.rows.length} rader` : ""}`;
      if (["textbox", "checkbox", "radio", "combobox", "switch"].includes(role)) return `${label}: ${name || "uten navn"}${stateText(element)}`;
      if (["p", "blockquote", "figcaption", "caption", "dt", "dd"].includes(tag)) return text;

      return "";
    }

    function structureLine(element, role, depth) {
      const tag = element.tagName.toLowerCase();
      const name = accessibleName(element);
      const text = textFromSubtree(element);
      const parts = [`tag=${tag}`];

      if (role) parts.push(`role=${role}`);
      if (name) parts.push(`navn="${name}"`);
      if (!name && text && text.length <= 80) parts.push(`tekst="${text}"`);
      if (/^h[1-6]$/.test(tag)) parts.push(`nivå=${tag.slice(1)}`);
      if (element.id) parts.push(`id=${element.id}`);

      return `${"  ".repeat(depth)}- ${parts.join(", ")}`;
    }

    function isAtomicForReader(role, tag) {
      return role === "heading" ||
        ["link", "button", "img", "listitem", "table", "textbox", "checkbox", "radio", "combobox", "switch"].includes(role) ||
        ["p", "blockquote", "figcaption", "caption", "dt", "dd"].includes(tag);
    }

    function isMeaningful(element, role) {
      const tag = element.tagName.toLowerCase();

      return Boolean(role) ||
        ["p", "blockquote", "figcaption", "caption", "dt", "dd"].includes(tag) ||
        Boolean(accessibleName(element));
    }

    function walk(element, depth = 0) {
      if (!(element instanceof Element) || isHidden(element) || lines.length >= maxLines) {
        return;
      }

      const tag = element.tagName.toLowerCase();
      const role = implicitRole(element);

      if (reportMode === "structure") {
        if (isMeaningful(element, role)) {
          addLine(structureLine(element, role, depth));
        }

        Array.from(element.children).forEach((child) => walk(child, depth + (isMeaningful(element, role) ? 1 : 0)));
        return;
      }

      if (isMeaningful(element, role)) {
        addLine(readerLine(element, role));
      }

      if (!isAtomicForReader(role, tag)) {
        Array.from(element.children).forEach((child) => walk(child, depth + 1));
      }
    }

    addLine(`Tittel: ${document.title || "uten tittel"}`);
    walk(document.body);

    if (lines.length >= maxLines) {
      lines.push(`... rapporten er avkortet etter ${maxLines} linjer.`);
    }

    return lines.join("\n");
  }, mode);
}

async function hideCookieOverlays(page) {
  await page.evaluate(() => {
    const cookiePattern = /cookie|cookies|informasjonskaps|samtykke|consent|personvern|privacy/i;
    const actionPattern = /godta|aksepter|accept|tillat|avvis|reject|administrer|innstillinger/i;

    function visibleText(element) {
      return String(element.innerText || element.textContent || "").replace(/\s+/g, " ").trim();
    }

    function isOverlay(element) {
      const style = window.getComputedStyle(element);
      const rect = element.getBoundingClientRect();

      if (rect.width < 150 || rect.height < 40) {
        return false;
      }

      return ["fixed", "sticky"].includes(style.position) ||
        element.getAttribute("role") === "dialog" ||
        element.getAttribute("role") === "alertdialog" ||
        element.getAttribute("aria-modal") === "true";
    }

    Array.from(document.body.querySelectorAll("*")).forEach((element) => {
      if (!(element instanceof HTMLElement) || element.dataset.webquestHiddenCookieOverlay === "true") {
        return;
      }

      const text = visibleText(element);

      if (!text || text.length > 2500 || !cookiePattern.test(text) || !isOverlay(element)) {
        return;
      }

      const hasAction = actionPattern.test(text) || element.querySelector("button, a[href], [role='button']");

      if (!hasAction) {
        return;
      }

      element.dataset.webquestHiddenCookieOverlay = "true";
      element.dataset.webquestPreviousDisplay = element.style.display || "";
      element.style.setProperty("display", "none", "important");
    });

    [document.documentElement, document.body].forEach((element) => {
      if (!element) {
        return;
      }

      element.style.setProperty("overflow", "auto", "important");
      element.style.setProperty("position", "static", "important");
    });
  });
}

async function countHiddenCookieOverlays(page) {
  return page.evaluate(() =>
    document.querySelectorAll("[data-webquest-hidden-cookie-overlay='true']").length
  );
}

async function getColorblindSimulation(page, mode = "deuteranopia") {
  await hideCookieOverlays(page);

  const labels = {
    protanopia: "rød fargeblindhet",
    deuteranopia: "rød/grønn fargeblindhet",
    tritanopia: "blå/gul fargeblindhet",
    achromatopsia: "gråtoner",
  };
  const pageSize = await page.evaluate(() => ({
    width: Math.max(document.documentElement.scrollWidth, document.body.scrollWidth, window.innerWidth),
    height: Math.max(document.documentElement.scrollHeight, document.body.scrollHeight, window.innerHeight),
    viewportWidth: window.innerWidth,
    viewportHeight: window.innerHeight,
  }));
  const chunkHeight = Math.max(600, Math.min(pageSize.viewportHeight || 900, 1100));
  const fullChunkCount = Math.ceil(pageSize.height / chunkHeight);
  const chunkCount = Math.max(1, Math.min(fullChunkCount, maxColorblindScreenshots));
  const images = [];
  const seenScreenshotHashes = new Set();
  const seenScrollPositions = new Set();
  let duplicateScreenshots = 0;

  async function simulateImage(dataUrl) {
    return page.evaluate(async ({ dataUrl, simulationMode }) => {
    const matrices = {
      protanopia: [
        0.152286, 1.052583, -0.204868,
        0.114503, 0.786281, 0.099216,
        -0.003882, -0.048116, 1.051998,
      ],
      deuteranopia: [
        0.367322, 0.860646, -0.227968,
        0.280085, 0.672501, 0.047413,
        -0.011820, 0.042940, 0.968881,
      ],
      tritanopia: [
        1.255528, -0.076749, -0.178779,
        -0.078411, 0.930809, 0.147602,
        0.004733, 0.691367, 0.303900,
      ],
      achromatopsia: [
        0.299, 0.587, 0.114,
        0.299, 0.587, 0.114,
        0.299, 0.587, 0.114,
      ],
    };
    const matrix = matrices[simulationMode] || matrices.deuteranopia;
    const image = new Image();

    function clamp(value) {
      return Math.max(0, Math.min(255, Math.round(value)));
    }

    await new Promise((resolve, reject) => {
      image.onload = resolve;
      image.onerror = () => reject(new Error("Skjermbildet kunne ikke behandles."));
      image.src = dataUrl;
    });

    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d", { willReadFrequently: true });
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    context.drawImage(image, 0, 0);

    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;

    for (let index = 0; index < data.length; index += 4) {
      const r = data[index];
      const g = data[index + 1];
      const b = data[index + 2];

      data[index] = clamp((matrix[0] * r) + (matrix[1] * g) + (matrix[2] * b));
      data[index + 1] = clamp((matrix[3] * r) + (matrix[4] * g) + (matrix[5] * b));
      data[index + 2] = clamp((matrix[6] * r) + (matrix[7] * g) + (matrix[8] * b));
    }

    context.putImageData(imageData, 0, 0);
    return canvas.toDataURL("image/jpeg", 0.82);
    }, { dataUrl, simulationMode: mode });
  }

  for (let index = 0; index < chunkCount; index += 1) {
    const y = index * chunkHeight;
    const height = Math.min(chunkHeight, pageSize.height - y);

    if (height <= 0) {
      continue;
    }

    const actualY = await page.evaluate((scrollY) => {
      const scrollingElement = document.scrollingElement || document.documentElement;
      const maxScroll = Math.max(0, scrollingElement.scrollHeight - window.innerHeight);
      const target = Math.min(scrollY, maxScroll);
      scrollingElement.scrollTop = target;
      window.scrollTo(0, target);
      return Math.round(window.scrollY || scrollingElement.scrollTop || 0);
    }, y);

    if (seenScrollPositions.has(actualY) && index > 0) {
      break;
    }

    seenScrollPositions.add(actualY);
    await page.waitForTimeout(150);

    const screenshot = await page.screenshot({
      type: "jpeg",
      quality: 82,
    });
    const hash = crypto.createHash("sha256").update(screenshot).digest("hex");

    if (seenScreenshotHashes.has(hash)) {
      duplicateScreenshots += 1;
      continue;
    }

    seenScreenshotHashes.add(hash);
    const dataUrl = `data:image/png;base64,${screenshot.toString("base64")}`;

    images.push({
      imageDataUrl: await simulateImage(dataUrl),
      part: images.length + 1,
      parts: 0,
      scrollY: actualY,
    });
  }

  images.forEach((image) => {
    image.parts = images.length;
  });

  return {
    mode,
    label: labels[mode] || labels.deuteranopia,
    imageDataUrl: images[0]?.imageDataUrl || "",
    images,
    hiddenCookieBanners: await countHiddenCookieOverlays(page),
    duplicateScreenshots,
    truncated: fullChunkCount > chunkCount,
  };
}

const analyzers = {
  headings: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    headings: await getHeadings(page),
  }),
  language: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    language: await getLanguage(page),
  }),
  fields: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    groups: await getFields(page),
  }),
  contrast: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    contrast: await getContrast(page),
  }),
  css: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    css: await getCssOverview(page),
  }),
  csselement: async (page, url, options = {}) => ({
    ok: true,
    engine: "playwright",
    url,
    cssElement: await getCssElement(page, options.selector || "body"),
  }),
  cssregel: async (page, url, options = {}) => ({
    ok: true,
    engine: "playwright+css-tree",
    url,
    cssRule: await getCssRules(page, options.selector || "body"),
  }),
  cssfarger: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    cssColors: await getCssColors(page),
  }),
  cssfokusstil: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    cssFocusStyles: await getCssFocusStyles(page),
  }),
  cssresponsiv: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    cssResponsive: await getCssResponsive(page, url),
  }),
  cssskjult: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    cssHidden: await getCssHidden(page),
  }),
  cssvariabler: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    cssVariables: await getCssVariables(page),
  }),
  links: async (page, url) => {
    const result = await getLinks(page);

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
  emails: async (page, url) => {
    const result = await page.evaluate(collectAccessibilityData, "emails");

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
  videos: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    videos: await getVideos(page),
  }),
  forms: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    forms: await getForms(page),
  }),
  brokenlinks: async (page, url, options = {}) => ({
    ok: true,
    engine: "playwright",
    url,
    brokenLinks: await getBrokenLinks(page, url, options),
  }),
  images: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    images: await getImages(page),
  }),
  landmarks: async (page, url) => {
    const result = await getLandmarks(page);

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
  title: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    titleInfo: await getTitleInfo(page),
  }),
  meta: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    meta: await getMetaInfo(page),
  }),
  cookies: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    cookies: await getCookiesInfo(page, url),
  }),
  readability: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    readability: await getReadability(page),
  }),
  focus: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    focus: await getFocus(page),
  }),
  aria: async (page, url) => {
    const result = await getAriaIssues(page);

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
  ariapointers: async (page, url) => {
    const result = await getAriaPointers(page);

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
  tables: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    tables: await getTables(page),
  }),
  iframes: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    iframes: await getIframes(page),
  }),
  ids: async (page, url) => {
    const result = await getIds(page);

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
  fonts: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    fonts: await getFonts(page),
  }),
  html: async (page, url) => ({
    ok: true,
    engine: "html-validate",
    url,
    html: await getHtmlValidation(url),
  }),
  hentelement: async (page, url, options = {}) => ({
    ok: true,
    engine: "playwright-screenshot",
    url,
    elementExtracts: await getElementExtracts(page, options.selector || "body"),
  }),
  source: async (page, url) => ({
    ok: true,
    engine: "fetch+html-formatter",
    url,
    source: formatHtmlSource(await getSource(url)),
  }),
  dom: async (page, url) => ({
    ok: true,
    engine: "playwright",
    url,
    dom: await getDom(page),
  }),
  screenreader: async (page, url) => ({
    ok: true,
    engine: "chrome-accessibility-tree",
    url,
    report: await getScreenReaderReport(page, "reader"),
    mode: "reader",
  }),
  screenreaderstructure: async (page, url) => ({
    ok: true,
    engine: "chrome-accessibility-tree",
    url,
    report: await getScreenReaderReport(page, "structure"),
    mode: "structure",
  }),
  colorblindprotanopia: async (page, url) => ({
    ok: true,
    engine: "playwright-screenshot",
    url,
    colorblind: await getColorblindSimulation(page, "protanopia"),
  }),
  colorblinddeuteranopia: async (page, url) => ({
    ok: true,
    engine: "playwright-screenshot",
    url,
    colorblind: await getColorblindSimulation(page, "deuteranopia"),
  }),
  colorblindtritanopia: async (page, url) => ({
    ok: true,
    engine: "playwright-screenshot",
    url,
    colorblind: await getColorblindSimulation(page, "tritanopia"),
  }),
  colorblindachromatopsia: async (page, url) => ({
    ok: true,
    engine: "playwright-screenshot",
    url,
    colorblind: await getColorblindSimulation(page, "achromatopsia"),
  }),
  wcag: async (page, url) => ({
    ok: true,
    engine: "axe-core",
    url,
    wcag: await getWcag(page),
  }),
};

app.use((req, res, next) => {
  setCorsHeaders(req, res);
  next();
});

app.options("/analyze", (req, res) => {
  setCorsHeaders(req, res);
  res.set("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Content-Type");
  res.sendStatus(204);
});

app.use("/analyze", async (req, res, next) => {
  try {
    await acquireAnalysisSlot();
  } catch (error) {
    res.status(503).json({
      ok: false,
      error: error.message || "Analyzeren er opptatt. Prøv igjen om litt.",
    });
    return;
  }

  res.on("finish", releaseAnalysisSlot);
  res.on("close", () => {
    if (!res.writableEnded) {
      releaseAnalysisSlot();
    }
  });
  next();
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/analyze", async (req, res) => {
  const command = String(req.query.command || "").toLowerCase();
  const requestedUrl = normalizeUrl(req.query.url);
  const selector = String(req.query.selector || "").trim();
  const ignore401 = String(req.query.ignore401 || "") === "1";
  const ignore403 = String(req.query.ignore403 || "") === "1";
  const cookieChoice = String(req.query.cookieChoice || "").trim();
  const cookieFlow = String(req.query.cookieFlow || "") === "1";
  const viewport = normalizeViewport(req.query.viewportWidth, req.query.viewportHeight);

  if (command === "describe") {
    if (!requestedUrl) {
      res.status(400).json({
        ok: false,
        error: "Du må angi en bilde-URL etter Beskriv.",
      });
      return;
    }

    try {
      const url = await validatePublicUrl(requestedUrl);
      const result = await describeImage(url);

      res.json(result);
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: friendlyErrorMessage(error, error.message || "Jeg fikk ikke beskrevet bildet."),
      });
    }

    return;
  }

  if (command === "checkurl") {
    if (!requestedUrl) {
      res.status(400).json({
        ok: false,
        error: "Skriv en URL etter Velg.",
      });
      return;
    }

    try {
      const result = await checkReachableUrl(requestedUrl);

      if (!result.ok) {
        res.status(400).json(result);
        return;
      }

      res.json({
        ok: true,
        engine: "fetch",
        ...result,
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: friendlyErrorMessage(error, "URL-en kan ikke nås."),
      });
    }

    return;
  }

  if (command === "startdomainjob") {
    if (!requestedUrl) {
      res.status(400).json({
        ok: false,
        error: 'Du må angi en URL eller velge en standard URL med kommandoen "Velg URL".',
      });
      return;
    }

    try {
      const type = String(req.query.type || "").trim().toLowerCase();
      const maxPages = normalizeDomainPageCount(req.query.maxPages);
      const maxSeconds = normalizeDomainSeconds(req.query.maxSeconds);
      const ignore401 = String(req.query.ignore401 || "") === "1";
      const ignore403 = String(req.query.ignore403 || "") === "1";

      if (!domainExtractors[type]) {
        res.status(400).json({ ok: false, error: "Ukjent domenejobb." });
        return;
      }

      const url = await validatePublicUrl(requestedUrl);
      const job = startDomainJob({ type, url, maxPages, maxSeconds, ignore401, ignore403 });

      res.json({
        ok: true,
        engine: "fetch-crawler-job",
        url,
        ...publicDomainJob(job),
      });
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: friendlyErrorMessage(error, "Jeg fikk ikke startet domenejobben."),
      });
    }

    return;
  }

  if (command === "domainjobstatus") {
    const jobId = String(req.query.jobId || "").trim();
    const job = domainJobs.get(jobId);

    if (!job) {
      res.status(404).json({ ok: false, error: "Domenejobben finnes ikke lenger." });
      return;
    }

    res.json({
      ok: true,
      engine: "fetch-crawler-job",
      ...publicDomainJob(job),
    });
    return;
  }

  if (command === "canceldomainjob") {
    const jobId = String(req.query.jobId || "").trim();
    const job = await cancelDomainJob(jobId);

    if (!job) {
      res.status(404).json({ ok: false, error: "Domenejobben finnes ikke lenger." });
      return;
    }

    res.json({
      ok: true,
      engine: "fetch-crawler-job",
      ...publicDomainJob(job),
    });
    return;
  }

  if (command === "save") {
    if (!requestedUrl) {
      res.status(400).json({
        ok: false,
        error: 'Du må angi en URL eller velge en standard URL med kommandoen "Velg URL".',
      });
      return;
    }

    try {
      const url = await validatePublicUrl(requestedUrl);
      const archive = await createSaveArchive(url, { cookieChoice, cookieFlow, viewport });

      if (archive.cookieChoiceNeeded) {
        res.json(archive);
        return;
      }

      res.set("Content-Type", "application/zip");
      res.set("Content-Disposition", `attachment; filename="${archive.filename}"`);
      res.send(archive.zip);
    } catch (error) {
      res.status(500).json({
        ok: false,
        error: friendlyErrorMessage(error, error.message || "Jeg fikk ikke lagret siden."),
      });
    }

    return;
  }

  if (!analyzers[command]) {
    res.status(400).json({ ok: false, error: "Ukjent analysekommando." });
    return;
  }

  if (!requestedUrl) {
    res.status(400).json({
      ok: false,
      error: 'Du må angi en URL eller velge en standard URL med kommandoen "Velg URL".',
    });
    return;
  }

  try {
    const url = await validatePublicUrl(requestedUrl);

    if (command === "source") {
      const source = await getSource(url);

      res.json({
        ok: true,
        engine: "fetch+html-formatter",
        url,
        source: formatHtmlSource(source),
        sourceCharacters: source.length,
      });
      return;
    }

    const result = await analyzePage(
      url,
      (page) => analyzers[command](page, url, { selector, ignore401, ignore403 }),
      { cookieChoice, cookieFlow, viewport, forceFreshContext: command === "cookies" }
    );

    res.json(result);
  } catch (error) {
    console.error(`Analysefeil for ${command || "ukjent kommando"}: ${String(error?.stack || error)}`);
    res.status(500).json({
      ok: false,
      error: friendlyErrorMessage(error, "Jeg fikk ikke analysert siden."),
    });
  }
});

app.listen(port, () => {
  console.log(`WebQuest analyzer listening on ${port}`);
});

process.on("SIGTERM", async () => {
  if (persistentContextPromise) {
    const context = await persistentContextPromise;
    await context.close();
  }

  if (browserPromise) {
    const browser = await browserPromise;
    await browser.close();
  }

  process.exit(0);
});
