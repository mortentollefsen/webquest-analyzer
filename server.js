import express from "express";
import { chromium } from "playwright";
import dns from "node:dns/promises";
import net from "node:net";

const app = express();
const port = Number(process.env.PORT || 3000);
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

let browserPromise;

function getBrowser() {
  if (!browserPromise) {
    browserPromise = chromium.launch({
      args: ["--no-sandbox", "--disable-dev-shm-usage"],
    });
  }

  return browserPromise;
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

  if (parsed.hostname === "localhost") {
    throw new Error("Lokale adresser kan ikke analyseres.");
  }

  const addresses = await dns.lookup(parsed.hostname, { all: true });

  if (addresses.some((entry) => isPrivateIp(entry.address))) {
    throw new Error("Private eller lokale adresser kan ikke analyseres.");
  }

  return parsed.href;
}

function setCorsHeaders(req, res) {
  const origin = req.get("origin");

  if (!origin) {
    return;
  }

  if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Vary", "Origin");
  }
}

async function analyzePage(url, analyzer) {
  const browser = await getBrowser();
  const context = await browser.newContext({
    locale: "nb-NO",
    userAgent:
      "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
  });
  const page = await context.newPage();

  try {
    await page.goto(url, {
      waitUntil: "networkidle",
      timeout: 30000,
    });

    return await analyzer(page);
  } finally {
    await context.close();
  }
}

async function getHeadings(page) {
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

async function getFields(page) {
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

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/analyze", async (req, res) => {
  const command = String(req.query.command || "").toLowerCase();
  const requestedUrl = normalizeUrl(req.query.url);

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
    const result = await analyzePage(url, (page) => analyzers[command](page, url));

    res.json(result);
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: error.message || "Jeg fikk ikke analysert siden.",
    });
  }
});

app.listen(port, () => {
  console.log(`WebQuest analyzer listening on ${port}`);
});

process.on("SIGTERM", async () => {
  if (browserPromise) {
    const browser = await browserPromise;
    await browser.close();
  }

  process.exit(0);
});
