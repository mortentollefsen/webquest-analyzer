import express from "express";
import { chromium } from "playwright";
import dns from "node:dns/promises";
import net from "node:net";
import axe from "axe-core";

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
  const context = await browser.newContext({
    viewport: { width: 1400, height: 1000 },
    locale: "nb-NO",
    userAgent:
      "Mozilla/5.0 (compatible; WebQuest/1.0; +https://mortentollefsen.no/apper/webquest/)",
  });
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
    await context.close();
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

    return Array.from(document.querySelectorAll("img, svg, input[type='image'], area")).map((image) => {
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
        altStatus = svgTitle(image) ? "svg title" : "mangler tekstalternativ";
      }

      const src = image.currentSrc || image.src || image.href?.baseVal || image.getAttribute("href") || "";

      return {
        altStatus,
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

async function getImages(page) {
  return page.evaluate(collectAccessibilityData, "images");

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

      return {
        caption,
        rows,
        columns,
        headerCells: headers.length,
        missingScope: headers.some((header) => !header.hasAttribute("scope")),
        possibleLayout: headers.length === 0 && !caption,
        selector: selectorFor(table),
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

    function nearestColorName(red, green, blue) {
      const colors = [
        ["svart", 0, 0, 0],
        ["hvit", 255, 255, 255],
        ["mørk grå", 64, 64, 64],
        ["grå", 128, 128, 128],
        ["lys grå", 211, 211, 211],
        ["sølvgrå", 192, 192, 192],
        ["rød", 220, 20, 60],
        ["mørk rød", 139, 0, 0],
        ["lys rød", 255, 102, 102],
        ["rosa", 255, 105, 180],
        ["lys rosa", 255, 182, 193],
        ["burgunder", 128, 0, 32],
        ["oransje", 255, 140, 0],
        ["mørk oransje", 204, 85, 0],
        ["fersken", 255, 218, 185],
        ["brun", 139, 69, 19],
        ["mørk brun", 92, 64, 51],
        ["beige", 245, 245, 220],
        ["sand", 194, 178, 128],
        ["gul", 255, 215, 0],
        ["lys gul", 255, 255, 153],
        ["oliven", 128, 128, 0],
        ["limegrønn", 50, 205, 50],
        ["grønn", 34, 139, 34],
        ["mørk grønn", 0, 100, 0],
        ["lys grønn", 144, 238, 144],
        ["mintgrønn", 152, 255, 152],
        ["turkis", 64, 224, 208],
        ["mørk turkis", 0, 128, 128],
        ["cyan", 0, 255, 255],
        ["lys blå", 135, 206, 250],
        ["blå", 30, 144, 255],
        ["mørk blå", 0, 0, 139],
        ["marineblå", 0, 31, 63],
        ["blågrå", 96, 125, 139],
        ["indigo", 75, 0, 130],
        ["lilla", 128, 0, 128],
        ["mørk lilla", 75, 0, 100],
        ["lys lilla", 216, 191, 216],
        ["magenta", 255, 0, 255],
      ];
      let best = colors[0];
      let bestDistance = Number.POSITIVE_INFINITY;

      colors.forEach((color) => {
        const distance =
          (red - color[1]) ** 2 +
          (green - color[2]) ** 2 +
          (blue - color[3]) ** 2;

        if (distance < bestDistance) {
          best = color;
          bestDistance = distance;
        }
      });

      return best[0];
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
        .map((value) => Math.max(0, Math.min(255, value)).toString(16).padStart(2, "0"))
        .join("");
      const value = `#${hex}`;
      const name = nearestColorName(red, green, blue);
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
  links: async (page, url) => {
    const result = await getLinks(page);

    return {
      ok: true,
      engine: "playwright",
      url,
      ...result,
    };
  },
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

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/analyze", async (req, res) => {
  const command = String(req.query.command || "").toLowerCase();
  const requestedUrl = normalizeUrl(req.query.url);

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
        error: error.message || "Jeg fikk ikke beskrevet bildet.",
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
