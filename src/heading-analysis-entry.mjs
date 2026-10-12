import { computeAccessibleName, isInaccessible } from "dom-accessibility-api";

const normalized = (value) => String(value || "").replace(/\s+/g, " ").trim();

export function headingName(element) {
  const name = computeAccessibleName(element, { computedStyleSupportsPseudoElements: true });
  if (!name) return { name: "", source: "ingen" };
  const root = element.getRootNode();
  const ids = normalized(element.getAttribute("aria-labelledby")).split(/\s+/).filter(Boolean);
  if (ids.some((id) => root.getElementById?.(id))) return { name, source: "aria-labelledby" };
  if (normalized(element.getAttribute("aria-label"))) return { name, source: "aria-label" };

  // Source metadata describes content conservatively; the engine calculates the name.
  const images = Array.from(element.querySelectorAll("img[alt]"))
    .filter((image) => !isInaccessible(image) && computeAccessibleName(image));
  if (images.length === 1 && !normalized(images[0].getAttribute("aria-label")) &&
      !normalized(images[0].getAttribute("aria-labelledby")) && normalized(images[0].getAttribute("alt")) === name) {
    return { name, source: "innhold (alt på bilde)" };
  }
  let hasContent = false;
  function visit(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      if (normalized(node.textContent)) hasContent = true;
      return;
    }
    if (!(node instanceof Element) || isInaccessible(node) || /^(script|style|template)$/i.test(node.localName)) return;
    if (node !== element && computeAccessibleName(node)) hasContent = true;
    for (const pseudo of ["::before", "::after"]) {
      const content = getComputedStyle(node, pseudo).content;
      if (content && !["none", "normal", '""', "''"].includes(content)) hasContent = true;
    }
    node.childNodes.forEach(visit);
  }
  visit(element);
  return { name, source: hasContent ? "innhold" : normalized(element.getAttribute("title")) ? "title" : "innhold" };
}

export function headingsReport(selectorFor = (element) => {
  if (element.id && document.querySelectorAll(`#${CSS.escape(element.id)}`).length === 1) return `#${CSS.escape(element.id)}`;
  const parts = [];
  for (let node = element; node; node = node.parentElement) {
    const siblings = Array.from(node.parentElement?.children || []).filter((child) => child.localName === node.localName);
    parts.unshift(node.localName + (siblings.length > 1 ? `:nth-of-type(${siblings.indexOf(node) + 1})` : ""));
  }
  return parts.join(" > ");
}) {
  function hidden(element) {
    for (let node = element; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (node.hasAttribute("hidden") || node.getAttribute("type") === "hidden" ||
          style.display === "none" || ["hidden", "collapse"].includes(style.visibility) || style.contentVisibility === "hidden") return true;
    }
    return false;
  }
  return Array.from(document.querySelectorAll("h1,h2,h3,h4,h5,h6"))
    .filter((element) => !hidden(element))
    .map((element) => {
      const info = headingName(element);
      let ariaHidden = false;
      for (let node = element; node; node = node.parentElement) {
        if (node.getAttribute("aria-hidden") === "true") ariaHidden = true;
      }
      return {
        level: Number(element.localName.slice(1)),
        text: info.name || "(uten tilgjengelig navn)",
        name: info.name,
        nameSource: info.source,
        where: selectorFor(element),
        ariaHidden,
      };
    });
}
