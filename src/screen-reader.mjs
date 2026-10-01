// Self-contained: also injected into the active tab by the extension.
export function screenReaderReport(mode = "reader") {
  const structure = mode === "structure";
  const lines = [];
  const limit = 900;
  let truncated = false;
  const normalize = (value) => String(value || "").replace(/\s+/g, " ").trim();
  const landmarks = new Set(["banner", "navigation", "main", "complementary", "contentinfo", "search", "form", "region"]);
  const labels = { banner: "banner", navigation: "navigasjon", main: "hovedinnhold", complementary: "tilleggsinnhold", contentinfo: "bunntekst", search: "søk", form: "skjema", region: "region", link: "Lenke", button: "Knapp", img: "Bilde", textbox: "Tekstfelt", searchbox: "Søkefelt", checkbox: "Avkrysningsboks", radio: "Radioknapp", combobox: "Kombinasjonsboks", switch: "Bryter", slider: "Glidebryter", spinbutton: "Tallfelt", tab: "Fane", menuitem: "Menyvalg", option: "Alternativ", rowheader: "Radoverskrift", columnheader: "Kolonneoverskrift", cell: "Celle", gridcell: "Celle" };
  function hidden(element) {
    for (let node = element; node; node = node.parentElement || node.getRootNode().host) {
      const style = getComputedStyle(node);
      if (node.hidden || node.inert || node.getAttribute("aria-hidden") === "true" || style.display === "none" || ["hidden", "collapse"].includes(style.visibility) || style.contentVisibility === "hidden") return true;
      if (node.parentElement?.tagName === "DETAILS" && !node.parentElement.open && node.tagName !== "SUMMARY") return true;
    }
    return false;
  }
  function children(element) {
    if (element.tagName === "SLOT") {
      const assigned = element.assignedNodes({ flatten: true });
      if (assigned.length) return assigned;
    }
    return Array.from((element.shadowRoot || element).childNodes);
  }
  function content(element, includeHidden = false) {
    if (!element || (!includeHidden && hidden(element))) return "";
    if (["SCRIPT", "STYLE", "TEMPLATE", "NOSCRIPT"].includes(element.tagName)) return "";
    if (element.tagName === "IMG") return normalize(element.getAttribute("alt"));
    return normalize(children(element).map((node) => node.nodeType === Node.TEXT_NODE ? node.textContent : node.nodeType === Node.ELEMENT_NODE ? content(node, includeHidden) : "").join(" "));
  }
  function name(element, visited = new Set(), referenced = false) {
    if (visited.has(element)) return "";
    visited.add(element);
    const ids = normalize(element.getAttribute("aria-labelledby")).split(/\s+/).filter(Boolean);
    const refs = ids.map((id) => element.getRootNode().getElementById?.(id) || document.getElementById(id)).filter(Boolean);
    if (refs.length && !referenced) return normalize(refs.map((ref) => ref === element ? content(ref, true) : name(ref, new Set(visited), true) || content(ref, true)).join(" "));
    const aria = normalize(element.getAttribute("aria-label"));
    if (aria) return aria;
    const tag = element.tagName.toUpperCase();
    const type = (element.getAttribute("type") || "text").toLowerCase();
    if (tag === "IMG" || tag === "AREA" || (tag === "INPUT" && type === "image")) {
      if (element.hasAttribute("alt")) return normalize(element.getAttribute("alt"));
    }
    if (element.labels?.length) return normalize(Array.from(element.labels).map((label) => content(label, true)).join(" "));
    if (tag === "INPUT" && ["submit", "reset", "button"].includes(type)) return normalize(element.value) || ({ submit: "Send", reset: "Tilbakestill" }[type] || "");
    if (tag === "SVG") return normalize(Array.from(element.children).find((child) => child.tagName.toLowerCase() === "title")?.textContent);
    if (tag === "TABLE") return content(element.caption);
    if (tag === "FIELDSET") return content(Array.from(element.children).find((child) => child.tagName === "LEGEND"));
    const role = element.getAttribute("role") || "";
    if (referenced || ["A", "BUTTON", "SUMMARY", "OPTION"].includes(tag) || /^H[1-6]$/.test(tag) || ["button", "link", "checkbox", "radio", "switch", "tab", "menuitem", "option"].includes(role)) return content(element, referenced) || normalize(element.title);
    return normalize(element.title);
  }
  function roleOf(element) {
    const explicit = normalize(element.getAttribute("role")).split(" ")[0];
    if (explicit) return ["none", "presentation"].includes(explicit) ? "" : explicit === "image" ? "img" : explicit;
    const tag = element.tagName.toUpperCase();
    const type = (element.getAttribute("type") || "text").toLowerCase();
    if (/^H[1-6]$/.test(tag)) return "heading";
    if (tag === "A") return element.hasAttribute("href") ? "link" : "";
    if (tag === "IMG") return element.getAttribute("alt") === "" && !element.hasAttribute("aria-label") && !element.hasAttribute("aria-labelledby") ? "" : "img";
    if (tag === "SVG") return name(element) ? "img" : "";
    if (tag === "HEADER" || tag === "FOOTER") return element.closest("article, aside, main, nav, section") ? "" : tag === "HEADER" ? "banner" : "contentinfo";
    if (tag === "FORM" || tag === "SECTION") return name(element) ? tag === "FORM" ? "form" : "region" : "";
    if (tag === "TH") return element.getAttribute("scope")?.startsWith("row") ? "rowheader" : "columnheader";
    if (tag === "INPUT") {
      if (type === "hidden") return "";
      if (["button", "submit", "reset", "image"].includes(type)) return "button";
      return ({ checkbox: "checkbox", radio: "radio", range: "slider", number: "spinbutton", search: "searchbox" })[type] || "textbox";
    }
    return ({ NAV: "navigation", MAIN: "main", ASIDE: "complementary", SEARCH: "search", BUTTON: "button", SUMMARY: "button", UL: "list", OL: "list", LI: "listitem", TABLE: "table", TR: "row", TD: "cell", TEXTAREA: "textbox", SELECT: "combobox", IFRAME: "iframe", FIELDSET: "group" })[tag] || "";
  }
  function states(element, role) {
    const values = [];
    if (["checkbox", "radio", "switch"].includes(role)) {
      const checked = element.getAttribute("aria-checked");
      values.push(checked === "mixed" || element.indeterminate ? "delvis avkrysset" : checked === "true" || element.checked ? "avkrysset" : "ikke avkrysset");
    }
    let expanded = element.getAttribute("aria-expanded");
    if (element.tagName === "SUMMARY") expanded = String(element.parentElement.open);
    if (expanded !== null) values.push(expanded === "true" ? "utvidet" : "sammenfoldet");
    if (element.getAttribute("aria-pressed") !== null) values.push(`trykket=${element.getAttribute("aria-pressed")}`);
    if (element.getAttribute("aria-selected") !== null) values.push(element.getAttribute("aria-selected") === "true" ? "valgt" : "ikke valgt");
    if (element.matches(":disabled") || element.getAttribute("aria-disabled") === "true") values.push("deaktivert");
    if (element.required || element.getAttribute("aria-required") === "true") values.push("påkrevd");
    if (element.getAttribute("aria-invalid") && element.getAttribute("aria-invalid") !== "false") values.push("ugyldig");
    if (role === "textbox" || role === "searchbox" || role === "spinbutton" || role === "slider") {
      if (element.type === "password") values.push("passordfelt; verdi skjult");
      else if (element.value || element.getAttribute("aria-valuetext") || element.getAttribute("aria-valuenow")) values.push(`verdi: ${normalize(element.getAttribute("aria-valuetext") || element.getAttribute("aria-valuenow") || element.value)}`);
    }
    if (role === "combobox" && element.selectedOptions) values.push(`valgt: ${normalize(Array.from(element.selectedOptions).map((option) => option.textContent).join(", "))}`);
    const description = normalize((element.getAttribute("aria-describedby") || "").split(/\s+/).map((id) => document.getElementById(id)).filter(Boolean).map((ref) => content(ref, true)).join(" ")) || normalize(element.getAttribute("aria-description"));
    if (description) values.push(`beskrivelse: ${description}`);
    return values.length ? ` (${values.join("; ")})` : "";
  }
  function add(line) {
    if (!normalize(line)) return;
    if (lines.length >= limit) { truncated = true; return; }
    lines.push(line);
  }
  function walk(element, depth = 0) {
    if (hidden(element) || ["SCRIPT", "STYLE", "TEMPLATE", "NOSCRIPT"].includes(element.tagName) || element.matches('input[type="hidden"]')) return;
    if (lines.length >= limit) { truncated = true; return; }
    const role = roleOf(element);
    const accessibleName = name(element);
    const tag = element.tagName.toLowerCase();
    const level = element.getAttribute("aria-level") || (/^h[1-6]$/.test(tag) ? tag.slice(1) : "");
    const atomic = ["heading", "link", "button", "img", "textbox", "searchbox", "checkbox", "radio", "combobox", "switch", "slider", "spinbutton", "tab", "menuitem", "option", "iframe"].includes(role);
    const meaningful = Boolean(role) || ["p", "blockquote", "figcaption", "caption", "dt", "dd"].includes(tag);
    if (structure && meaningful) {
      const parts = [`tag=${tag}`];
      if (role) parts.push(`role=${role}`);
      if (accessibleName) parts.push(`navn=${JSON.stringify(accessibleName)}`);
      if (level) parts.push(`nivå=${level}`);
      if (element.id) parts.push(`id=${element.id}`);
      if (element.hasAttribute("scope")) parts.push(`scope=${element.getAttribute("scope")}`);
      if (element.colSpan > 1) parts.push(`colspan=${element.colSpan}`);
      if (element.rowSpan > 1) parts.push(`rowspan=${element.rowSpan}`);
      add(`${"  ".repeat(depth)}- ${parts.join(", ")}${states(element, role)}`);
    } else if (!structure) {
      if (landmarks.has(role)) add(`Landemerke ${labels[role] || role}${accessibleName ? `: ${accessibleName}` : ""}`);
      else if (role === "heading") add(`Overskrift nivå ${level || "ukjent"}: ${accessibleName || content(element) || "uten tekst"}`);
      else if (atomic) add(`${labels[role] || (role === "iframe" ? "Innebygd ramme" : role)}: ${accessibleName || "uten navn"}${states(element, role)}`);
      else if (role === "list") {
        const count = Array.from(element.children).filter((child) => !hidden(child) && roleOf(child) === "listitem").length;
        add(`Liste med ${count} ${count === 1 ? "punkt" : "punkter"}`);
      }
      else if (role === "listitem") add("Listepunkt:");
      else if (role === "table") add(`Tabell${accessibleName ? `: ${accessibleName}` : ""}${element.rows ? ` (${element.rows.length} rader)` : ""}`);
      else if (role === "row") add("Rad:");
      else if (["cell", "gridcell", "rowheader", "columnheader"].includes(role)) {
        const headers = normalize(element.getAttribute("headers")).split(/\s+/).filter(Boolean).map((id) => document.getElementById(id)).filter(Boolean).map((header) => content(header));
        add(`${labels[role]}${headers.length ? ` (${headers.join("; ")})` : ""}:`);
      }
      else if (role === "group" && accessibleName) add(`Gruppe: ${accessibleName}`);
    }
    if (role === "iframe") {
      add(`${"  ".repeat(structure ? depth + 1 : 0)}Rammeinnhold er ikke med i rapporten.`);
      return;
    }
    // Read text nodes in place, so nested links and controls keep their order.
    if (atomic && !structure) return;
    let pending = "";
    const flush = () => { if (normalize(pending)) add(`${"  ".repeat(structure ? depth + (meaningful ? 1 : 0) : 0)}${structure ? "Tekst: " : ""}${normalize(pending)}`); pending = ""; };
    for (const node of children(element)) {
      if (node.nodeType === Node.TEXT_NODE) pending += node.textContent;
      else if (node.nodeType === Node.ELEMENT_NODE) {
        if (!structure && (hidden(node) || ["SCRIPT", "STYLE", "TEMPLATE", "NOSCRIPT"].includes(node.tagName))) continue;
        if (!structure && ["SPAN", "EM", "STRONG", "B", "I", "SMALL"].includes(node.tagName) && !node.hasAttribute("role") && !node.hasAttribute("aria-label") && !node.hasAttribute("aria-labelledby") && !node.querySelector("a, button, input, select, textarea, img, [role]")) pending += ` ${content(node)} `;
        else { flush(); walk(node, depth + (meaningful ? 1 : 0)); }
      }
    }
    flush();
  }
  add(`Tittel: ${document.title || "uten tittel"}`);
  if (document.body) walk(document.body);
  if (truncated) lines.push(`... rapporten er avkortet etter ${limit} linjer.`);
  return lines.join("\n");
}
