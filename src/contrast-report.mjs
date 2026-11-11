export async function runContrastReport() {
  const definitions = [
    ["AA", "1.4.3", "color-contrast"],
    ["AAA", "1.4.6", "color-contrast-enhanced"],
  ];
  const result = await globalThis.axe.run(document, {
    runOnly: { type: "rule", values: definitions.map((rule) => rule[2]) },
    resultTypes: ["violations", "incomplete", "passes"],
    iframes: false,
  });
  const reasons = {
    bgImage: "Bakgrunnsbilde",
    bgGradient: "Bakgrunn med gradient",
    imgNode: "Et bilde påvirker bakgrunnen",
    bgOverlap: "Andre elementer overlapper bakgrunnen",
    fgAlpha: "Gjennomsiktig tekstfarge",
    elmPartiallyObscured: "Teksten er delvis dekket av et annet element",
    elmPartiallyObscuring: "Elementet dekker delvis andre elementer",
    outsideViewport: "Elementet er utenfor det synlige området",
    equalRatio: "Samme beregnede forgrunns- og bakgrunnsfarge",
    shortTextContent: "Svært kort tekst",
    pseudoContent: "CSS-generert innhold påvirker målingen",
    complexTextShadows: "Komplekse tekstskygger",
    colorParse: "Fargen kunne ikke tolkes sikkert",
  };
  const limit = 200;
  const levels = definitions.map(([level, criterion, ruleId]) => {
    const groups = ["violations", "incomplete", "passes"].map((kind) => {
      const nodes = result[kind].find((rule) => rule.id === ruleId)?.nodes || [];
      return {
        kind, count: nodes.length,
        items: nodes.slice(0, limit).map((node) => {
          const check = [...node.any, ...node.all, ...node.none].find((check) => check.data);
          const data = check?.data || {};
          const targetPath = (node.target || []).flat();
          let element = null;
          try {
            let root = document;
            for (const selector of targetPath) {
              element = root?.querySelector(selector) || null;
              root = element?.shadowRoot;
            }
          } catch { /* Keep the axe selector. */ }
          const text = String(element?.innerText || "").replace(/\s+/g, " ").trim();
          return {
            text: text.length > 140 ? text.slice(0, 139) + "…" : text,
            where: targetPath.join(" → "),
            targetPath,
            ratio: kind !== "incomplete" && Number.isFinite(data.contrastRatio) ? data.contrastRatio + ":1" : "",
            required: data.expectedContrastRatio || "",
            foreground: data.fgColor || "", background: data.bgColor || "", shadow: data.shadowColor || "",
            size: data.fontSize || "", weight: data.fontWeight === "bold" ? "fet" : data.fontWeight === "normal" ? "normal" : "",
            reason: kind === "incomplete" ? reasons[data.messageKey] || "Axe kunne ikke avgjøre kontrasten sikkert." : "",
            reasonCode: kind === "incomplete" ? data.messageKey || "" : "",
          };
        }),
      };
    });
    return { level, criterion, ruleId, groups };
  });
  return { engine: result.testEngine.version, frames: document.querySelectorAll("iframe, frame").length, levels };
}

export function parseContrastOptions(tokens) {
  const switches = new Set(["-fokus", "-bakgrunn", "-hover"]);
  return {
    modes: [...new Set(tokens.map((token) => token.toLowerCase()).filter((token) => switches.has(token)))],
    argument: tokens.filter((token) => !switches.has(token.toLowerCase())).join(" "),
  };
}

export async function runContrastProbe({ action, input }) {
  const color = (value) => {
    const match = /^rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)$/.exec(value || "");
    return match ? match.slice(1, 4).map(Number).concat(Number(match[4] ?? 1)) : null;
  };
  const solid = (value) => color(value)?.[3] === 1;
  const ratio = (first, second) => {
    const luminance = (rgb) => rgb.slice(0, 3).reduce((sum, value, index) => {
      const channel = value / 255;
      return sum + [0.2126, 0.7152, 0.0722][index] * (channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4);
    }, 0);
    const a = luminance(first);
    const b = luminance(second);
    return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
  };
  const format = (value) => `${(Math.floor(value * 100) / 100).toFixed(2).replace(".", ",")}:1`;
  const text = (element) => String(element.getAttribute("aria-label") || element.innerText || element.getAttribute("title") || element.localName).replace(/\s+/g, " ").trim().slice(0, 120);
  const viewport = () => JSON.stringify([location.href, innerWidth, innerHeight, scrollX, scrollY, devicePixelRatio, visualViewport?.scale || 1]);
  const unsafePaint = (style) => Number(style.opacity) !== 1 || style.mixBlendMode !== "normal" ||
    style.filter !== "none" || (style.backdropFilter && style.backdropFilter !== "none") || style.transform !== "none" ||
    style.clipPath !== "none" || (style.maskImage && style.maskImage !== "none");
  const simplePaint = (element) => {
    for (let node = element; node; node = node.parentElement) if (unsafePaint(getComputedStyle(node))) return false;
    return true;
  };
  const background = (element) => {
    for (let node = element; node; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.backgroundImage !== "none") return "";
      const rgb = color(style.backgroundColor);
      if (!rgb) return "";
      if (rgb[3] === 1) return style.backgroundColor;
      if (rgb[3] > 0) return "";
    }
    return ""; // Do not assume a white canvas or a browser theme.
  };
  const selectorFor = (element) => {
    if (element.id && document.querySelectorAll(`#${CSS.escape(element.id)}`).length === 1) return `#${CSS.escape(element.id)}`;
    const parts = [];
    for (let node = element; node; node = node.parentElement) {
      const siblings = Array.from(node.parentElement?.children || []).filter((child) => child.localName === node.localName);
      parts.unshift(node.localName + (siblings.length > 1 ? `:nth-of-type(${siblings.indexOf(node) + 1})` : ""));
    }
    return parts.join(" > ");
  };
  const hit = (element, x, y) => element.contains(document.elementFromPoint(x, y));
  const visible = (element) => {
    const r = element.getBoundingClientRect();
    for (let node = element; node; node = node.parentElement) if (Number(getComputedStyle(node).opacity) === 0) return false;
    return r.width > 0 && r.height > 0 && r.left >= 0 && r.top >= 0 &&
      r.right <= innerWidth && r.bottom <= innerHeight && hit(element, (r.left + r.right) / 2, (r.top + r.bottom) / 2);
  };
  const targets = () => {
    const elements = Array.from(document.querySelectorAll("a[href],button,input:not([type=hidden]),select,textarea,summary,[tabindex],[contenteditable=true]"))
      .filter((element) => element.tabIndex >= 0 && !element.matches(":disabled,[aria-disabled=true]") && visible(element));
    return { total: elements.length, items: elements.slice(0, 12).map((element) => {
      const where = selectorFor(element);
      return { text: text(element), where, targetPath: [where] };
    }) };
  };
  const snapshot = (element) => {
    if (!element || !visible(element)) return null;
    const style = getComputedStyle(element);
    const sides = ["Top", "Right", "Bottom", "Left"].map((side) => [style[`border${side}Style`], style[`border${side}Width`], style[`border${side}Color`]]);
    return {
      bounds: JSON.stringify(element.getBoundingClientRect()),
      foreground: style.webkitTextFillColor || style.color, fill: background(element), surrounding: background(element.parentElement),
      outline: [style.outlineStyle, style.outlineWidth, style.outlineColor, style.outlineOffset],
      border: sides.every((side) => String(side) === String(sides[0])) ? sides[0] : null,
      borderSignature: JSON.stringify(sides), shadow: style.boxShadow, image: style.backgroundImage,
      decoration: style.textDecorationLine, focusVisible: element.matches(":focus-visible"),
      focused: document.activeElement === element, hovered: element.matches(":hover"),
      simple: simplePaint(element) && !element.getAnimations().some((animation) => animation.playState === "running"),
    };
  };
  const controlResult = ({ target, before, after, mode }) => {
    const unavailable = (note) => ({ ...target, note });
    if (!before || !after || (mode === "focus" ? !after.focused : !after.hovered)) return unavailable("Tilstanden kunne ikke måles.");
    if (mode === "focus" ? before.focused : before.hovered) return unavailable("Elementet var allerede i tilstanden før testen.");
    const row = { ...target, foreground: after.foreground, background: after.fill, focusVisible: after.focusVisible };
    if (!after.simple) return { ...row, note: "Kompleks eller bevegelig gjengivelse; må vurderes manuelt." };
    if (solid(after.foreground) && solid(after.fill)) row.textRatio = format(ratio(color(after.foreground), color(after.fill)));
    let indicator, neighbors, previous;
    if (String(before.outline) !== String(after.outline) && after.outline[0] === "solid" && parseFloat(after.outline[1]) > 0) {
      indicator = ["Omriss", after.outline[2], after.outline[1]];
      const offset = parseFloat(after.outline[3]);
      neighbors = offset < 0 ? [after.fill] : offset > 0 ? [after.surrounding] : [after.fill, after.surrounding];
      previous = before.outline[0] === "none" && offset > 0 ? before.surrounding : "";
    } else if (before.borderSignature !== after.borderSignature && after.border?.[0] === "solid" && parseFloat(after.border[1]) > 0) {
      indicator = ["Kant", after.border[2], after.border[1]];
      neighbors = [after.fill, after.surrounding];
      previous = before.border?.[0] === "solid" && before.border[1] === after.border[1] ? before.border[2] : "";
    } else if (before.fill !== after.fill && after.fill) {
      indicator = ["Flate", after.fill, ""];
      neighbors = [after.surrounding];
      previous = before.fill;
    }
    if (!indicator) return { ...row, note: "Ingen enkel endring i omriss, kant eller flate målt. Andre visuelle endringer kan finnes." };
    row.indicator = indicator.filter(Boolean).join(", ");
    if (solid(indicator[1]) && neighbors.every(solid) && after.shadow === "none" && after.image === "none") {
      row.adjacent = format(Math.min(...neighbors.map((neighbor) => ratio(color(indicator[1]), color(neighbor)))));
      row.adjacentColors = [...new Set(neighbors)].join(" / ");
    }
    if (before.bounds === after.bounds && solid(indicator[1]) && solid(previous) && before.shadow === "none" && before.image === "none" && after.shadow === "none" && after.image === "none") {
      row.change = format(ratio(color(indicator[1]), color(previous)));
      row.previousColor = previous;
    }
    if (!row.adjacent) row.note = "Nabofargene kunne ikke fastslås sikkert.";
    return row;
  };

  if (action === "targets") return targets();
  if (action === "snapshot") return snapshot(document.querySelector(input));
  if (action === "compare") return controlResult(input);
  if (action === "focus") {
    const candidates = targets();
    const original = document.activeElement;
    const scroll = [scrollX, scrollY];
    const items = [];
    try {
      for (const target of candidates.items) {
        const element = document.querySelector(target.where);
        const before = snapshot(element);
        if (before && !before.focused) {
          element.focus({ preventScroll: true });
          await new Promise((resolve) => setTimeout(resolve, 120));
        }
        items.push(controlResult({ target, before, after: snapshot(element), mode: "focus" }));
      }
    } finally {
      if (original?.isConnected && original !== document.body) original.focus({ preventScroll: true });
      else if (document.activeElement !== original) document.activeElement?.blur();
      if (scrollX !== scroll[0] || scrollY !== scroll[1]) window.scrollTo(...scroll);
    }
    return { total: candidates.total, items };
  }

  if (action === "prepare") {
    if (globalThis.webquestBackgroundProbe || (visualViewport?.scale || 1) !== 1) return { items: [], note: "Skjermbildemåling er ikke tilgjengelig i denne visningen." };
    if (innerWidth * innerHeight * devicePixelRatio ** 2 > 16000000) return { items: [], note: "Det synlige området er for stort for skjermbildemåling." };
    const entries = new Map();
    for (const level of input.levels) {
      for (const item of level.groups.find((group) => group.kind === "incomplete").items) {
        if (["bgGradient", "bgImage"].includes(item.reasonCode) && item.targetPath.length === 1) entries.set(item.where, item);
      }
    }
    const saved = [];
    const items = [];
    const restore = () => {
      for (const { element, value, priority, hadStyle } of saved) {
        if (element.style.getPropertyValue("-webkit-text-fill-color") !== "transparent" ||
            element.style.getPropertyPriority("-webkit-text-fill-color") !== "important") continue;
        element.style.setProperty("-webkit-text-fill-color", value, priority);
        if (!hadStyle && !element.getAttribute("style")) element.removeAttribute("style");
      }
    };
    const key = viewport();
    try {
      for (const item of entries.values()) {
        if (items.length >= 16) break;
        const nodes = document.querySelectorAll(item.where);
        if (nodes.length !== 1) continue;
        const element = nodes[0];
        if (!(element instanceof HTMLElement) || element.children.length || !visible(element) || !simplePaint(element)) continue;
        const style = getComputedStyle(element);
        const foreground = style.webkitTextFillColor || style.color;
        if (!solid(foreground) || style.textShadow !== "none" || style.textDecorationLine !== "none" ||
            style.webkitTextStrokeWidth !== "0px" || ["::before", "::after"].some((pseudo) => !["none", "normal"].includes(getComputedStyle(element, pseudo).content))) continue;
        const range = document.createRange();
        range.selectNodeContents(element);
        const points = Array.from(range.getClientRects()).slice(0, 12).flatMap((rect) =>
          [.2, .5, .8].flatMap((x) => [.25, .5, .75].map((y) => [rect.left + rect.width * x, rect.top + rect.height * y]))
        ).filter(([x, y]) => x >= 0 && y >= 0 && x < innerWidth && y < innerHeight && hit(element, x, y));
        if (!points.length) continue;
        saved.push({ element, value: element.style.getPropertyValue("-webkit-text-fill-color"), priority: element.style.getPropertyPriority("-webkit-text-fill-color"), hadStyle: element.hasAttribute("style") });
        element.style.setProperty("-webkit-text-fill-color", "transparent", "important");
        items.push({ text: item.text, where: item.where, targetPath: item.targetPath, foreground, points });
      }
    } catch (error) {
      restore();
      throw error;
    }
    if (items.length) {
      const token = String(Date.now()) + Math.random();
      const finish = () => {
        try {
          return key === viewport() && saved.every(({ element }, index) => {
            const rect = element.getBoundingClientRect();
            return getComputedStyle(element).webkitTextFillColor === "rgba(0, 0, 0, 0)" &&
              items[index].points.every(([x, y]) => x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom && hit(element, x, y));
          });
        } finally {
          restore();
          clearTimeout(timer);
          delete globalThis.webquestBackgroundProbe;
        }
      };
      const timer = setTimeout(finish, 8000);
      globalThis.webquestBackgroundProbe = { token, finish };
      return { token, items, total: entries.size, width: innerWidth, height: innerHeight };
    }
    return { items: [], total: entries.size };
  }
  if (action === "finish") {
    const probe = globalThis.webquestBackgroundProbe;
    return probe?.token === input ? probe.finish() : false;
  }
  if (action === "pixels") {
    const { png, probe } = input;
    const bytes = Uint8Array.from(atob(png), (byte) => byte.charCodeAt(0));
    const image = await createImageBitmap(new Blob([bytes], { type: "image/png" }));
    try {
      const xScale = image.width / probe.width;
      const yScale = image.height / probe.height;
      if (Math.abs(xScale - yScale) > .03 || image.width * image.height > 16000000) throw new Error("Skjermbildet samsvarer ikke med måleområdet.");
      const canvas = new OffscreenCanvas(image.width, image.height);
      const context = canvas.getContext("2d", { willReadFrequently: true });
      context.drawImage(image, 0, 0);
      return {
        total: probe.total,
        items: probe.items.map(({ points, ...item }) => {
          let minimum = Infinity;
          let worst = "";
          for (const [x, y] of points) {
            const pixel = context.getImageData(Math.floor(x * xScale), Math.floor(y * yScale), 1, 1).data;
            const measured = ratio(color(item.foreground), pixel);
            if (measured < minimum) {
              minimum = measured;
              worst = "#" + Array.from(pixel.slice(0, 3), (value) => value.toString(16).padStart(2, "0")).join("");
            }
          }
          return { ...item, background: worst, ratio: format(minimum), points: points.length };
        }),
      };
    } finally { image.close(); }
  }
}

export function renderContrastReport(url, report, { problemOnly = false, inspect } = {}) {
  const section = document.createElement("section");
  const add = (parent, tag, text) => {
    const node = document.createElement(tag);
    node.textContent = text;
    parent.append(node);
    return node;
  };
  add(section, "p", `Tekstkontrast på ${url}.`);
  if (!Array.isArray(report?.levels)) {
    add(section, "p", "Ingen kontrastdata i det nye rapportformatet. Oppdater WebQuest og analyseserveren til samme versjon.");
    return section;
  }
  add(section, "p", `Axe-core ${report.engine}. AA: 4,5:1 for vanlig tekst og 3:1 for stor tekst. AAA: 7:1 og 4,5:1. Samme element kan ha funn på begge nivåer.`);
  add(section, "p", "Axe-tabellene gjelder tekst i hoveddokumentet, slik siden vises før eventuelle tilleggsmålinger. Tekst i bilder og ikke-tekstlig kontrast dekkes ikke av axe-tabellene.");
  if (report.frames) add(section, "p", `Innebygde rammer ikke kontrollert: ${report.frames}.`);
  if (problemOnly) add(section, "p", "Viser brudd og funn som må vurderes manuelt. Beståtte detaljer er skjult.");

  const labels = { violations: "Brudd", incomplete: "Må vurderes manuelt", passes: "Bestått" };
  const summary = add(section, "table", "");
  summary.className = "responsive-table";
  add(summary, "caption", "Kontrast per nivå");
  const header = (table, labels) => {
    const row = add(add(table, "thead", ""), "tr", "");
    labels.forEach((label) => { add(row, "th", label).scope = "col"; });
  };
  const summaryColumns = ["Nivå", "Brudd", "Må vurderes manuelt", "Bestått"];
  header(summary, summaryColumns);
  const body = add(summary, "tbody", "");
  for (const level of report.levels) {
    const row = add(body, "tr", "");
    add(row, "th", `${level.level} (${level.criterion})`).scope = "row";
    level.groups.forEach((group, index) => { add(row, "td", String(group.count)).dataset.label = summaryColumns[index + 1]; });
  }
  for (const level of report.levels) {
    add(section, "h3", `Nivå ${level.level} (${level.criterion})`);
    if (!level.groups.some((group) => group.count)) add(section, "p", "Ingen tekstforekomster omfattet av denne testen.");
    for (const group of level.groups) {
      if (!group.count || (problemOnly && group.kind === "passes")) continue;
      const title = `${labels[group.kind]} på nivå ${level.level}`;
      add(section, "h4", title);
      if (group.count > group.items.length) add(section, "p", `Viser ${group.items.length} av ${group.count} forekomster.`);
      const table = add(section, "table", "");
      table.className = "responsive-table";
      add(table, "caption", title);
      const columns = ["Tekst", "Kontrast", "Krav", "Tekstfarge", "Bakgrunn", "Skrift", "Hvor"];
      if (group.kind === "incomplete") columns.push("Årsak");
      header(table, columns);
      const rows = add(table, "tbody", "");
      for (const item of group.items) {
        const row = add(rows, "tr", "");
        const values = [
          item.text || "(tekstutdrag ikke tilgjengelig)", item.ratio || "Ikke fastslått", item.required || "Ikke fastslått",
          item.foreground || "Ikke fastslått", item.background || "Ikke fastslått",
          [item.size, item.weight].filter(Boolean).join(", ") || "Ikke fastslått", item.where || "Ikke fastslått",
        ];
        if (item.shadow) values[5] += `; skyggefarge: ${item.shadow}`;
        if (group.kind === "incomplete") values.push(item.reason);
        values.forEach((value, index) => {
          const cell = add(row, index === 0 ? "th" : "td", value);
          if (index === 0) cell.scope = "row";
          cell.dataset.label = columns[index];
          if (index === 6 && item.inspectionRef && inspect) cell.append(document.createElement("br"), inspect(item.inspectionRef, `${title}: ${item.text || item.where}`));
        });
      }
    }
  }
  const extraTable = (title, columns, items, valuesFor) => {
    if (!items.length) return;
    const table = add(section, "table", "");
    table.className = "responsive-table";
    add(table, "caption", title);
    header(table, columns);
    const rows = add(table, "tbody", "");
    for (const item of items) {
      const row = add(rows, "tr", "");
      valuesFor(item).forEach((value, index) => {
        const cell = add(row, index === 0 ? "th" : "td", value || "Ikke fastslått");
        if (index === 0) cell.scope = "row";
        cell.dataset.label = columns[index];
        if (index === 0 && item.inspectionRef && inspect) cell.append(document.createElement("br"), inspect(item.inspectionRef, item.text || item.where));
      });
    }
  };
  if (report.backgroundProbe) {
    const probe = report.backgroundProbe;
    add(section, "h3", "Skjermbildemåling av usikre bakgrunner");
    add(section, "p", "Indikasjon: svakeste kontrast blant målte punkter bak tekstlinjene. Dette er ikke et sikkert minimum eller en WCAG-avgjørelse. Axe-resultatet over endres ikke.");
    if (probe.note) add(section, "p", probe.note);
    else add(section, "p", `Målt: ${probe.items.length} av ${probe.total} kandidater med bilde- eller gradientbakgrunn i axe-rapporten. Bare enkel tekst i synlig område kan måles.`);
    extraTable("Målte bakgrunnspunkter", ["Tekst", "Laveste målte kontrast", "Tekstfarge", "Bakgrunn ved svakeste punkt", "Punkter", "Hvor"], probe.items, (item) => [
      item.text, item.ratio, item.foreground, item.background, String(item.points), item.where,
    ]);
  }
  for (const [key, title, method] of [
    ["focusProbe", "Kontrast ved fokus", "Programmatisk fokus, ikke en test av tab-rekkefølge. Om :focus-visible slo inn vises i tabellen."],
    ["hoverProbe", "Kontrast ved hover", "Musepekeren flyttes over kontrollen, uten klikk."],
  ]) {
    const probe = report[key];
    if (!probe) continue;
    add(section, "h3", title);
    if (probe.note) add(section, "p", probe.note);
    else {
      add(section, "p", `${method} Undersøkt: ${probe.items.length} av ${probe.total} synlige kontroller. Tallene er indikasjoner fra beregnede CSS-farger, ikke WCAG-avgjørelser.`);
      add(section, "p", "Nabokontrast sammenlikner indikatoren med fargene rundt den. Tilstandsendring sammenlikner anslått farge før og etter. 3:1 er en relevant referanse for nødvendig visuell informasjon etter WCAG 1.4.11. Størrelse, areal og om indikatoren er nødvendig er ikke vurdert. Beståttfilteret gjelder bare axe-tabellene.");
    }
    extraTable(title, ["Kontroll", "Indikator", "Nabokontrast", "Tilstandsendring", "Tekstkontrast", "Hvor", "Merknad"], probe.items, (item) => {
      const focusState = key === "focusProbe" && typeof item.focusVisible === "boolean"
        ? `:focus-visible: ${item.focusVisible ? "ja" : "nei"}.` : "";
      return [
        item.text, item.indicator,
        item.adjacent ? `${item.adjacent} mot ${item.adjacentColors}` : "",
        item.change ? `${item.change} fra ${item.previousColor}` : "",
        item.textRatio ? `${item.textRatio} (${item.foreground} mot ${item.background})` : "",
        item.where, [focusState, item.note].filter(Boolean).join(" ") || "Må vurderes i sammenheng",
      ];
    });
  }
  return section;
}
