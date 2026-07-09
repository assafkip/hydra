// cd-ui (PRD chat-dock D10): the chat's markdown renderer, ported from
// investigations/webapp/templates/_chat.html `md()`. XSS-safe BY CONSTRUCTION: it HTML-escapes
// the input FIRST, then layers a fixed allowlist (inline code, **bold**, bullet lists,
// paragraphs) on top of the already-escaped text. A hostile entity value or model output
// (`<img onerror=…>`, `<script>`) therefore renders as LITERAL text — the only tags in the
// output are the ones this function inserts. Kept pure (no DOM) so the escape contract is
// node-testable.

const ESCAPE: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };

/** Render agent/Q&A markdown to safe HTML. Escape-first; allowlist only. */
export function renderMarkdown(text: string): string {
  if (!text) return "";
  let h = String(text).replace(/[&<>]/g, (c) => ESCAPE[c]);
  h = h.replace(/\s*\[\d+\]/g, ""); // drop bare [27]-style numeric citation markers (keeps [run: …])
  // Headings: the chat renderer has NO heading style, so a model `## Findings` used to render as literal
  // "## Findings" (founder 2026-07-08: "not stylized text ... just hashtags"). Strip the #'s and bold the
  // line so a heading reads as a clean bold label, never raw hashtags.
  h = h.replace(/^\s{0,3}#{1,6}\s+(.+?)\s*$/gm, "<strong>$1</strong>");
  // `code` and **bold** mark entity names → tag them clickable (.chat-node spotlights on click).
  h = h.replace(/`([^`]+)`/g, '<code class="chat-node">$1</code>');
  h = h.replace(/\*\*(.+?)\*\*/g, '<strong class="chat-node">$1</strong>');
  h = h.replace(/(?:^[-*] .+(?:\n|$))+/gm, (b) =>
    "<ul>" + b.trim().split("\n").map((l) => `<li>${l.replace(/^[-*] /, "")}</li>`).join("") + "</ul>",
  );
  h = h
    .split(/\n{2,}/)
    .map((p) => (/^<(ul|ol|h\d|blockquote)/.test(p.trim()) ? p : p.trim() ? `<p>${p.replace(/\n/g, "<br>")}</p>` : ""))
    .join("");
  return h;
}

// sf-deliverables: the BRIEF/deliverable markdown renderer — a FULLER sibling of renderMarkdown that
// ports the original deliverable renderer (investigations/webapp/templates/synthesis.html `renderMd`
// + `inlineMd`, also used by brief.html/entity.html): fenced code, GFM tables, h1-h3, blockquote,
// bullet lists, paragraphs; inline **bold**, *italic*, `code`, [[entity]] nav, [text](url) links.
//
// Why a SEPARATE function and not an extension of renderMarkdown: the original has TWO renderers — the
// chat `md()` (ported to renderMarkdown above) and the deliverable `renderMd()`. Keeping them split
// preserves chat-dock parity (extending the shared renderer would make chat render headings/tables the
// chat original never did).
//
// SECURITY HARDENING over the original (scar: the client is a zero-retention BYO-key tool — D9 / the
// kipi-web "No inline handlers" CSP). Two deltas from the server `renderMd`, both REQUIRED, neither a
// behavior change for trusted content:
//   1. ESCAPE-FIRST: the whole input is HTML-escaped before any allowlist tag is layered, so a hostile
//      brief/entity value (`<img onerror=…>`, `<script>`) renders as LITERAL text. The server renderMd
//      escapes only inside code blocks (it trusts its own LLM output server-side); the client cannot.
//   2. NO inline `onclick`: the server inlineMd emits `onclick="window.kipiNav.entity(…)"`, which the
//      client CSP (`script-src 'self'`) blocks. [[entity]] becomes a `.brief-entity` element; a CLICK
//      DELEGATE on the deliverables page handles nav (mirrors the chat dock `.chat-node` delegate).
// Kept pure (no DOM) so the escape + url-guard contract is node-testable.

const BRIEF_ESCAPE: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function escBrief(s: string): string {
  return s.replace(/[&<>"']/g, (c) => BRIEF_ESCAPE[c]);
}

/** Allow ONLY absolute http(s) urls (after stripping control chars + trimming). Returns the cleaned
 *  url for an href, or null for everything else — `javascript:`/`data:`/`vbscript:`/`java\tscript:` and
 *  protocol-relative `//evil` all return null (escape-first stops attribute breakout, NOT a dangerous
 *  scheme firing on click). The href is rendered from the already-escaped substring, so quotes/angles
 *  in it are inert. */
function safeHttpUrl(url: string): string | null {
  const cleaned = url.replace(/[\u0000-\u001f\u007f]/g, "").trim(); // strip control chars (java\tscript:)
  if (!/^https?:\/\//i.test(cleaned)) return null; // absolute http(s) only (blocks js:/data:/vbscript:/protocol-relative)
  // defense-in-depth (review finding 2): a real URL has no escaped quote/angle/whitespace — those only
  // appear when an attacker stuffs attribute-breakout chars into [](url). Inert today (escape-first
  // neutralized them + a double-quoted href cannot be broken out of), rejected anyway so the href is clean.
  if (/&quot;|&lt;|&gt;|\s/.test(cleaned)) return null;
  return cleaned;
}

/** Inline marks, applied to ALREADY-ESCAPED text (so `&lt;`/`&amp;` stay literal). Order matters:
 *  [[entity]] and [text](url) before bold/italic so a `*` inside a link text isn't mangled. */
function inlineBriefMd(s: string): string {
  // [[entity]] -> a clickable span (NO inline handler — the page's click delegate navigates).
  s = s.replace(/\[\[(.+?)\]\]/g, '<span class="chat-node brief-entity">$1</span>');
  // [text](url) -> anchor for http(s) only; a blocked scheme degrades to the plain text (no link).
  s = s.replace(/\[([^\]]+?)\]\(([^)]+?)\)/g, (_m, text: string, url: string) => {
    const safe = safeHttpUrl(url);
    return safe ? `<a href="${safe}" target="_blank" rel="noopener noreferrer">${text}</a>` : text;
  });
  s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/\*(.+?)\*/g, "<em>$1</em>");
  s = s.replace(/`([^`]+?)`/g, "<code>$1</code>");
  return s;
}

/** Render a deliverable brief's markdown to safe HTML (escape-first; allowlist + http(s)-only links). */
export function renderBriefMarkdown(text: string): string {
  if (!text) return "";
  let h = escBrief(String(text)); // ESCAPE-FIRST: the whole input, before any tag is layered
  // fenced code: content is already escaped, so just wrap it.
  h = h.replace(/```([\s\S]*?)```/g, (_m, c: string) => `<pre class="md-code"><code>${c}</code></pre>`);
  // GFM tables: a run of `|…|` lines whose 2nd row is the `---`/`:--:` separator.
  h = h.replace(/(?:^\|.+\|\s*\n?)+/gm, (block) => {
    const rows = block.trim().split("\n").filter((r) => r.trim());
    if (rows.length < 2) return block;
    const cells = rows.map((r) => r.split("|").slice(1, -1).map((c) => c.trim()));
    if (!cells[1] || !cells[1].every((c) => /^:?-+:?$/.test(c))) return block; // not a real separator row
    const head = "<tr>" + cells[0].map((c) => `<th>${inlineBriefMd(c)}</th>`).join("") + "</tr>";
    const body = cells.slice(2).map((r) => "<tr>" + r.map((c) => `<td>${inlineBriefMd(c)}</td>`).join("") + "</tr>").join("");
    return `<table>${head}${body}</table>\n`;
  });
  // headings (text left as escaped literal, matching the server renderMd — no inline marks in headings).
  h = h.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  h = h.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  h = h.replace(/^# (.+)$/gm, "<h1>$1</h1>");
  // blockquote: `>` is now `&gt;` after escape-first.
  h = h.replace(/^&gt; (.+)$/gm, "<blockquote>$1</blockquote>");
  // bullet lists.
  h = h.replace(/^(?:- (.+)(?:\n|$))+/gm, (block) => {
    const items = block.trim().split("\n").map((l) => l.replace(/^- /, ""));
    return "<ul>" + items.map((i) => `<li>${inlineBriefMd(i)}</li>`).join("") + "</ul>\n";
  });
  // paragraphs: anything not already a block tag.
  h = h
    .split("\n\n")
    .map((p) => {
      const t = p.trim();
      if (/^<(h\d|ul|ol|blockquote|pre|table)/.test(t)) return p;
      if (!t) return "";
      return `<p>${inlineBriefMd(p)}</p>`;
    })
    .join("\n");
  return h;
}
