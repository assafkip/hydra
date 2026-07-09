import { describe, it, expect } from "vitest";
import { renderMarkdown, renderBriefMarkdown } from "../../src/chat/markdown.js";

// cd-ui (D10): the chat renders model output as SAFE markdown — escape-first, allowlist only.

describe("renderMarkdown headings (founder 2026-07-08: no raw ## hashtags)", () => {
  it("renders a ## heading as a clean bold line, never literal hashtags", () => {
    const out = renderMarkdown("## What I found\n\nThe domain is 2 days old.");
    expect(out).toContain("<strong>What I found</strong>"); // clean bold label
    expect(out).not.toContain("##"); // no raw hashtags
    expect(out).not.toContain("# What"); // no partial hashes either
  });
  it("handles #, ###, and indented headings too", () => {
    expect(renderMarkdown("# Summary")).toContain("<strong>Summary</strong>");
    expect(renderMarkdown("### Next steps")).toContain("<strong>Next steps</strong>");
    expect(renderMarkdown("### Next steps")).not.toContain("#");
  });
});

describe("renderMarkdown XSS-safety", () => {
  it("escapes injected HTML so a hostile value renders as literal text", () => {
    const out = renderMarkdown("<img src=x onerror=alert(1)> and <script>steal()</script>");
    // The dangerous bit is a LIVE tag. Escape-first makes both inert text (&lt;img…&gt;), so the
    // payload survives only as literal characters — never as an element the browser executes.
    expect(out).not.toMatch(/<img\b/i); // no live <img element (the &lt;img text is inert)
    expect(out).not.toMatch(/<script\b/i); // no live <script element
    expect(out).toContain("&lt;img src=x onerror=alert(1)&gt;"); // the whole payload is inert text
    expect(out).toContain("&lt;script&gt;");
  });

  it("escapes a hostile entity name inside backticks/bold (no tag injection through the allowlist)", () => {
    const out = renderMarkdown("the actor `<b onclick=x>evil</b>` is **<i>bad</i>**");
    expect(out).toContain('<code class="chat-node">'); // our tag
    expect(out).toContain('<strong class="chat-node">'); // our tag
    expect(out).not.toContain("<b onclick"); // their tag escaped
    expect(out).toContain("&lt;b onclick"); // proven escaped
  });
});

describe("renderMarkdown allowlist", () => {
  it("renders bold, code, lists, and paragraphs", () => {
    expect(renderMarkdown("**live**")).toContain('<strong class="chat-node">live</strong>');
    expect(renderMarkdown("`example.com`")).toContain('<code class="chat-node">example.com</code>');
    const list = renderMarkdown("- one\n- two");
    expect(list).toContain("<ul>");
    expect(list).toContain("<li>one</li>");
    expect(list).toContain("<li>two</li>");
    expect(renderMarkdown("hello")).toBe("<p>hello</p>");
  });

  it("keeps [run: …] citations but drops numeric [27] markers", () => {
    const out = renderMarkdown("operating now [27] per [run: Investigate example.com]");
    expect(out).not.toContain("[27]");
    expect(out).toContain("[run: Investigate example.com]");
  });
});

// sf-deliverables: the fuller brief renderer — clones the original synthesis.html renderMd feature set
// (headings/tables/lists/code/blockquote + inline) but ESCAPE-FIRST and with NO inline onclick + an
// http(s)-only link guard. These tests are the negative self-test the build verifies against.

describe("renderBriefMarkdown allowlist (faithful to the original renderMd)", () => {
  it("renders h1/h2/h3 headings as elements, not literal ## tokens", () => {
    const out = renderBriefMarkdown("# Title\n\n## Section\n\n### Sub");
    expect(out).toContain("<h1>Title</h1>");
    expect(out).toContain("<h2>Section</h2>");
    expect(out).toContain("<h3>Sub</h3>");
    expect(out).not.toContain("## Section"); // the literal token must be gone
  });

  it("renders a GFM table", () => {
    const out = renderBriefMarkdown("| a | b |\n| --- | --- |\n| 1 | 2 |");
    expect(out).toContain("<table>");
    expect(out).toContain("<th>a</th>");
    expect(out).toContain("<td>1</td>");
  });

  it("renders bold/italic/code, bullet lists, and blockquotes", () => {
    expect(renderBriefMarkdown("**b**")).toContain("<strong>b</strong>");
    expect(renderBriefMarkdown("*i*")).toContain("<em>i</em>");
    expect(renderBriefMarkdown("`c`")).toContain("<code>c</code>");
    const list = renderBriefMarkdown("- one\n- two");
    expect(list).toContain("<li>one</li>");
    expect(list).toContain("<li>two</li>");
    expect(renderBriefMarkdown("> quoted")).toContain("<blockquote>quoted</blockquote>");
  });

  it("renders [[entity]] as a clickable span WITHOUT an inline onclick (CSP)", () => {
    const out = renderBriefMarkdown("see [[Acme Corp]] now");
    expect(out).toContain('<span class="chat-node brief-entity">Acme Corp</span>');
    expect(out).not.toMatch(/onclick/i); // a cloned inline handler would be CSP-blocked
  });
});

describe("renderBriefMarkdown XSS-safety (escape-first + scheme guard)", () => {
  it("escapes injected HTML so a hostile value renders as literal text", () => {
    const out = renderBriefMarkdown("<img src=x onerror=alert(1)> and <script>steal()</script>");
    expect(out).not.toMatch(/<img\b/i);
    expect(out).not.toMatch(/<script\b/i);
    expect(out).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(out).toContain("&lt;script&gt;");
  });

  it("renders a table cell containing < and & as literal text inside <td>", () => {
    const out = renderBriefMarkdown("| x | y |\n| --- | --- |\n| a<b | c&d |");
    expect(out).toContain("<td>a&lt;b</td>");
    expect(out).toContain("<td>c&amp;d</td>");
    expect(out).not.toMatch(/<td>a<b/); // not a live tag
  });

  it("makes an http(s) link an anchor but DROPS javascript:/data:/vbscript:/protocol-relative", () => {
    expect(renderBriefMarkdown("[ok](http://good.com)")).toContain('<a href="http://good.com"');
    expect(renderBriefMarkdown("[ok](https://good.com)")).toContain('<a href="https://good.com"');
    // every dangerous scheme degrades to the plain text — NO anchor, NO href.
    for (const bad of ["[x](javascript:alert(1))", "[x](data:text/html,<script>)", "[x](vbscript:msgbox)", "[x](//evil.com)"]) {
      const out = renderBriefMarkdown(bad);
      expect(out).not.toMatch(/<a\s+href/i);
      expect(out).not.toMatch(/javascript:|vbscript:|data:text/i);
    }
  });

  it("strips control chars so an obfuscated scheme (java\\tscript:) is still dropped", () => {
    const out = renderBriefMarkdown("[x](java\tscript:alert(1))");
    expect(out).not.toMatch(/<a\s+href/i);
  });

  it("rejects an http url carrying attribute-breakout chars (defense-in-depth)", () => {
    // escape-first already turns the " into &quot; (inert in a double-quoted href), but the guard also
    // refuses the url outright, so no half-broken href ships.
    const out = renderBriefMarkdown('[x](https://a.com" onmouseover="alert(1))');
    expect(out).not.toMatch(/onmouseover/i);
    expect(out).not.toMatch(/<a\s+href/i);
  });
});
