// The "Full tool" upsell manifest (free/pro split, founder 2026-07-08). Everything a desktop/server
// investigation tool (like four_points) does that a 100%-client browser app CANNOT — the nudge.
//
// WHY these aren't in the free web app: each needs something a browser tab can't provide — a proxy or a
// server-side runner (CORS-blocked providers, Apify/MCP scrapers, browser rendering), a long multi-step
// analytic workflow with file/subagent orchestration (the 18 SATs, the case lifecycle), a local filesystem
// + OCR engine + court-grade capture (evidence chain-of-custody, multi-report ingestion), or an Obsidian
// vault. Sourced from the actual kipi/four_points capabilities: the OSINT skill (55+ Apify actors + the
// proxied providers), the structured-analysis skill (18 CIA/IC techniques), the q-* investigation commands,
// the evidence-capture protocol, and the ./invctl ingestion + correlation layer. It is a MANIFEST, not a
// runner — nothing here executes in the browser; that is the point.

export interface FullToolCapability {
  /** Human name shown on the row. */
  name: string;
  /** One line: what it does. */
  detail: string;
}

export interface FullToolGroup {
  /** Section heading. */
  category: string;
  /** One line under the heading: WHY the browser can't do it. */
  blurb: string;
  items: FullToolCapability[];
}

// The one-line promise at the top of the page.
export const FULL_TOOL_NOTE =
  "These run in the full desktop/server investigation tool, not this free browser app. A browser tab can't reach CORS-blocked sources, run server-side scrapers, drive a long multi-step analytic workflow, OCR files on disk, or hold court-grade evidence. Everything below is what you get when you move up from the web tool.";

export const FULL_TOOL_CAPABILITIES: FullToolGroup[] = [
  {
    category: "Advanced OSINT (proxy / server-side)",
    blurb: "Sources with no browser CORS, or that run server-side — reachable only through a proxy or a runner.",
    items: [
      { name: "VirusTotal", detail: "Reputation + detection stats for a domain / IP / hash / URL" },
      { name: "GreyNoise", detail: "Internet-scanner vs targeted-actor classification for an IP" },
      { name: "SecurityTrails", detail: "Deep subdomain + historical DNS enumeration" },
      { name: "AbuseIPDB / Pulsedive", detail: "IP abuse-confidence + threat-indicator context" },
      { name: "Hunter.io", detail: "Email discovery for a domain (operator contact anchors)" },
      { name: "Exa AI", detail: "Neural / semantic search + company + people" },
      { name: "WhoisXML / HIBP / abuse.ch", detail: "Reverse-WHOIS portfolios, breach exposure, malware IOC feeds" },
      { name: "Apify social scraping (55+ actors)", detail: "Instagram, Facebook, TikTok, YouTube, X, LinkedIn, Telegram, Google Maps, Reddit — profiles, posts, comments, followers" },
      { name: "Bright Data", detail: "Geo-targeted Google / Bing / Yandex + CAPTCHA / authwall bypass" },
      { name: "Browser forensics", detail: "Render a JS scam page headlessly — reach the payout wallet, script host, and network hosts a static fetch can't see" },
    ],
  },
  {
    category: "Structured analytic techniques (18 CIA/IC methods)",
    blurb: "A long, multi-step, cited analytic workflow with subagent orchestration — beyond a browser chat.",
    items: [
      { name: "Analysis of Competing Hypotheses (ACH)", detail: "Score every hypothesis against all evidence to find the least-disproven" },
      { name: "Key Assumptions Check", detail: "Surface + stress-test the load-bearing assumptions behind a judgment" },
      { name: "Devil's Advocacy + Red Hat", detail: "Argue the opposite case; model the adversary's own view" },
      { name: "Premortem + What-If", detail: "Assume the assessment is wrong / an event happened — work backward to why" },
      { name: "Deception Detection", detail: "Test whether you're being deliberately misled (MOM / POP / MOSES / EVE)" },
      { name: "Cross-Impact Matrix + Bowtie", detail: "Map how factors drive each other; model threat pathways + barriers" },
      { name: "Alternative Futures + Counterfactual", detail: "Scenario-plan divergent outcomes; test if one changed fact flips the conclusion" },
      { name: "Contrasting Narratives", detail: "Build the strongest competing stories, then adjudicate on evidence" },
      { name: "Adaptive + guided modes", detail: "Auto-select the right techniques, or a full walkthrough — 18 techniques total, every claim cited" },
    ],
  },
  {
    category: "Investigation workflow (case lifecycle)",
    blurb: "A managed case from scope to deliverable, with tradecraft gates — a stateful multi-session workflow.",
    items: [
      { name: "Scope + hypotheses", detail: "Frame the case: hypotheses + collection requirements as the source of truth" },
      { name: "Target profiles", detail: "Build + maintain a profile per subject (handles, infra, wallets)" },
      { name: "Collection planning + security-stack recon", detail: "Plan OSINT collection; profile a company's security tools from job posts + ATS" },
      { name: "Adversarial challenge + reality-check gates", detail: "Force a structured challenge of assumptions + a sanity check before findings are written" },
      { name: "Timelines + entity linking", detail: "Build a chronological event timeline; link entities across evidence" },
      { name: "Briefing + export + handoff", detail: "Produce the customer brief, export findings, debrief, and hand off state to the next session" },
    ],
  },
  {
    category: "Evidence & chain-of-custody",
    blurb: "Court-grade capture that needs a local filesystem + a headless renderer + immutable integrity records.",
    items: [
      { name: "EV-NNNN evidence capture", detail: "Every item captured at collection time: full-page PDF + PNG render, one immutable folder per item" },
      { name: "Integrity hashing", detail: "SHA-256 of every capture, recorded in a chain-of-custody file that never changes after capture" },
      { name: "Evidence tiers (T1 / T2 / T3)", detail: "Every attribution graded by source non-fakeability; T3-only never shown as confirmed" },
      { name: "Client-provided evidence handling", detail: "Screenshot-only items (lost original URL) captured with an honest evidentiary label for an attorney" },
    ],
  },
  {
    category: "Deep ingestion & correlation",
    blurb: "Reads dense files on disk, OCRs them, and correlates across many reports — needs an OCR engine + a vault.",
    items: [
      { name: "Multi-language OCR", detail: "Dense PDFs, scanned docs, and images OCR'd in English, Arabic, Farsi, Hebrew, Russian, Chinese" },
      { name: "Cross-report entity correlation", detail: "Find the same entity across many reports + auto-link aliases" },
      { name: "Entity consolidation + role classification", detail: "LLM dedup of entities + role tagging with a per-case schema" },
      { name: "Actor dossiers", detail: "Cross-report dossier per key actor" },
      { name: "Obsidian vault + canvas export", detail: "The whole case as a linked Obsidian graph + canvas, not just an in-browser view" },
    ],
  },
];

/** Flat count for the page header. */
export function fullToolCount(): number {
  return FULL_TOOL_CAPABILITIES.reduce((n, g) => n + g.items.length, 0);
}
