// sf-exports: the downstream-tool serializers — a verbatim port of investigations/export/intel_exports.py
// (export_stix / export_csv / export_misp). PURE functions over an already-key-redacted ExportModel (the
// session layer owns the vault + redaction; this module never touches a vault or a key). The bytes are
// generated in-browser and downloaded via the existing download() Blob primitive — nothing leaves the page.

export interface ExportEntity {
  id: number; // a stable 1-based index (the SQLite rowid analog — the client has no rowid; signed divergence)
  name: string; // redacted canonical label
  type: string; // the entity_type (the STIX_TYPE_MAP / MISP_TYPE_MAP key)
  role: string; // the EXPLICIT role (correction > AI overlay), "" when none — the Python notes analog
  threatScore: number;
  degree: number;
  reportCount: number;
  clusters: string[]; // the cluster NAMES this entity is a member of
}

export interface ExportRel {
  srcId: number; // ExportEntity.id of the source (for the STIX source_ref join)
  dstId: number; // ExportEntity.id of the target
  srcName: string; // for the relationships.csv src column
  dstName: string;
  relType: string;
  confidence: string;
  evidence: string;
}

export interface ExportCluster {
  name: string;
  kind: string;
  description: string;
  members: string[]; // member entity NAMES
}

export interface ExportModel {
  investigationName: string;
  entities: ExportEntity[];
  relationships: ExportRel[];
  clusters: ExportCluster[];
}

export interface ExportFiles {
  stix: string;
  misp: string;
  entitiesCsv: string;
  relationshipsCsv: string;
  clustersCsv: string;
}

// intel_exports.py STIX_TYPE_MAP (verbatim).
const STIX_TYPE_MAP: Record<string, string> = {
  ip: "ipv4-addr",
  domain: "domain-name",
  url: "url",
  email: "email-addr",
  telegram_channel: "user-account",
  handle: "user-account",
  crypto_wallet: "x-crypto-wallet",
  hash_sha256: "file",
  hash_md5: "file",
  phone: "x-phone-number",
  person: "identity",
};

// intel_exports.py misp_type_map (verbatim).
const MISP_TYPE_MAP: Record<string, string> = {
  ip: "ip-src",
  domain: "domain",
  url: "url",
  email: "email-src",
  hash_sha256: "sha256",
  hash_md5: "md5",
  handle: "text",
  telegram_channel: "text",
  crypto_wallet: "btc",
};

// the roles MISP keeps (Python: notes NOT NULL AND NOT noise/source/infra → operator/channel/ioc).
const MISP_ROLES = new Set(["operator", "channel", "ioc"]);

function uuid(): string {
  return crypto.randomUUID();
}

// the intel_exports.py _now_z() format: %Y-%m-%dT%H:%M:%S.000Z (whole-second precision, .000 ms).
function stixNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, ".000Z");
}

/** export_stix: a STIX 2.1 bundle — an identity SDO + one SDO/observable per mapped entity + a relationship
 *  SRO per typed relationship whose BOTH endpoints mapped. */
export function buildStixBundle(model: ExportModel): string {
  const now = stixNow();
  const objects: Record<string, unknown>[] = [];

  objects.push({
    type: "identity",
    spec_version: "2.1",
    id: `identity--${uuid()}`,
    created: now,
    modified: now,
    name: model.investigationName,
    identity_class: "organization",
  });

  const oidByEntityId = new Map<number, string>();
  for (const e of model.entities) {
    const stixType = STIX_TYPE_MAP[e.type];
    if (!stixType) continue; // an unmapped type is skipped (Python: no STIX_TYPE_MAP entry → continue)
    const oid = `${stixType}--${uuid()}`;
    oidByEntityId.set(e.id, oid);
    const obj: Record<string, unknown> = { type: stixType, spec_version: "2.1", id: oid, created: now, modified: now };
    if (stixType === "user-account") {
      obj.user_id = e.name.replace(/^@/, "");
      obj.account_type = e.name.includes("t.me/") ? "telegram" : "social";
    } else if (stixType === "file") {
      obj.hashes = { [e.type === "hash_sha256" ? "SHA-256" : "MD5"]: e.name };
    } else if (stixType === "identity") {
      obj.name = e.name;
      obj.identity_class = "individual";
      obj.roles = e.role ? [e.role] : [];
    } else {
      obj.value = e.name; // ipv4-addr / domain-name / url / email-addr / x-crypto-wallet / x-phone-number
    }
    objects.push(obj);
  }

  for (const r of model.relationships) {
    const sid = oidByEntityId.get(r.srcId);
    const did = oidByEntityId.get(r.dstId);
    if (!sid || !did) continue; // an endpoint that didn't map (unmapped type / dropped) → skip the SRO
    objects.push({
      type: "relationship",
      spec_version: "2.1",
      id: `relationship--${uuid()}`,
      created: now,
      modified: now,
      relationship_type: r.relType,
      source_ref: sid,
      target_ref: did,
      description: r.evidence || "",
      x_kipi_confidence: r.confidence,
    });
  }

  return JSON.stringify({ type: "bundle", id: `bundle--${uuid()}`, objects }, null, 2);
}

/** export_misp: a lightweight MISP event — one Attribute per entity whose EXPLICIT role ∈ {operator,channel,ioc}. */
export function buildMispEvent(model: ExportModel): string {
  const attributes: Record<string, unknown>[] = [];
  for (const e of model.entities) {
    if (!MISP_ROLES.has(e.role)) continue; // Python: notes NOT NULL AND NOT noise/source/infra
    const mispType = MISP_TYPE_MAP[e.type];
    if (!mispType) continue;
    attributes.push({
      type: mispType,
      category: mispType === "ip-src" || mispType === "domain" || mispType === "url" ? "Network activity" : "Other",
      value: e.name,
      to_ids: e.role === "ioc" || e.role === "operator",
      comment: `role=${e.role} score=${e.threatScore || 0}`,
    });
  }
  const d = new Date();
  const event = {
    Event: {
      info: `kipi-investigations: ${model.investigationName}`,
      date: d.toISOString().slice(0, 10),
      timestamp: String(Math.floor(d.getTime() / 1000)),
      distribution: "0",
      threat_level_id: "2",
      analysis: "1",
      published: false,
      Attribute: attributes,
    },
  };
  return JSON.stringify(event, null, 2);
}

// RFC-4180: quote a cell with comma/quote/CR/LF; double embedded quotes. Rows end CRLF.
function csvCell(v: string | number): string {
  let s = String(v ?? "");
  // CSV-injection defense (OWASP, codex impl-review): a cell starting with = + - @ TAB or CR is executed as
  // a FORMULA by Excel / Google Sheets. Investigation data is adversary-controlled (a crafted domain/handle/
  // evidence string like `=cmd|...`), so prefix a single quote → the cell renders as literal text. Numeric
  // columns are non-negative so they never trigger this.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
function csvRow(cells: (string | number)[]): string {
  return cells.map(csvCell).join(",") + "\r\n";
}

/** export_csv entities.csv — id,name,type,role,threat_score,degree,report_count,clusters. */
export function buildEntitiesCsv(model: ExportModel): string {
  let out = csvRow(["id", "name", "type", "role", "threat_score", "degree", "report_count", "clusters"]);
  for (const e of model.entities) {
    out += csvRow([e.id, e.name, e.type, e.role, e.threatScore || 0, e.degree || 0, e.reportCount || 0, e.clusters.join(",")]);
  }
  return out;
}

/** export_csv typed_relationships.csv — src,rel_type,dst,confidence,evidence. */
export function buildRelationshipsCsv(model: ExportModel): string {
  let out = csvRow(["src", "rel_type", "dst", "confidence", "evidence"]);
  for (const r of model.relationships) {
    out += csvRow([r.srcName, r.relType, r.dstName, r.confidence, r.evidence || ""]);
  }
  return out;
}

/** export_csv clusters.csv — cluster,kind,description,members (members joined ' | ' per the Python). */
export function buildClustersCsv(model: ExportModel): string {
  let out = csvRow(["cluster", "kind", "description", "members"]);
  for (const c of model.clusters) {
    out += csvRow([c.name, c.kind || "", c.description || "", c.members.join(" | ")]);
  }
  return out;
}

/** All five export artifacts from one model. */
export function buildExportFiles(model: ExportModel): ExportFiles {
  return {
    stix: buildStixBundle(model),
    misp: buildMispEvent(model),
    entitiesCsv: buildEntitiesCsv(model),
    relationshipsCsv: buildRelationshipsCsv(model),
    clustersCsv: buildClustersCsv(model),
  };
}
