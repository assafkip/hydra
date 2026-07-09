// ca-core: the PURE analyst-corrections projection. An analyst override re-labels an EXISTING entity's
// ROLE (operator/channel/ioc/source/infra/noise) or TYPE (a surface type). It is DISPLAY-ONLY (codex D2):
// it changes record.role / record.type (and a graph node's role / entityType) — it NEVER mutates the
// identity ref, never rekeys the store, never adds/removes an entity, and never touches grade / source
// counts / promotion (an analyst label is judgment, not fabricated corroboration). Keyed by the ONE
// canonKey (codex D3) so it can never orphan on an alias/case drift.

import { canonKey, type EntityStore, type EntityRecord } from "./db.js";
import type { GraphModel } from "../graph/model.js";
import { CONSOLIDATE_ROLES, SURFACE_TYPES } from "./consolidate.js";

export const PREDICATES = ["role", "type"] as const;
export const ROLE_VALUES = new Set<string>(CONSOLIDATE_ROLES);
export const TYPE_VALUES = new Set<string>(SURFACE_TYPES);

/** A correction is valid only for a known predicate + a value from that predicate's fixed allowlist. */
export function isValidCorrection(predicate: string, value: string): boolean {
  if (predicate === "role") return ROLE_VALUES.has(value);
  if (predicate === "type") return TYPE_VALUES.has(value);
  return false;
}

/** canonKey -> the analyst overrides for that entity (validated values only). */
export type CorrectionMap = Record<string, { role?: string; type?: string }>;

/** A NEW store with each entity's role / display type overridden by its canonKey. Identity (ref), grade,
 *  promoted, sourceCount, runs, and connections are untouched (codex D2). A correction for an entity not
 *  in the store is a no-op (codex D4: never invents an entity). */
export function applyCorrections(store: EntityStore, map: CorrectionMap): EntityStore {
  if (!map || Object.keys(map).length === 0) return store;
  const entities: Record<string, EntityRecord> = {};
  for (const [key, rec] of Object.entries(store.entities)) {
    const corr = map[key];
    if (!corr) {
      entities[key] = rec;
      continue;
    }
    entities[key] = {
      ...rec,
      role: corr.role ?? rec.role,
      type: corr.type ?? rec.type, // DISPLAY only — rec.ref (identity) is NOT changed, so the key stays
    };
  }
  return { ...store, entities };
}

/** A NEW model with each non-objective node's role / display entityType overridden by its canonKey. Nodes
 *  are never added or removed (codex D1/D2). A role correction sets node.role (the renderer prefers it). */
export function applyCorrectionsToModel(model: GraphModel, map: CorrectionMap): GraphModel {
  if (!map || Object.keys(map).length === 0) return model;
  const nodes = model.nodes.map((n) => {
    if (n.kind === "objective") return n;
    const corr = map[canonKey(n.entityType, n.label)];
    if (!corr) return n;
    return {
      ...n,
      role: corr.role ?? n.role,
      entityType: corr.type ?? n.entityType, // display only
    };
  });
  return { ...model, nodes };
}
