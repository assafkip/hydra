// LIGHT TABLE surface (Hydra redesign 2026-07-06). The "drawing on a bench": a calm grid + ruler
// ticks drawn on a canvas BEHIND the cytoscape layer, transformed by the live cy pan/zoom so it
// moves WITH the graph (the graph reads as ink laid on drafting paper, not a floating force cloud).
//
// Pure render, zero egress: it draws lines from the theme CSS vars (--grid / --tick / --hair) onto
// its own 2D canvas. No data, no DOM text, no network. Redraws on cy 'render' (fires on pan/zoom/
// resize/layout) and on theme toggle. Detached + GC'd by destroy().

import type { Core } from "cytoscape";

// Grid spacing in MODEL units at zoom 1. The step adapts across zoom so the on-screen grid never
// gets too dense or too sparse (a drafting grid stays legible whether you're zoomed in or out).
const BASE_STEP = 56;
const MIN_SCREEN_STEP = 26; // px — below this the grid coarsens (×2)
const MAX_SCREEN_STEP = 108; // px — above this the grid refines (÷2)
const TICK_LEN = 6; // px ruler tick length along the top/left rails
const MAJOR_EVERY = 5; // every 5th grid line is a stronger "major" rule (drafting-paper feel)

interface SurfaceTokens {
  grid: string;
  tick: string;
  hair: string;
}

export class GraphSurface {
  private canvas: HTMLCanvasElement;
  private ctx: CanvasRenderingContext2D | null;
  private cy: Core;
  private container: HTMLElement;
  private tokens: SurfaceTokens;
  private ro: ResizeObserver | null = null;
  private onRender = (): void => this.redraw();

  constructor(container: HTMLElement, cy: Core) {
    this.cy = cy;
    this.container = container;
    this.tokens = readSurfaceTokens();
    this.canvas = document.createElement("canvas");
    this.canvas.className = "cy-surface";
    // Sit inside the graph pane, behind the cytoscape canvases (which get their own stacking
    // context via #cy z-index:0). Pointer-events off so it never eats a graph gesture.
    Object.assign(this.canvas.style, {
      position: "absolute",
      inset: "0",
      width: "100%",
      height: "100%",
      zIndex: "0",
      pointerEvents: "none",
    } as CSSStyleDeclaration);
    this.ctx = this.canvas.getContext("2d");
    // Insert as the container's previous sibling so it paints under #cy (same z, earlier in DOM).
    const parent = container.parentElement ?? container;
    if (container.parentElement) parent.insertBefore(this.canvas, container);
    else container.appendChild(this.canvas);

    this.cy.on("render", this.onRender);
    if (typeof ResizeObserver !== "undefined") {
      this.ro = new ResizeObserver(() => this.redraw());
      this.ro.observe(container);
    }
    this.redraw();
  }

  /** Re-read the theme tokens (light↔dark) and repaint. */
  themeChanged(): void {
    this.tokens = readSurfaceTokens();
    this.redraw();
  }

  redraw(): void {
    const ctx = this.ctx;
    if (!ctx) return;
    const rect = this.container.getBoundingClientRect();
    const w = Math.max(1, Math.round(rect.width));
    const h = Math.max(1, Math.round(rect.height));
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    if (this.canvas.width !== w * dpr || this.canvas.height !== h * dpr) {
      this.canvas.width = w * dpr;
      this.canvas.height = h * dpr;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const zoom = this.cy.zoom();
    const pan = this.cy.pan();
    if (!isFinite(zoom) || zoom <= 0) return;

    // Adapt the model step so the on-screen spacing stays in [MIN, MAX] px.
    let step = BASE_STEP;
    while (step * zoom < MIN_SCREEN_STEP) step *= 2;
    while (step * zoom > MAX_SCREEN_STEP) step /= 2;
    const screenStep = step * zoom;

    // Model coords are: screen = model * zoom + pan. First grid line >= screen 0.
    const firstX = pan.x - Math.floor(pan.x / screenStep) * screenStep;
    const firstY = pan.y - Math.floor(pan.y / screenStep) * screenStep;

    // The model grid index of a screen line (major every 5th — a drafting-paper minor/major grid).
    const kx = (x: number): number => Math.round((x - pan.x) / screenStep);
    const ky = (y: number): number => Math.round((y - pan.y) / screenStep);

    // Minor grid — hairline, very low alpha (calm). Draw the non-major lines only.
    ctx.lineWidth = 1;
    ctx.strokeStyle = this.tokens.grid;
    ctx.beginPath();
    for (let x = firstX; x <= w; x += screenStep) { if (kx(x) % MAJOR_EVERY === 0) continue; const px = Math.round(x) + 0.5; ctx.moveTo(px, 0); ctx.lineTo(px, h); }
    for (let y = firstY; y <= h; y += screenStep) { if (ky(y) % MAJOR_EVERY === 0) continue; const py = Math.round(y) + 0.5; ctx.moveTo(0, py); ctx.lineTo(w, py); }
    ctx.stroke();

    // Major grid — every 5th line, a touch stronger (the ruled lines of the bench).
    ctx.strokeStyle = this.tokens.tick;
    ctx.beginPath();
    for (let x = firstX; x <= w; x += screenStep) { if (kx(x) % MAJOR_EVERY !== 0) continue; const px = Math.round(x) + 0.5; ctx.moveTo(px, 0); ctx.lineTo(px, h); }
    for (let y = firstY; y <= h; y += screenStep) { if (ky(y) % MAJOR_EVERY !== 0) continue; const py = Math.round(y) + 0.5; ctx.moveTo(0, py); ctx.lineTo(w, py); }
    ctx.globalAlpha = 0.5;
    ctx.stroke();
    ctx.globalAlpha = 1;

    // Ruler ticks — short marks along the top + left rails at each grid line (the drafting bench).
    ctx.strokeStyle = this.tokens.tick;
    ctx.beginPath();
    for (let x = firstX; x <= w; x += screenStep) {
      const px = Math.round(x) + 0.5;
      const len = kx(x) % MAJOR_EVERY === 0 ? TICK_LEN + 3 : TICK_LEN;
      ctx.moveTo(px, 0);
      ctx.lineTo(px, len);
    }
    for (let y = firstY; y <= h; y += screenStep) {
      const py = Math.round(y) + 0.5;
      const len = ky(y) % MAJOR_EVERY === 0 ? TICK_LEN + 3 : TICK_LEN;
      ctx.moveTo(0, py);
      ctx.lineTo(len, py);
    }
    ctx.stroke();
  }

  destroy(): void {
    this.cy.off("render", this.onRender);
    this.ro?.disconnect();
    this.ro = null;
    this.canvas.remove();
  }
}

/** Read the Light Table surface tokens off <html> (theme-aware; empty-safe fallbacks). */
function readSurfaceTokens(): SurfaceTokens {
  const cs = getComputedStyle(document.documentElement);
  const get = (name: string, fallback: string): string => {
    const v = cs.getPropertyValue(name).trim();
    return v || fallback;
  };
  return {
    grid: get("--grid", "rgba(46,40,30,0.05)"),
    tick: get("--tick", "rgba(46,40,30,0.14)"),
    hair: get("--hair", "rgba(60,52,40,0.10)"),
  };
}
