// Chrome exposes only `chrome`; Safari and Firefox expose both `browser` and
// `chrome`. Aliasing once here lets every other file speak one dialect instead
// of branching on the browser at each call site.
//
// Deliberately has no `export`. That keeps it loadable three ways — as a
// side-effect `import` from the service worker module, as a plain
// `<script src>` on the block page and popup, and as the first entry in the
// content script list — which matters because content scripts and classic
// page scripts cannot load ES modules.
if (typeof globalThis.browser === "undefined" && typeof globalThis.chrome !== "undefined") {
  globalThis.browser = globalThis.chrome;
}
