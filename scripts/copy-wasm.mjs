// Copy the wasm-pack artifacts (the .js glue, .d.ts, and the .wasm binary) from src/wasm into
// dist/wasm, so the compiled SDK ships the wasm next to its emitted JS. tsc only emits the .ts
// sources; the wasm-pack output is vendored, not compiled, so we copy it verbatim.
import { cp, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const from = join(root, "src", "wasm");
const to = join(root, "dist", "wasm");

await mkdir(to, { recursive: true });
await cp(from, to, { recursive: true });
console.log(`copied wasm artifacts: ${from} -> ${to}`);
