// Metro-compatible wrapper that avoids import.meta.url issues
// This file dynamically loads WASM bindings at runtime instead of at parse time

let wasmInitialized = false;
let wasmInitPromise: Promise<void> | null = null;
let wasmBindings: any = null;

export async function asyncInit(): Promise<void> {
  if (wasmInitialized) {
    return;
  }
  if (wasmInitPromise) {
    return wasmInitPromise;
  }

  wasmInitPromise = (async () => {
    // Dynamically require the bindings at runtime (not parse time)
    // This prevents Metro from trying to parse the ES module code
    const initWasm = new Function('return require("./bindings/authentication.js").default');
    const wasmModule = new Function('return require("./bindings/authentication_bg.wasm")');

    const init = initWasm();
    const wasm = wasmModule();

    await init(wasm.default || wasm);

    // Now load the full bindings
    const bindingsLoader = new Function('return require("./bindings/authentication.js")');
    wasmBindings = bindingsLoader();

    wasmInitialized = true;
  })();

  return wasmInitPromise;
}

// Re-export everything from the main index
// But for Metro, we'll intercept the WASM initialization
export * from './index';
