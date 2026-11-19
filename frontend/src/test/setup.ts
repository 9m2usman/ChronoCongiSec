/// <reference types="vitest/globals" />
import '@testing-library/jest-dom/vitest';
import { expect } from 'vitest';
import * as matchers from '@testing-library/jest-dom/matchers';
import { cleanup } from '@testing-library/react';

// vitest 5.1.1 ESM interop quirk in this environment: the `expect` injected by
// `globals: true` is a DIFFERENTENT instance than the one imported from 'vitest'.
// jest-dom's `expect.extend` registers matchers on its own imported instance,
// so the global expect used by tests never sees them. Copy the matchers onto
// the global expect so `toBeInTheDocument` and friends resolve for every test.
expect.extend(matchers);
// Also extend the global expect injected by vitest's `globals: true`.
if (typeof globalThis !== 'undefined' && globalThis.expect && typeof globalThis.expect.extend === 'function') {
  globalThis.expect.extend(matchers);
}

afterEach(() => {
  cleanup();
});