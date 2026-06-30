# axiam-sdk (TypeScript/JavaScript)

Official TypeScript/JavaScript client SDK for [AXIAM](https://github.com/axiam/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **npm package:** `axiam-sdk`
- **Registry:** [npmjs.com/package/axiam-sdk](https://www.npmjs.com/package/axiam-sdk) _(reserved, not yet published)_
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

## Status

Scaffold placeholder. Full implementation follows in Phase 17 (TypeScript SDK).

## Usage

```bash
npm install axiam-sdk
```

```typescript
import { AximClient } from 'axiam-sdk';
// or for browser-only (REST authz via FND-04):
import { AximClient } from 'axiam-sdk/rest';
```
