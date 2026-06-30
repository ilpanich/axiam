# axiam/axiam-sdk (PHP)

Official PHP client SDK for [AXIAM](https://github.com/axiam/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Packagist package:** `axiam/axiam-sdk`
- **Registry:** [packagist.org/packages/axiam/axiam-sdk](https://packagist.org/packages/axiam/axiam-sdk) _(reserved, not yet published)_
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1-§10.

See [`../CONTRACT.md`](../CONTRACT.md) for the full cross-language behavioral contract.

## Status

Scaffold placeholder. Full implementation follows in Phase 22 (PHP SDK).

## Usage

```bash
composer require axiam/axiam-sdk
```

```php
use Axiam\Sdk\AximClient;

$client = new AximClient(['base_url' => 'https://your-axiam-instance']);
```
