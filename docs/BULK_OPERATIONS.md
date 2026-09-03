# Bulk Operations

## List operations

Applicable object lists provide NetBox-native:

- metadata export
- bulk edit
- bulk delete
- bulk rename for named objects

Bulk edit exposes mutable management fields. Parsed cryptographic fingerprints, serial numbers, derived validity fields, and secret material are not editable.

## Multi-object import

Unified import supports multiple unrelated objects and multiple Bundle candidates in one request.

Loose Bundle grouping uses public-key fingerprint. Ambiguous candidates are rejected.

## Filtered material/archive export

Custom material/archive export operates on the complete permission-restricted filtered queryset, not only the current pagination page.

See [EXPORTS.md](EXPORTS.md).
