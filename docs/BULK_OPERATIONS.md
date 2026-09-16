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

Bundle grouping uses public-key fingerprint; distinct renewals remain as individual certificates. See [Imports](IMPORTS.md) for selection, limits, deduplication, and atomic permission checks.

## Filtered material/archive export

Custom material/archive export operates on the complete permission-restricted filtered queryset, not only the current pagination page.

See [EXPORTS.md](EXPORTS.md).

In 1.1.1, Groups and Health and Validity support selected-row bulk actions from their main pages. Automatic ObjectLinks are excluded from bulk edits/deletes. Invalid export filters produce readable field errors; an empty matching queryset displays a warning without downloading an archive. Group metadata export requires the `archive_export` action.

The Vault’s **Export inventory** combines selected object types in one archive. Groups use padded hierarchy rows and separate action buttons. Bulk edit/delete continue to use standard confirmation pages and permission-scoped querysets.
