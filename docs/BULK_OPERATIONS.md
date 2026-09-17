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

## Deletion (1.3.0)

Individual and bulk deletion use NetBox's normal confirmation and permission checks. All public plugin models now expose the canonical serializers needed by NetBox deletion events. Generic ObjectLinks referencing deleted inventory objects are removed; certificate bulk deletion coalesces post-commit relationship reconciliation. Automatic links themselves remain read-only; delete their owning artifacts to remove them.

## Selection controls (1.3.1)

Standard NetBox inventory tables retain their header checkbox and all-matching-query selection. Groups adds Select all groups and Clear selection, including groups inside collapsed branches. Health adds page selection, Clear selection, and a separate all-matching-findings checkbox across pages. Bulk edit/delete preserves the Health filter query and still enforces the corresponding object permissions. Inventory export adds Select all object types and Clear selection. Empty lists have disabled selection buttons.
