# Contributing

Contributions, forks, and derivative versions are welcome.

## License

By contributing code/documentation to this repository, you agree that your contribution may be distributed under the repository's Apache License 2.0 unless explicitly agreed otherwise by the maintainer.

When redistributing a derivative, comply with Apache-2.0 Section 4, including preservation of the license and applicable `NOTICE` attribution and prominent notices for files you modify where required.

## Development expectations

- Keep changes compatible with the NetBox plugin API for the declared compatibility range.
- Do not widen NetBox compatibility solely because the package imports; run integration tests against each new NetBox minor line.
- Add/update tests for behavioral changes.
- Never expose private-key plaintext through ordinary serializers/logging.
- Preserve sensitive-operation token/superuser overlays unless a security review intentionally changes them.
- Update `CHANGELOG.md`, API documentation, and compatibility notes for user-visible behavior.
- Build wheel + sdist and run `twine check` before release.

## AI-assisted contributions

AI-assisted contributions are allowed. Review generated code before submission and disclose material AI assistance when appropriate. Do not invent a fake GitHub identity for an AI system.
