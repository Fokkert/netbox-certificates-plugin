# Validation Notes - 0.4.11

0.4.11 is an API corrective release for NetBox 4.5.9. It retains the prior pagination and unified-import HTTP 400 fixes and corrects direct Certificate/CSR serializer validation so valid PEM material is normalized before NetBox model full-clean validation.

Validation includes release-contract tests, Python compilation, archive integrity, and a source scan confirming the unordered `.objects.all()` queryset is absent from that viewset.


- Mismatched primary public-key identities are rejected before persistence and are mapped to DRF `ValidationError` (HTTP 400).
- Missing multipart `files` and combined-upload-size validation also return HTTP 400.
