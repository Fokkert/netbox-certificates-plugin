"""1.0 background-job entry point.

The pre-1.0 expiration-only system job is intentionally removed. Health,
validity, and all configured alert types are processed by the unified job.
"""

from .jobs_v1 import CertificateHealthAndAlertJob

__all__ = ("CertificateHealthAndAlertJob",)
