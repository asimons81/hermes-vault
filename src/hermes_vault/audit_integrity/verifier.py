"""Public verification entry point."""
from hermes_vault.audit_integrity.service import AuditIntegrityService


def verify_audit_integrity(service: AuditIntegrityService):
    return service.verify()