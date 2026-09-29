from typing import Set, Tuple, Optional, List
from pydantic import BaseModel, Field
from auth import Principal

CLEARANCE_HIERARCHY = {
    "PUBLIC": 0,
    "INTERNAL": 1,
    "CONFIDENTIAL": 2,
    "RESTRICTED": 3
}

class Resource(BaseModel):
    doc_id: str
    tenant_id: str
    classification: str = "INTERNAL"
    allowed_roles: List[str] = Field(default_factory=lambda: ["*"])

class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    control_id: str

class PolicyGate:
    """Formal deterministic policy engine enforcing Zero-Trust multi-tenant data boundaries,
    RBAC role assignments, and classification clearance constraints."""

    @staticmethod
    def can_ingest(principal: Principal, resource: Resource) -> PolicyDecision:
        """Evaluates whether a Principal is authorized to write a Resource into vector storage."""
        # Rule 1: A principal cannot write into a foreign tenant space (unless target is explicitly public)
        if resource.tenant_id != principal.tenant_id and resource.tenant_id != "public":
            return PolicyDecision(
                allowed=False,
                reason=f"Tenant boundary violation: Principal tenant '{principal.tenant_id}' cannot ingest into '{resource.tenant_id}'.",
                control_id="AUTHZ-INGEST-001"
            )

        # Rule 2: Ingestion requires 'writer' or 'admin' role
        has_write_role = bool({"writer", "admin", "finance-admin", "hr-admin"} & principal.roles)
        if not has_write_role:
            return PolicyDecision(
                allowed=False,
                reason=f"Insufficient role privileges: Principal roles {principal.roles} lack required 'writer' role.",
                control_id="AUTHZ-INGEST-002"
            )

        return PolicyDecision(allowed=True, reason="Ingestion authorized.", control_id="AUTHZ-INGEST-PASS")

    @staticmethod
    def can_query(principal: Principal, target_tenant_hint: Optional[str]) -> PolicyDecision:
        """Evaluates whether a query's targeted tenant scope is within the Principal's boundary."""
        if target_tenant_hint:
            if target_tenant_hint != principal.tenant_id and target_tenant_hint != "public":
                return PolicyDecision(
                    allowed=False,
                    reason=f"Cross-tenant query attempt blocked: '{principal.tenant_id}' queried '{target_tenant_hint}'.",
                    control_id="AUTHZ-QUERY-001"
                )
        return PolicyDecision(allowed=True, reason="Query authorized.", control_id="AUTHZ-QUERY-PASS")

    @staticmethod
    def is_chunk_authorized(principal: Principal, resource: Resource) -> bool:
        """Evaluates retrieval invariant: checks tenant match, role overlap, and clearance level."""
        # Tenant boundary invariant
        if resource.tenant_id != principal.tenant_id and resource.tenant_id != "public":
            return False

        # Role overlap invariant
        if "*" not in resource.allowed_roles:
            if not bool(set(resource.allowed_roles) & principal.roles):
                return False

        # Clearance hierarchy invariant
        principal_clearance_lvl = CLEARANCE_HIERARCHY.get(principal.clearance, 0)
        resource_clearance_lvl = CLEARANCE_HIERARCHY.get(resource.classification, 1)
        if resource_clearance_lvl > principal_clearance_lvl:
            return False

        return True
