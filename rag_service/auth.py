from typing import Protocol, Optional, Set, Dict
from pydantic import BaseModel, Field

class Principal(BaseModel):
    subject: str = Field(..., description="Unique user identifier / email")
    tenant_id: str = Field(..., description="Organizational tenant domain")
    roles: Set[str] = Field(default_factory=set, description="Assigned RBAC roles")
    clearance: str = Field(default="INTERNAL", description="Data clearance level: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED")

class IdentityProvider(Protocol):
    def authenticate(self, token: str) -> Optional[Principal]:
        """Validates bearer token credential and returns authenticated Principal."""
        ...

class StaticFixtureIdentityProvider:
    """Reference identity provider backed by explicit test fixture identities for local reproducibility.
    
    NOTE: Production deployments replace this with JWTIdentityProvider or OIDCIdentityProvider
    connected to Keycloak, Okta, or AWS Cognito.
    """
    
    FIXTURES: Dict[str, Principal] = {
        "token-alpha-fin-admin": Principal(
            subject="alice@tenant-alpha.com",
            tenant_id="tenant-alpha",
            roles={"finance-admin", "writer", "reader"},
            clearance="RESTRICTED"
        ),
        "token-alpha-exec": Principal(
            subject="bob@tenant-alpha.com",
            tenant_id="tenant-alpha",
            roles={"executive", "reader"},
            clearance="RESTRICTED"
        ),
        "token-beta-hr-admin": Principal(
            subject="carol@tenant-beta.com",
            tenant_id="tenant-beta",
            roles={"hr-admin", "writer", "reader"},
            clearance="RESTRICTED"
        ),
        "token-beta-employee": Principal(
            subject="david@tenant-beta.com",
            tenant_id="tenant-beta",
            roles={"staff", "reader"},
            clearance="INTERNAL"
        ),
        "token-public-user": Principal(
            subject="guest@external.com",
            tenant_id="guest-org",
            roles={"guest", "reader"},
            clearance="PUBLIC"
        )
    }

    def authenticate(self, token: str) -> Optional[Principal]:
        return self.FIXTURES.get(token)
