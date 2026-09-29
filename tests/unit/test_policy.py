import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../rag_service")))

from auth import Principal
from policy import Resource, PolicyGate

def test_cross_tenant_ingestion_denied():
    principal = Principal(
        subject="alice@tenant-alpha.com",
        tenant_id="tenant-alpha",
        roles={"writer"},
        clearance="INTERNAL"
    )
    foreign_resource = Resource(
        doc_id="doc_beta_01",
        tenant_id="tenant-beta",
        classification="INTERNAL"
    )
    decision = PolicyGate.can_ingest(principal, foreign_resource)
    assert not decision.allowed
    assert "Tenant boundary violation" in decision.reason

def test_unauthorized_role_ingestion_denied():
    principal = Principal(
        subject="david@tenant-beta.com",
        tenant_id="tenant-beta",
        roles={"reader"},  # Missing 'writer' role
        clearance="INTERNAL"
    )
    resource = Resource(
        doc_id="doc_beta_02",
        tenant_id="tenant-beta",
        classification="INTERNAL"
    )
    decision = PolicyGate.can_ingest(principal, resource)
    assert not decision.allowed
    assert "Insufficient role privileges" in decision.reason

def test_valid_tenant_writer_ingestion_allowed():
    principal = Principal(
        subject="carol@tenant-beta.com",
        tenant_id="tenant-beta",
        roles={"writer", "hr-admin"},
        clearance="RESTRICTED"
    )
    resource = Resource(
        doc_id="doc_beta_03",
        tenant_id="tenant-beta",
        classification="RESTRICTED"
    )
    decision = PolicyGate.can_ingest(principal, resource)
    assert decision.allowed

def test_cross_tenant_query_denied():
    principal = Principal(
        subject="david@tenant-beta.com",
        tenant_id="tenant-beta",
        roles={"reader"},
        clearance="INTERNAL"
    )
    decision = PolicyGate.can_query(principal, target_tenant_hint="tenant-alpha")
    assert not decision.allowed
    assert "Cross-tenant query attempt blocked" in decision.reason

def test_chunk_clearance_invariant():
    low_clearance_principal = Principal(
        subject="david@tenant-beta.com",
        tenant_id="tenant-beta",
        roles={"staff"},
        clearance="INTERNAL"
    )
    restricted_chunk = Resource(
        doc_id="doc_beta_exec",
        tenant_id="tenant-beta",
        classification="RESTRICTED",
        allowed_roles=["*"]
    )
    assert not PolicyGate.is_chunk_authorized(low_clearance_principal, restricted_chunk)

    high_clearance_principal = Principal(
        subject="carol@tenant-beta.com",
        tenant_id="tenant-beta",
        roles={"staff"},
        clearance="RESTRICTED"
    )
    assert PolicyGate.is_chunk_authorized(high_clearance_principal, restricted_chunk)
