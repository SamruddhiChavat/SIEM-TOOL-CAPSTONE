from fastapi import APIRouter
from typing import List, Dict, Any
from datetime import datetime
from models.compliance_schemas import ComplianceStateSchema, ComplianceFrameworkSummary

router = APIRouter()

# Dummy data for UI building. In production this queries Elasticsearch.
MOCK_COMPLIANCE_DATA = {
    "overall_score": 78,
    "frameworks": {
        "pci_dss": {
            "name": "PCI DSS 4.0",
            "total_violations": 14,
            "controls_failed": ["11.5", "8.1.1", "10.2.1"],
            "compliance_score": 82
        },
        "nist_800_53": {
            "name": "NIST SP 800-53",
            "total_violations": 6,
            "controls_failed": ["SI-7", "AC-2", "AU-2"],
            "compliance_score": 90
        },
        "cis": {
            "name": "CIS Controls v8",
            "total_violations": 24,
            "controls_failed": ["3.14", "4.3", "5.4"],
            "compliance_score": 65
        },
        "hipaa": {
            "name": "HIPAA",
            "total_violations": 2,
            "controls_failed": ["164.312(a)(1)"],
            "compliance_score": 95
        },
        "gdpr": {
            "name": "GDPR",
            "total_violations": 0,
            "controls_failed": [],
            "compliance_score": 100
        }
    }
}

@router.get("", response_model=ComplianceStateSchema)
async def get_compliance_state():
    return {
        "timestamp": datetime.utcnow(),
        **MOCK_COMPLIANCE_DATA
    }
