import pytest

@pytest.mark.asyncio
async def test_health_check(async_client):
    response = await async_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@pytest.mark.asyncio
async def test_auth_login(async_client):
    response = await async_client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "testpass"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data

@pytest.mark.asyncio
async def test_auth_refresh(async_client):
    login_response = await async_client.post(
        "/api/auth/login",
        data={"username": "admin", "password": "testpass"}
    )
    refresh_token = login_response.json()["refresh_token"]
    
    response = await async_client.post(
        "/api/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

@pytest.mark.asyncio
async def test_create_alert_internal(async_client):
    # This endpoint doesn't require auth (internal call)
    alert_payload = {
        "alert_id": "test-alert-1",
        "rule_id": "rule-1",
        "rule_name": "Test Rule",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "severity": "high",
        "entity": "192.168.1.100",
        "timestamp": "2023-01-01T00:00:00Z",
        "raw_event": {},
        "recommended_action": "Investigate"
    }
    response = await async_client.post("/api/alerts", json=alert_payload)
    assert response.status_code == 201

@pytest.mark.asyncio
async def test_list_alerts(async_client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = await async_client.get("/api/alerts", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

@pytest.mark.asyncio
async def test_assets_update_and_list(async_client, auth_token):
    # Internal update
    payload = {
        "entity_id": "192.168.1.100",
        "added_risk": 10,
        "last_seen_alert": "test-alert-1",
        "mitre_technique_triggered": "T1059"
    }
    resp1 = await async_client.post("/api/assets/risk-update", json=payload)
    assert resp1.status_code == 200
    
    # List (requires auth)
    headers = {"Authorization": f"Bearer {auth_token}"}
    resp2 = await async_client.get("/api/assets", headers=headers)
    assert resp2.status_code == 200
    data = resp2.json()
    assert len(data) > 0
    assert data[0]["entity_id"] == "192.168.1.100"

@pytest.mark.asyncio
async def test_response_playbooks_crud(async_client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Create playbook
    pb_payload = {
        "name": "Block Malicious IP",
        "description": "Uses firewall to block IP",
        "trigger_condition": "severity == high"
    }
    resp_create = await async_client.post("/api/response/playbooks", json=pb_payload, headers=headers)
    assert resp_create.status_code == 200
    pb_id = resp_create.json()["id"]
    
    # List playbooks
    resp_list = await async_client.get("/api/response/playbooks", headers=headers)
    assert resp_list.status_code == 200
    assert any(pb["id"] == pb_id for pb in resp_list.json())
    
    # Delete playbook
    resp_delete = await async_client.delete(f"/api/response/playbooks/{pb_id}", headers=headers)
    assert resp_delete.status_code == 200

@pytest.mark.asyncio
async def test_threat_intel_bypass(async_client, auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Internal IP check should bypass
    resp_ip = await async_client.get("/api/threat-intel/ip/192.168.1.1", headers=headers)
    assert resp_ip.status_code == 200
    assert resp_ip.json()["source"] == "internal"
