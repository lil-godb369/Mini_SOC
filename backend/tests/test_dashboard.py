"""Dashboard assets and the authenticated alert investigation workflow."""
from app.db import SessionLocal
from app.models import Alert


def test_dashboard_is_bundled_and_api_remains_protected(client):
    response = client.get("/", follow_redirects=False)
    assert response.headers["location"] == "/dashboard/"
    page = client.get("/dashboard/")
    assert page.status_code == 200
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert "'unsafe-inline'" not in page.headers["content-security-policy"]
    assert page.headers["x-content-type-options"] == "nosniff"
    assert 'id="login-form"' in page.text
    for asset, content_type in [("app.js", "javascript"), ("style.css", "text/css")]:
        response = client.get("/dashboard/" + asset)
        assert response.status_code == 200
        assert content_type in response.headers["content-type"]
    assert client.get("/api/v1/alerts").status_code == 401
    assert client.patch("/api/v1/alerts/1/status", json={"status": "closed"}).status_code == 401


def test_dashboard_filter_detail_and_close_workflow(client, auth_headers):
    with SessionLocal() as db:
        alert = Alert(title="Ransomware demo", severity="critical", host="LAB-PC",
                      source="ransomware", technique="T1486",
                      evidence={"file_path": "sandbox/demo.txt", "score": 0.42})
        db.add(alert)
        db.add(Alert(title="Other endpoint", severity="low", host="OTHER-PC", source="rule"))
        db.commit()
        alert_id = alert.id

    params = {"severity": "critical", "host": "LAB-PC", "status": "new", "source": "ransomware", "limit": 20}
    page = client.get("/api/v1/alerts", params=params, headers=auth_headers).json()
    assert page["total"] == 1
    assert page["items"][0]["id"] == alert_id
    detail = client.get(f"/api/v1/alerts/{alert_id}", headers=auth_headers).json()
    assert detail["evidence"]["score"] == 0.42
    response = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "closed"}, headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["status"] == "closed"
    assert client.get("/api/v1/alerts", params=params, headers=auth_headers).json()["total"] == 0
    params["status"] = "closed"
    assert client.get("/api/v1/alerts", params=params, headers=auth_headers).json()["total"] == 1
