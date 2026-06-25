from __future__ import annotations

from _auth_flow_helpers import *


def test_health_endpoints_report_liveness_and_dependency_readiness(app, client, monkeypatch):
    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.get_json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.get_json() == {"status": "ready"}

    monkeypatch.setattr(db.session, "execute", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline")))
    unavailable = app.test_client().get("/health/ready")

    assert unavailable.status_code == 503
    assert unavailable.get_json() == {"status": "unavailable"}
