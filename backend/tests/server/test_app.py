import ast
import base64
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import server.relay
from server.app import create_app
from server.link import QKDLink

FAST = {"n_key": 4096, "k_test": 2048}


@pytest.fixture()
def client():
    with TestClient(create_app(QKDLink())) as c:
        yield c


def creds(client):
    return client.get("/api/demo/credentials").json()["sae_tokens"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def run_session(client, **overrides):
    body = {**FAST, **overrides}
    started = client.post("/api/link/sessions", json=body)
    assert started.status_code == 202, started.text
    session_id = started.json()["id"]
    deadline = time.time() + 90
    while time.time() < deadline:
        record = client.get(f"/api/link/sessions/{session_id}").json()
        if record["status"] in {"success", "aborted", "error"}:
            return record
        time.sleep(0.1)
    raise AssertionError("session did not finish")


def test_health_labels_the_service_as_a_simulation(client):
    assert client.get("/api/health").json() == {"status": "ok", "simulation": True}


def test_kme_rejects_missing_wrong_and_foreign_tokens(client):
    tokens = creds(client)
    url = "/kme/alice/api/v1/keys/sae-bob/status"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=auth("nope")).status_code == 401
    assert (
        client.get(url, headers=auth(tokens["sae-bob"])).status_code == 401
    )  # Bob's token, Alice's KME
    ok = client.get(url, headers=auth(tokens["sae-alice"]))
    assert ok.status_code == 200 and ok.json()["stored_key_count"] == 0


def test_no_key_yet_gives_503_with_etsi_error_body(client):
    tokens = creds(client)
    response = client.post(
        "/kme/alice/api/v1/keys/sae-bob/enc_keys",
        json={"size": 256},
        headers=auth(tokens["sae-alice"]),
    )
    assert response.status_code == 503
    assert "insufficient key material" in response.json()["message"]


def test_malformed_etsi_requests_are_400_with_error_object(client):
    tokens = creds(client)
    response = client.post(
        "/kme/alice/api/v1/keys/sae-bob/enc_keys",
        json={"number": "many"},
        headers=auth(tokens["sae-alice"]),
    )
    assert response.status_code == 400 and response.json()["message"] == "bad request format"


def test_qkd_session_feeds_both_kmes_and_keys_flow_alice_to_bob_and_back(client):
    tokens = creds(client)
    record = run_session(client, n_key=8192, k_test=4096)
    assert record["status"] == "success", record["result"]
    assert record["result"]["key_bits"] > 1_500
    a, b = auth(tokens["sae-alice"]), auth(tokens["sae-bob"])

    status = client.get("/kme/alice/api/v1/keys/sae-bob/status", headers=a).json()
    assert status["stored_key_count"] > 0 and status["master_SAE_ID"] == "sae-alice"

    issued = client.post(
        "/kme/alice/api/v1/keys/sae-bob/enc_keys", json={"number": 2, "size": 256}, headers=a
    ).json()
    ids = [{"key_ID": k["key_ID"]} for k in issued["keys"]]
    got = client.post(
        "/kme/bob/api/v1/keys/sae-alice/dec_keys", json={"key_IDs": ids}, headers=b
    ).json()
    assert [k["key"] for k in got["keys"]] == [k["key"] for k in issued["keys"]]
    assert all(len(base64.b64decode(k["key"])) == 32 for k in got["keys"])
    # one-shot: the same IDs cannot be fetched again
    again = client.post("/kme/bob/api/v1/keys/sae-alice/dec_keys", json={"key_IDs": ids}, headers=b)
    assert again.status_code == 400
    # GET shortcut with a single ID, and the reverse direction
    back = client.get("/kme/bob/api/v1/keys/sae-alice/enc_keys?number=1&size=256", headers=b).json()
    kid = back["keys"][0]["key_ID"]
    via_get = client.get(f"/kme/alice/api/v1/keys/sae-bob/dec_keys?key_ID={kid}", headers=a).json()
    assert via_get["keys"][0]["key"] == back["keys"][0]["key"]
    # Alice cannot fetch a key she issued, Bob cannot fetch one Alice's KME never allocated to him
    stolen = client.post(
        "/kme/bob/api/v1/keys/sae-alice/dec_keys", json={"key_IDs": ids}, headers=a
    )
    assert stolen.status_code == 401


def test_session_event_stream_covers_the_pipeline(client):
    started = client.post("/api/link/sessions", json=FAST).json()
    stages = []
    with client.stream("GET", f"/api/link/sessions/{started['id']}/events") as stream:
        for line in stream.iter_lines():
            if line.startswith("data: ") and line != "data: {}":
                stages.append(json.loads(line[6:])["stage"])
            if line == "event: end":
                break
    for stage in (
        "session",
        "quantum",
        "sifting",
        "estimation",
        "reconciliation",
        "verification",
        "amplification",
        "result",
        "kme",
    ):
        assert stage in stages, stage


def test_eve_on_the_line_aborts_the_session_and_no_key_is_stored(client):
    tokens = creds(client)
    client.put("/api/link/config", json={"attack": {"kind": "intercept_resend", "fraction": 1.0}})
    record = run_session(client)
    assert record["status"] == "aborted"
    assert record["result"]["abort"]["stage"] == "estimation"
    assert record["result"]["abort"]["detail"]["qber"] > 0.2
    status = client.get(
        "/kme/alice/api/v1/keys/sae-bob/status", headers=auth(tokens["sae-alice"])
    ).json()
    assert status["stored_key_count"] == 0
    # authentication key was burned by the failed attempt
    link = client.get("/api/link").json()
    assert link["auth_pool"]["alice_bytes"] < 2_048
    # remove Eve, recover
    client.put("/api/link/config", json={"attack": {"kind": "none"}})
    assert run_session(client)["status"] == "success"


def test_classical_tampering_is_reported_as_an_authentication_failure(client):
    record = run_session(client, tamper="flip_estimate")
    assert record["status"] == "aborted" and record["result"]["abort"]["stage"] == "authentication"


def test_relay_forwards_ciphertext_and_logs_what_it_sees(client):
    envelope = {
        "id": "msg-00000001",
        "sender": "alice",
        "recipient": "bob",
        "mode": "otp-wc",
        "seq": 0,
        "key_ids": ["550e8400-e29b-41d4-a716-446655440000"],
        "ciphertext": base64.b64encode(b"\x01\x02\x03").decode(),
        "tag": "00" * 16,
    }
    with client.websocket_connect("/relay/ws/bob") as socket:
        assert client.post("/relay/send", json=envelope).status_code == 202
        pushed = socket.receive_json()
    assert pushed["envelope"]["ciphertext"] == envelope["ciphertext"]
    assert client.get("/relay/inbox/bob").json()[0]["id"] == envelope["id"]
    log = client.get("/relay/log").json()
    assert log["log"][0]["envelope"]["sender"] == "alice" and "plaintext" not in json.dumps(log)


def test_hostile_relay_modes(client):
    envelope = {
        "id": "msg-00000002",
        "sender": "alice",
        "recipient": "bob",
        "mode": "aes-gcm",
        "seq": 1,
        "key_ids": ["550e8400-e29b-41d4-a716-446655440000"],
        "ciphertext": base64.b64encode(b"\x10\x20\x30").decode(),
        "nonce": "00" * 12,
    }
    client.put("/relay/config", json={"mode": "flip_ciphertext"})
    client.post("/relay/send", json=envelope)
    assert (
        client.get("/relay/inbox/bob").json()[-1]["ciphertext"]
        == base64.b64encode(b"\x11\x20\x30").decode()
    )
    client.delete("/relay/messages")
    client.put("/relay/config", json={"mode": "drop"})
    assert client.post("/relay/send", json=envelope).json()["delivered"] == 0
    assert client.get("/relay/inbox/bob").json() == []


def test_relay_cannot_reach_key_material():
    """Static guarantee: the relay module imports nothing from the KME or crypto packages."""
    tree = ast.parse(Path(server.relay.__file__).read_text())
    imported = {
        (node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        for alias in (node.names if isinstance(node, ast.Import | ast.ImportFrom) else [])
    } | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any(name and ("kme" in name or "qkd" in name) for name in imported), imported
