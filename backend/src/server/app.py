"""FastAPI application: ETSI-014 key managers, QKD link control, and the untrusted chat relay."""

import asyncio
import json
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from server.kme import KME, KMEError
from server.link import ALICE_SAE, BOB_SAE, QKDLink, jsonable
from server.relay import Relay
from server.schemas import Envelope, LinkConfigUpdate, RelayConfigUpdate, SessionRequest

FRONTEND_DIST = Path(__file__).resolve().parents[3] / "frontend" / "dist"


class KeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    number: int | None = None
    size: int | None = None
    additional_slave_SAE_IDs: list[str] | None = None
    extension_mandatory: list[dict[str, Any]] | None = None
    extension_optional: list[dict[str, Any]] | None = None


class KeyIDItem(BaseModel):
    model_config = ConfigDict(extra="allow")

    key_ID: str


class KeyIDs(BaseModel):
    model_config = ConfigDict(extra="allow")

    key_IDs: list[KeyIDItem]


def create_app(link: QKDLink | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.link = link or QKDLink()
        app.state.relay = Relay()
        # Stand-in for the mutual-TLS certificates a real SAE/KME pair would have.
        app.state.tokens = {
            secrets.token_urlsafe(24): ALICE_SAE,
            secrets.token_urlsafe(24): BOB_SAE,
        }
        yield

    app = FastAPI(title="QKD Messenger", version="0.1.0", lifespan=lifespan)

    @app.exception_handler(KMEError)
    async def kme_error(_: Request, exc: KMEError):
        return JSONResponse(exc.body(), status_code=exc.status)

    @app.exception_handler(RequestValidationError)
    async def bad_request(request: Request, exc: RequestValidationError):
        if request.url.path.startswith("/kme/"):  # ETSI 014: malformed requests are 400 + Error
            details = [{"/".join(str(p) for p in e["loc"]): e["msg"]} for e in exc.errors()]
            return JSONResponse(
                {"message": "bad request format", "details": details}, status_code=400
            )
        return JSONResponse({"detail": jsonable(exc.errors())}, status_code=422)

    def get_link(request: Request) -> QKDLink:
        return request.app.state.link

    def get_relay(request: Request) -> Relay:
        return request.app.state.relay

    # ---------------------------------------------------------------- health and demo setup

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "simulation": True}

    @app.get("/api/demo/credentials")
    async def credentials(request: Request):
        """Demo convenience: hand each browser pane its SAE token (stands in for mTLS provisioning)."""
        by_sae = {sae: token for token, sae in request.app.state.tokens.items()}
        return {"sae_tokens": by_sae, "kme_paths": {"alice": "/kme/alice", "bob": "/kme/bob"}}

    # ---------------------------------------------------------------- ETSI GS QKD 014 key delivery

    def kme_for(request: Request, who: str, authorization: str | None) -> tuple[KME, str]:
        link: QKDLink = request.app.state.link
        kme = {"alice": link.kme_alice, "bob": link.kme_bob}.get(who)
        if kme is None:
            raise HTTPException(404, "no such KME")
        token = (authorization or "").removeprefix("Bearer ").strip()
        sae = request.app.state.tokens.get(token)
        if sae is None or sae != kme.sae_id:
            raise KMEError(401, "unauthorized")
        return kme, sae

    Auth = Annotated[str | None, Header()]

    @app.get("/kme/{who}/api/v1/keys/{slave_sae_id}/status")
    async def kme_status(who: str, slave_sae_id: str, request: Request, authorization: Auth = None):
        kme, _ = kme_for(request, who, authorization)
        return kme.get_status(slave_sae_id)

    @app.get("/kme/{who}/api/v1/keys/{slave_sae_id}/enc_keys")
    async def kme_enc_keys_get(
        who: str,
        slave_sae_id: str,
        request: Request,
        number: int | None = Query(None),
        size: int | None = Query(None),
        authorization: Auth = None,
    ):
        kme, _ = kme_for(request, who, authorization)
        return kme.get_key(slave_sae_id, number=number, size=size)

    @app.post("/kme/{who}/api/v1/keys/{slave_sae_id}/enc_keys")
    async def kme_enc_keys_post(
        who: str,
        slave_sae_id: str,
        request: Request,
        body: KeyRequest | None = None,
        authorization: Auth = None,
    ):
        kme, _ = kme_for(request, who, authorization)
        body = body or KeyRequest()
        return kme.get_key(
            slave_sae_id,
            number=body.number,
            size=body.size,
            additional_slave_SAE_IDs=body.additional_slave_SAE_IDs,
            extension_mandatory=body.extension_mandatory,
            extension_optional=body.extension_optional,
        )

    @app.get("/kme/{who}/api/v1/keys/{master_sae_id}/dec_keys")
    async def kme_dec_keys_get(
        who: str,
        master_sae_id: str,
        request: Request,
        key_ID: str = Query(...),
        authorization: Auth = None,
    ):
        kme, sae = kme_for(request, who, authorization)
        return kme.get_key_with_ids(master_sae_id, [key_ID], sae)

    @app.post("/kme/{who}/api/v1/keys/{master_sae_id}/dec_keys")
    async def kme_dec_keys_post(
        who: str, master_sae_id: str, request: Request, body: KeyIDs, authorization: Auth = None
    ):
        kme, sae = kme_for(request, who, authorization)
        return kme.get_key_with_ids(master_sae_id, [item.key_ID for item in body.key_IDs], sae)

    @app.get("/api/kme/{who}/ledger")
    async def kme_ledger(who: str, link: Annotated[QKDLink, Depends(get_link)]):
        kme = {"alice": link.kme_alice, "bob": link.kme_bob}.get(who)
        if kme is None:
            raise HTTPException(404, "no such KME")
        return jsonable({"snapshot": kme.snapshot(), "ledger": list(kme.ledger)[-200:]})

    # ---------------------------------------------------------------- QKD link control

    @app.get("/api/link")
    async def link_status(link: Annotated[QKDLink, Depends(get_link)]):
        return link.snapshot()

    @app.put("/api/link/config")
    async def link_config(update: LinkConfigUpdate, link: Annotated[QKDLink, Depends(get_link)]):
        link.configure(update)
        return link.snapshot()

    @app.post("/api/link/provision")
    async def link_provision(link: Annotated[QKDLink, Depends(get_link)]):
        if link._lock.locked():
            raise HTTPException(409, "a session is running")
        link.provision()
        return link.snapshot()

    @app.post("/api/link/sessions", status_code=202)
    async def start_session(request: SessionRequest, link: Annotated[QKDLink, Depends(get_link)]):
        if request.seed is not None and request.seed < 0:
            raise HTTPException(400, "bad seed")
        record = link.start(request)
        return record.summary()

    @app.get("/api/link/sessions")
    async def list_sessions(link: Annotated[QKDLink, Depends(get_link)]):
        return [s.summary() for s in reversed(link.sessions.values())]

    @app.get("/api/link/sessions/{session_id}")
    async def get_session(session_id: str, link: Annotated[QKDLink, Depends(get_link)]):
        record = link.sessions.get(session_id)
        if record is None:
            raise HTTPException(404, "no such session")
        return {**record.summary(), "events": record.events}

    @app.get("/api/link/sessions/{session_id}/events")
    async def session_events(session_id: str, link: Annotated[QKDLink, Depends(get_link)]):
        record = link.sessions.get(session_id)
        if record is None:
            raise HTTPException(404, "no such session")

        async def stream():
            async for event in record.stream():
                yield f"data: {json.dumps(event)}\n\n"
            yield "event: end\ndata: {}\n\n"

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    # ---------------------------------------------------------------- untrusted chat relay

    @app.post("/relay/send", status_code=202)
    async def relay_send(envelope: Envelope, relay: Annotated[Relay, Depends(get_relay)]):
        return await relay.submit(envelope)

    @app.get("/relay/inbox/{user}")
    async def relay_inbox(user: str, relay: Annotated[Relay, Depends(get_relay)]):
        return relay.messages_for(user)

    @app.get("/relay/log")
    async def relay_log(relay: Annotated[Relay, Depends(get_relay)]):
        return {"mode": relay.mode, "log": list(relay.log)}

    @app.put("/relay/config")
    async def relay_config(update: RelayConfigUpdate, relay: Annotated[Relay, Depends(get_relay)]):
        relay.mode = update.mode
        return {"mode": relay.mode}

    @app.delete("/relay/messages")
    async def relay_clear(relay: Annotated[Relay, Depends(get_relay)]):
        relay.clear()
        return {"cleared": True}

    @app.websocket("/relay/ws/{user}")
    async def relay_socket(socket: WebSocket, user: str):
        relay: Relay = socket.app.state.relay
        await relay.connect(user, socket)
        try:
            while True:
                await socket.receive_text()  # clients only listen; this keeps the socket open
        except WebSocketDisconnect:
            relay.disconnect(user, socket)
        except asyncio.CancelledError:
            relay.disconnect(user, socket)
            raise

    if FRONTEND_DIST.exists():
        app.mount("/", StaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")

    return app


app = create_app()
