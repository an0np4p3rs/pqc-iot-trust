import base64
import hashlib
import os
import time
from typing import Dict, List, Optional

import requests
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from oqs_kem import Kem

from oqs_sig import verify_message

LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger:8000")
AI_MONITOR_URL = os.getenv("AI_MONITOR_URL", "http://ai_monitor:8000")

TRUSTED_MANUFACTURER_SIG_ALG = os.getenv("TRUSTED_MANUFACTURER_SIG_ALG", "Dilithium2")
TRUSTED_MANUFACTURER_PUBLIC_KEY_B64 = os.getenv("TRUSTED_MANUFACTURER_PUBLIC_KEY_B64", "")

app = FastAPI(title="PQC IoT Trust Hub")

kem = Kem()

sessions: Dict[str, dict] = {}
telemetry_events: List[dict] = []
device_states: Dict[str, dict] = {}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())


def verify_firmware_signature(
    firmware_hash: str,
    firmware_signature_b64: str,
    manufacturer_sig_alg: str,
) -> bool:
    if not TRUSTED_MANUFACTURER_PUBLIC_KEY_B64:
        raise RuntimeError("TRUSTED_MANUFACTURER_PUBLIC_KEY_B64 is not set")

    public_key = b64d(TRUSTED_MANUFACTURER_PUBLIC_KEY_B64)
    signature = b64d(firmware_signature_b64)

    return verify_message(
        message=firmware_hash.encode(),
        signature=signature,
        public_key=public_key,
        algorithm=manufacturer_sig_alg,
    )


def derive_session_key(shared_secret: bytes, nonce_d: str, nonce_h: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=(nonce_d + nonce_h).encode(),
        info=b"join-session",
    )
    return hkdf.derive(shared_secret)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ledger_get_device(device_id: str) -> Optional[dict]:
    try:
        r = requests.get(f"{LEDGER_URL}/devices/{device_id}", timeout=5)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail=f"Ledger unavailable: {exc}")


def ledger_register_device(device_id: str, firmware_hash: str, device_type: str) -> None:
    payload = {
        "device_id": device_id,
        "firmware_hash": firmware_hash,
        "device_type": device_type,
        "status": "registered",
    }
    try:
        r = requests.post(f"{LEDGER_URL}/devices/register", json=payload, timeout=5)
        r.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(status_code=503, detail=f"Ledger unavailable: {exc}")


def ledger_log_event(device_id: str, event_type: str, details: dict) -> None:
    payload = {
        "device_id": device_id,
        "event_type": event_type,
        "timestamp": time.time(),
        "details": details,
    }
    try:
        r = requests.post(f"{LEDGER_URL}/events", json=payload, timeout=5)
        r.raise_for_status()
    except requests.RequestException:
        pass


def ledger_revoke_device(device_id: str, reason: str) -> None:
    payload = {"device_id": device_id, "reason": reason}
    try:
        r = requests.post(f"{LEDGER_URL}/devices/revoke", json=payload, timeout=5)
        r.raise_for_status()
    except requests.RequestException:
        pass


class JoinRequest(BaseModel):
    device_id: str
    device_type: str
    firmware_hash: str
    firmware_signature_b64: str
    manufacturer_sig_alg: str = "Dilithium2"
    manufacturer_public_key_b64: str | None = None
    nonce_d: str
    kem_public_key_b64: str = Field(..., description="Device ephemeral ML-KEM public key in base64")


class JoinResponse(BaseModel):
    accepted: bool
    reason: str
    kem_ciphertext_b64: Optional[str] = None
    nonce_h: Optional[str] = None
    session_key_hash: Optional[str] = None
    selected_algorithm: Optional[str] = None


class TelemetryEvent(BaseModel):
    device_id: str
    metric: str
    value: float
    ts: float


class TrustAction(BaseModel):
    device_id: str
    action: str
    reason: str


@app.get("/status")
def status():
    return {
        "hub": "ok",
        "kem_algorithm": kem.alg,
        "known_sessions": len(sessions),
        "telemetry_events": len(telemetry_events),
    }


@app.post("/join", response_model=JoinResponse)
def join_device(req: JoinRequest):
    existing = ledger_get_device(req.device_id)

    if existing and existing.get("status") == "revoked":
        return JoinResponse(accepted=False, reason="device revoked")

    if existing and existing.get("firmware_hash") != req.firmware_hash:
        return JoinResponse(accepted=False, reason="firmware hash mismatch")

    # -----------------------------
    # Dilithium firmware verification
    # -----------------------------
    try:
        firmware_ok = verify_firmware_signature(
            firmware_hash=req.firmware_hash,
            firmware_signature_b64=req.firmware_signature_b64,
            manufacturer_sig_alg=req.manufacturer_sig_alg,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"firmware signature verification failed: {exc}",
        )

    if not firmware_ok:
        ledger_log_event(
            req.device_id,
            "join_rejected",
            {"reason": "invalid firmware signature"},
        )
        return JoinResponse(accepted=False, reason="invalid firmware signature")

    # -----------------------------
    # Device registration
    # -----------------------------
    if not existing:
        ledger_register_device(req.device_id, req.firmware_hash, req.device_type)

    try:
        pk = b64d(req.kem_public_key_b64)
        ct, shared_secret = kem.encaps(pk)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"KEM encapsulation failed: {exc}")

    nonce_h = sha256_hex(os.urandom(16))[:16]
    session_key = derive_session_key(shared_secret, req.nonce_d, nonce_h)
    session_key_hash = sha256_hex(session_key)

    sessions[req.device_id] = {
        "device_id": req.device_id,
        "device_type": req.device_type,
        "nonce_d": req.nonce_d,
        "nonce_h": nonce_h,
        "session_key_hash": session_key_hash,
        "joined_at": time.time(),
        "status": "active",
    }

    device_states[req.device_id] = {
        "trust_score": 1.0,
        "status": "active",
        "device_type": req.device_type,
        "last_seen": time.time(),
    }

    ledger_log_event(
        req.device_id,
        "join",
        {
            "device_type": req.device_type,
            "algorithm": kem.alg,
            "session_key_hash": session_key_hash,
        },
    )

    return JoinResponse(
        accepted=True,
        reason="join accepted",
        kem_ciphertext_b64=b64e(ct),
        nonce_h=nonce_h,
        session_key_hash=session_key_hash,
        selected_algorithm=kem.alg,
    )


@app.post("/telemetry")
def post_telemetry(event: TelemetryEvent):
    if event.device_id not in sessions:
        raise HTTPException(status_code=404, detail="unknown device session")

    state = device_states.get(event.device_id)

    if state and state["status"] in {"quarantined", "banned"}:
        ledger_log_event(
            event.device_id,
            "telemetry_rejected",
            {
                "reason": f"device is {state['status']}",
                "metric": event.metric,
                "value": event.value,
                "ts": event.ts,
            },
        )
        raise HTTPException(status_code=403, detail=f"device {state['status']}")

    telemetry_events.append(event.model_dump())

    if event.device_id in device_states:
        device_states[event.device_id]["last_seen"] = event.ts

    ledger_log_event(event.device_id, "telemetry", event.model_dump())

    return {"accepted": True}


@app.get("/telemetry")
def get_telemetry(limit: int = 100):
    return telemetry_events[-limit:]


@app.get("/devices")
def get_devices():
    return device_states


@app.post("/trust-action")
def trust_action(action: TrustAction):
    if action.device_id not in device_states:
        raise HTTPException(status_code=404, detail="unknown device")

    if action.action not in {"quarantine", "ban", "restore"}:
        raise HTTPException(status_code=400, detail="invalid action")

    if action.action == "quarantine":
        device_states[action.device_id]["status"] = "quarantined"
        device_states[action.device_id]["trust_score"] = 0.3

        if action.device_id in sessions:
            sessions[action.device_id]["status"] = "quarantined"

        ledger_log_event(action.device_id, "quarantine", {"reason": action.reason})

    elif action.action == "ban":
        device_states[action.device_id]["status"] = "banned"
        device_states[action.device_id]["trust_score"] = 0.0

        if action.device_id in sessions:
            sessions[action.device_id]["status"] = "banned"

        ledger_revoke_device(action.device_id, action.reason)
        ledger_log_event(action.device_id, "ban", {"reason": action.reason})

    elif action.action == "restore":
        device_states[action.device_id]["status"] = "active"
        device_states[action.device_id]["trust_score"] = 1.0

        if action.device_id in sessions:
            sessions[action.device_id]["status"] = "active"

        ledger_log_event(action.device_id, "restore", {"reason": action.reason})

    return {
        "ok": True,
        "device": action.device_id,
        "new_status": device_states[action.device_id]["status"],
    }
