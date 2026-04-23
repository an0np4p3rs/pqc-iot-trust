import hashlib
import json
import time
from typing import Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


app = FastAPI(title="Distributed Trust Ledger MVP")

devices: Dict[str, dict] = {}
events: List[dict] = []


def compute_event_hash(previous_hash: str, payload: dict) -> str:
    material = json.dumps(payload, sort_keys=True).encode() + previous_hash.encode()
    return hashlib.sha256(material).hexdigest()


class DeviceRegistration(BaseModel):
    device_id: str
    firmware_hash: str
    device_type: str
    status: str = "registered"


class LedgerEvent(BaseModel):
    device_id: str
    event_type: str
    timestamp: float
    details: dict


class RevocationRequest(BaseModel):
    device_id: str
    reason: str


@app.get("/status")
def status():
    return {
        "ledger": "ok",
        "devices": len(devices),
        "events": len(events),
    }


@app.post("/devices/register")
def register_device(req: DeviceRegistration):
    if req.device_id not in devices:
        devices[req.device_id] = {
            "device_id": req.device_id,
            "firmware_hash": req.firmware_hash,
            "device_type": req.device_type,
            "status": req.status,
            "registered_at": time.time(),
        }
    return {"ok": True, "device": devices[req.device_id]}


@app.get("/devices/{device_id}")
def get_device(device_id: str):
    if device_id not in devices:
        raise HTTPException(status_code=404, detail="device not found")
    return devices[device_id]


@app.post("/devices/revoke")
def revoke_device(req: RevocationRequest):
    if req.device_id not in devices:
        raise HTTPException(status_code=404, detail="device not found")

    devices[req.device_id]["status"] = "revoked"
    devices[req.device_id]["revoked_reason"] = req.reason
    devices[req.device_id]["revoked_at"] = time.time()

    return {"ok": True, "device": devices[req.device_id]}


@app.post("/events")
def add_event(req: LedgerEvent):
    previous_hash = events[-1]["hash"] if events else "GENESIS"
    payload = req.model_dump()
    event_hash = compute_event_hash(previous_hash, payload)

    record = {
        **payload,
        "previous_hash": previous_hash,
        "hash": event_hash,
    }
    events.append(record)

    return {"ok": True, "hash": event_hash}


@app.get("/events")
def get_events(limit: int = 100):
    return events[-limit:]
