import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext

from pydantic import BaseModel

from database import db, create_document, get_documents
from schemas import (
    UserCreate, UserPublic, TokenResponse,
    VitalCreate, VitalRecord, Alert, Message,
)

# App setup
app = FastAPI(title="NeuroLink Health API (FastAPI)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth / security
SECRET_KEY = os.getenv("JWT_SECRET", "dev_secret_change_me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Utility helpers

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_doc = db["user"].find_one({"_id": db.client.get_default_database().client.get_database().client._Database__name and None})
    # The above is not reliable; fetch by id string saved in token
    from bson import ObjectId  # lazy import
    try:
        user_doc = db["user"].find_one({"_id": ObjectId(user_id)})
    except Exception:
        user_doc = None
    if not user_doc:
        raise credentials_exception

    user_public: Dict[str, Any] = {
        "id": str(user_doc["_id"]),
        "name": user_doc.get("name"),
        "email": user_doc.get("email"),
        "role": user_doc.get("role"),
        "doctor_id": user_doc.get("doctor_id"),
        "doctor_code": user_doc.get("doctor_code"),
    }
    return user_public


# Models for requests
class LoginRequest(BaseModel):
    email: str
    password: str


# Routes
@app.get("/")
def root():
    return {"service": "NeuroLink Health API", "status": "ok"}


@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: UserCreate):
    # Role validation
    if payload.role not in ("doctor", "patient"):
        raise HTTPException(status_code=400, detail="Invalid role")

    # Unique email
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")

    doctor_id: Optional[str] = None
    doctor_code: Optional[str] = None

    if payload.role == "doctor":
        # Generate a simple doctor connection code
        doctor_code = f"DOC-{int(datetime.utcnow().timestamp()) % 100000:05d}"
    else:
        # For patients, optionally link to doctor via code or email
        if payload.doctor_code:
            doc = db["user"].find_one({"doctor_code": payload.doctor_code, "role": "doctor"})
            if doc:
                doctor_id = str(doc["_id"])
        elif payload.doctor_email:
            doc = db["user"].find_one({"email": payload.doctor_email, "role": "doctor"})
            if doc:
                doctor_id = str(doc["_id"])

    doc_to_insert = {
        "name": payload.name,
        "email": payload.email,
        "password_hash": hash_password(payload.password),
        "role": payload.role,
        "doctor_id": doctor_id,
        "doctor_code": doctor_code,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    result = db["user"].insert_one(doc_to_insert)
    user_id = str(result.inserted_id)
    token = create_access_token({"sub": user_id})

    return TokenResponse(
        access_token=token,
        user=UserPublic(
            id=user_id,
            name=payload.name,
            email=payload.email,
            role=payload.role,
            doctor_id=doctor_id,
            doctor_code=doctor_code,
        ),
    )


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = str(user["_id"])
    token = create_access_token({"sub": user_id})

    return TokenResponse(
        access_token=token,
        user=UserPublic(
            id=user_id,
            name=user["name"],
            email=user["email"],
            role=user["role"],
            doctor_id=user.get("doctor_id"),
            doctor_code=user.get("doctor_code"),
        ),
    )


# Vitals and alerts

def compute_alerts_for_vitals(user_id: str, doctor_id: Optional[str], v: VitalCreate) -> List[Alert]:
    alerts: List[Alert] = []
    if v.heartRate < 50:
        alerts.append(Alert(user_id=user_id, doctor_id=doctor_id or "", type="heartRate_low", message="Heart rate below 50"))
    if v.heartRate > 120:
        alerts.append(Alert(user_id=user_id, doctor_id=doctor_id or "", type="heartRate_high", message="Heart rate above 120"))
    if v.spo2 < 90:
        alerts.append(Alert(user_id=user_id, doctor_id=doctor_id or "", type="spo2_low", message="SpO₂ below 90%"))
    if v.temperature > 38.0:
        alerts.append(Alert(user_id=user_id, doctor_id=doctor_id or "", type="temperature_high", message="Fever detected"))
    if v.bpSystolic > 140 or v.bpDiastolic > 90:
        alerts.append(Alert(user_id=user_id, doctor_id=doctor_id or "", type="bp_high", message="Blood pressure elevated"))
    if v.respirationRate < 10 or v.respirationRate > 24:
        alerts.append(Alert(user_id=user_id, doctor_id=doctor_id or "", type="respiration_abnormal", message="Respiration abnormal"))
    return alerts


@app.post("/vitals", response_model=dict)
def create_vitals(v: VitalCreate, current=Depends(get_current_user)):
    user_id = current["id"]
    timestamp = v.timestamp or datetime.now(timezone.utc)
    record = {
        "user_id": user_id,
        "heartRate": v.heartRate,
        "spo2": v.spo2,
        "temperature": v.temperature,
        "bpSystolic": v.bpSystolic,
        "bpDiastolic": v.bpDiastolic,
        "respirationRate": v.respirationRate,
        "timestamp": timestamp,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["vitalrecord"].insert_one(record)

    # Alerts
    alerts = compute_alerts_for_vitals(user_id, current.get("doctor_id"), v)
    created_alerts = []
    for a in alerts:
        alert_doc = {
            "user_id": a.user_id,
            "doctor_id": a.doctor_id,
            "type": a.type,
            "message": a.message,
            "created_at": datetime.now(timezone.utc),
            "read": False,
        }
        db["alert"].insert_one(alert_doc)
        created_alerts.append(alert_doc)

    # Push via websocket if doctor connected
    ChatManager.notify_alerts(created_alerts)

    return {"id": str(res.inserted_id), "alerts": created_alerts}


@app.get("/vitals/{user_id}", response_model=List[VitalRecord])
def vitals_history(user_id: str, current=Depends(get_current_user)):
    # Access control: doctor can fetch if assigned; patient can fetch own
    if current["role"] == "patient" and current["id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    if current["role"] == "doctor":
        # ensure user is one of doctor's patients
        patient = db["user"].find_one({"_id": _oid(user_id), "doctor_id": current["id"]})
        if not patient:
            raise HTTPException(status_code=403, detail="Not your patient")

    docs = db["vitalrecord"].find({"user_id": user_id}).sort("timestamp", -1).limit(200)
    result: List[VitalRecord] = []
    for d in docs:
        result.append(VitalRecord(
            user_id=d["user_id"],
            heartRate=d["heartRate"],
            spo2=d["spo2"],
            temperature=d["temperature"],
            bpSystolic=d["bpSystolic"],
            bpDiastolic=d["bpDiastolic"],
            respirationRate=d["respirationRate"],
            timestamp=d["timestamp"],
        ))
    return result


# Doctor endpoints

def _oid(id_str: str):
    from bson import ObjectId
    return ObjectId(id_str)


@app.get("/doctor/patients", response_model=List[dict])
def doctor_patients(current=Depends(get_current_user)):
    if current["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Doctor only")
    patients = list(db["user"].find({"doctor_id": current["id"]}))
    output: List[dict] = []
    for p in patients:
        latest = db["vitalrecord"].find({"user_id": str(p["_id"]) }).sort("timestamp", -1).limit(1)
        latest_vital = None
        for d in latest:
            latest_vital = {
                "heartRate": d["heartRate"],
                "spo2": d["spo2"],
                "temperature": d["temperature"],
                "bpSystolic": d["bpSystolic"],
                "bpDiastolic": d["bpDiastolic"],
                "respirationRate": d["respirationRate"],
                "timestamp": d["timestamp"],
            }
        alert_count = db["alert"].count_documents({"user_id": str(p["_id"]), "read": False})
        output.append({
            "id": str(p["_id"]),
            "name": p["name"],
            "email": p["email"],
            "latest_vitals": latest_vital,
            "alert_count": int(alert_count),
        })
    return output


@app.get("/doctor/patients/{patient_id}/alerts", response_model=dict)
def patient_alerts_summary(patient_id: str, current=Depends(get_current_user)):
    if current["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Doctor only")
    if not db["user"].find_one({"_id": _oid(patient_id), "doctor_id": current["id"]}):
        raise HTTPException(status_code=403, detail="Not your patient")

    alerts = list(db["alert"].find({"user_id": patient_id}).sort("created_at", -1).limit(200))
    summary: Dict[str, int] = {}
    for a in alerts:
        t = a["type"]
        summary[t] = summary.get(t, 0) + 1
    return {
        "total": len(alerts),
        "byType": summary,
        "items": [{"type": a["type"], "message": a["message"], "created_at": a["created_at"].isoformat()} for a in alerts],
    }


@app.get("/doctor/summary", response_model=dict)
def doctor_summary(current=Depends(get_current_user)):
    if current["role"] != "doctor":
        raise HTTPException(status_code=403, detail="Doctor only")
    total_patients = db["user"].count_documents({"doctor_id": current["id"]})
    active_alerts = db["alert"].count_documents({"doctor_id": current["id"], "read": False})
    # For MVP, new messages count approximated by last 24h messages
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    new_messages = db["message"].count_documents({"recipient_id": current["id"], "timestamp": {"$gte": since}})
    return {
        "total_patients": int(total_patients),
        "active_alerts": int(active_alerts),
        "new_messages": int(new_messages),
    }


# WebSocket Chat Manager
class ChatManager:
    connections: Dict[str, WebSocket] = {}

    @classmethod
    async def connect(cls, user_id: str, websocket: WebSocket):
        await websocket.accept()
        cls.connections[user_id] = websocket

    @classmethod
    def disconnect(cls, user_id: str):
        if user_id in cls.connections:
            del cls.connections[user_id]

    @classmethod
    async def send_to(cls, user_id: str, message: dict):
        ws = cls.connections.get(user_id)
        if ws:
            await ws.send_json(message)

    @classmethod
    def notify_alerts(cls, alerts: List[dict]):
        # Fire and forget; schedule sending if doctor connected
        for a in alerts:
            doctor_id = a.get("doctor_id")
            if doctor_id and doctor_id in cls.connections:
                # We cannot use await here in sync context; ignore for MVP
                try:
                    import anyio
                    anyio.from_thread.run(asyncio.run, cls.send_to(doctor_id, {"type": "alert", "data": a}))
                except Exception:
                    pass


@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    # Authenticate token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            await websocket.close(code=4401)
            return
    except JWTError:
        await websocket.close(code=4401)
        return

    await ChatManager.connect(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Expect {recipientId, content}
            recipient_id = data.get("recipientId")
            content = data.get("content")
            msg = {
                "sender_id": user_id,
                "recipient_id": recipient_id,
                "content": content,
                "timestamp": datetime.now(timezone.utc),
            }
            db["message"].insert_one(msg)
            # Echo to sender
            await websocket.send_json({"type": "message:sent", "data": {
                "sender_id": user_id,
                "recipient_id": recipient_id,
                "content": content,
                "timestamp": msg["timestamp"].isoformat(),
            }})
            # Forward to recipient if connected
            await ChatManager.send_to(recipient_id, {"type": "message:receive", "data": {
                "sender_id": user_id,
                "recipient_id": recipient_id,
                "content": content,
                "timestamp": msg["timestamp"].isoformat(),
            }})
    except WebSocketDisconnect:
        ChatManager.disconnect(user_id)


@app.get("/test")
def test_database():
    info = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            info["database"] = "✅ Connected"
            info["database_url"] = "✅ Set"
            info["database_name"] = os.getenv("DATABASE_NAME") or ""
            info["connection_status"] = "Connected"
            try:
                info["collections"] = db.list_collection_names()
            except Exception as e:
                info["database"] = f"⚠️ Connected but error: {str(e)[:80]}"
    except Exception as e:
        info["database"] = f"❌ Error: {str(e)[:80]}"
    return info


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
