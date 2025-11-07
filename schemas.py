from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Literal, List
from datetime import datetime

Role = Literal['doctor', 'patient']

class User(BaseModel):
    name: str
    email: EmailStr
    password_hash: str
    role: Role
    doctor_id: Optional[str] = Field(default=None, description="Assigned doctor's user id for patients")
    doctor_code: Optional[str] = Field(default=None, description="Invite/connection code for doctors")

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Role
    doctor_code: Optional[str] = None
    doctor_email: Optional[EmailStr] = None

class UserPublic(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: Role
    doctor_id: Optional[str] = None
    doctor_code: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    user: UserPublic

class VitalRecord(BaseModel):
    user_id: str
    heartRate: int
    spo2: int
    temperature: float
    bpSystolic: int
    bpDiastolic: int
    respirationRate: int
    timestamp: datetime

class VitalCreate(BaseModel):
    heartRate: int
    spo2: int
    temperature: float
    bpSystolic: int
    bpDiastolic: int
    respirationRate: int
    timestamp: Optional[datetime] = None

class Alert(BaseModel):
    user_id: str
    doctor_id: str
    type: Literal['heartRate_low','heartRate_high','spo2_low','temperature_high','bp_high','respiration_abnormal']
    message: str
    created_at: Optional[datetime] = None

class Message(BaseModel):
    sender_id: str
    recipient_id: str
    content: str
    timestamp: datetime

class PatientSummary(BaseModel):
    id: str
    name: str
    email: EmailStr
    latest_vitals: Optional[VitalRecord] = None
    alert_count: int = 0

class DoctorDashboardSummary(BaseModel):
    total_patients: int
    active_alerts: int
    new_messages: int
