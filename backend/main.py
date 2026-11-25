from __future__ import annotations

import os
import re
import secrets
import shutil
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

load_dotenv()
ROOT = Path(__file__).parent
SECRET = os.getenv("SECRET_KEY", "local-development-secret-change-before-deploy")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'classroom.db'}")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", str(ROOT / "storage" / "uploads")))
MAX_UPLOAD = int(os.getenv("MAX_UPLOAD_SIZE_MB", "25")) * 1024 * 1024
ALLOWED = set(os.getenv("ALLOWED_EXTENSIONS", "pdf,txt,md,doc,docx,xls,xlsx,ppt,pptx,png,jpg,jpeg,gif,csv,zip").lower().split(","))
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)


class Base(DeclarativeBase): pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="student")


class Classroom(Base):
    __tablename__ = "classrooms"
    id: Mapped[int] = mapped_column(primary_key=True)
    class_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    subject: Mapped[str] = mapped_column(String(100), default="General")
    description: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    owner: Mapped[User] = relationship()
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    enrollments: Mapped[list["Enrollment"]] = relationship(back_populates="classroom", cascade="all, delete-orphan")
    documents: Mapped[list["Document"]] = relationship(back_populates="classroom", cascade="all, delete-orphan")
    boards: Mapped[list["Board"]] = relationship(back_populates="classroom", cascade="all, delete-orphan")


class Enrollment(Base):
    __tablename__ = "enrollments"
    __table_args__ = (UniqueConstraint("classroom_id", "student_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    classroom_id: Mapped[int] = mapped_column(ForeignKey("classrooms.id"))
    student_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    status: Mapped[str] = mapped_column(String(20), default="active")
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    classroom: Mapped[Classroom] = relationship(back_populates="enrollments")
    student: Mapped[User] = relationship()


class Document(Base):
    __tablename__ = "documents"
    id: Mapped[int] = mapped_column(primary_key=True)
    classroom_id: Mapped[int] = mapped_column(ForeignKey("classrooms.id"))
    name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255), unique=True)
    size: Mapped[int] = mapped_column(Integer)
    content_type: Mapped[str] = mapped_column(String(160), default="application/octet-stream")
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    classroom: Mapped[Classroom] = relationship(back_populates="documents")


class Board(Base):
    __tablename__ = "boards"
    id: Mapped[int] = mapped_column(primary_key=True)
    classroom_id: Mapped[int] = mapped_column(ForeignKey("classrooms.id"))
    name: Mapped[str] = mapped_column(String(160), default="Lesson board")
    snapshot: Mapped[str] = mapped_column(Text)
    saved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    classroom: Mapped[Classroom] = relationship(back_populates="boards")


class Credentials(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str | None = None


class ClassroomInput(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    subject: str = Field(default="General", max_length=100)
    description: str = Field(default="", max_length=2000)


class BoardInput(BaseModel):
    name: str = Field(default="Lesson board", max_length=160)
    snapshot: dict[str, Any]


class ManagedUserInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    role: str
    password: str | None = Field(default=None, min_length=8, max_length=128)
    batch_ids: list[int] = Field(default_factory=list)


def db_session():
    db = SessionLocal()
    try: yield db
    finally: db.close()


def token_for(user: User) -> str:
    return jwt.encode({"sub": str(user.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")))}, SECRET, algorithm="HS256")


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer), db: Session = Depends(db_session)) -> User:
    if not creds: raise HTTPException(401, "Sign in to continue")
    try: uid = int(jwt.decode(creds.credentials, SECRET, algorithms=["HS256"])["sub"])
    except Exception: raise HTTPException(401, "Session expired; please sign in again")
    user = db.get(User, uid)
    if not user: raise HTTPException(401, "Account not found")
    return user


def teacher(user: User = Depends(current_user)) -> User:
    if user.role != "teacher": raise HTTPException(403, "Teacher access required")
    return user


def admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin": raise HTTPException(403, "Admin access required")
    return user


def pack_user(user: User) -> dict: return {"id": user.id, "name": user.name, "email": user.email, "role": user.role}
def pack_class(c: Classroom, db: Session) -> dict:
    return {"id": c.id, "class_id": c.class_id, "name": c.name, "subject": c.subject, "description": c.description, "created_at": c.created_at.isoformat(), "student_count": len(c.enrollments), "document_count": len(c.documents), "last_saved": max((b.saved_at for b in c.boards), default=None).isoformat() if c.boards else None}
def owned_class(db: Session, c_id: int, user: User) -> Classroom:
    c = db.get(Classroom, c_id)
    if not c: raise HTTPException(404, "Classroom not found")
    if user.role == "teacher" and c.owner_id == user.id: return c
    if db.scalar(select(Enrollment).where(Enrollment.classroom_id == c_id, Enrollment.student_id == user.id)): return c
    raise HTTPException(403, "You are not enrolled in this classroom")


app = FastAPI(title="Classroom Portal API", version="1.0.0")
origins = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def create_admin_account(email: str, name: str, password: str):
    """Create the first administrator explicitly from the command line."""
    with SessionLocal() as db:
        normalized_email = email.lower()
        existing = db.scalar(select(User).where(User.email == normalized_email))
        if existing:
            raise SystemExit("That email already belongs to an account; no changes were made.")
        person = User(name=name.strip(), email=normalized_email, password_hash=pwd.hash(password), role="admin")
        db.add(person); db.commit()
        print(f"Administrator account created for {normalized_email}")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.email == "teacher@demo.edu")):
            t = User(name="Morgan Lee", email="teacher@demo.edu", password_hash=pwd.hash("teach1234"), role="teacher")
            s1 = User(name="Avery Johnson", email="avery@demo.edu", password_hash=pwd.hash("learn1234"), role="student")
            s2 = User(name="Noah Williams", email="noah@demo.edu", password_hash=pwd.hash("learn1234"), role="student")
            c = Classroom(class_id="BIO-101", name="Foundations of Biology", subject="Biology", description="Explore the building blocks of life, from cells to ecosystems.", owner=t)
            db.add_all([t, s1, s2, c]); db.flush()
            db.add_all([Enrollment(classroom_id=c.id, student_id=s1.id), Enrollment(classroom_id=c.id, student_id=s2.id)])
            db.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Classroom Portal administration")
    parser.add_argument("--create-admin", action="store_true", help="Create an administrator account")
    parser.add_argument("--email", help="Administrator email")
    parser.add_argument("--name", help="Administrator name")
    parser.add_argument("--password", help="Administrator password (at least 12 characters)")
    args, _ = parser.parse_known_args()
    if args.create_admin:
        if not args.email or not args.name or not args.password or len(args.password) < 12:
            parser.error("--create-admin requires --email, --name and --password (at least 12 characters)")
        Base.metadata.create_all(engine)
        create_admin_account(args.email, args.name, args.password)


@app.get("/api/health")
def health(): return {"status": "ok"}


@app.post("/api/auth/register")
def register(data: Credentials, db: Session = Depends(db_session)):
    email = data.email.lower()
    if db.scalar(select(User).where(User.email == email)): raise HTTPException(409, "An account with that email already exists")
    user = User(name=(data.name or email.split("@")[0]).strip(), email=email, password_hash=pwd.hash(data.password), role="student")
    db.add(user); db.commit(); db.refresh(user)
    return {"token": token_for(user), "user": pack_user(user)}


@app.post("/api/auth/login")
def login(data: Credentials, db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if not user or not pwd.verify(data.password, user.password_hash): raise HTTPException(401, "Email or password is incorrect")
    return {"token": token_for(user), "user": pack_user(user)}


@app.post("/api/auth/admin-login")
def admin_login(data: Credentials, db: Session = Depends(db_session)):
    user = db.scalar(select(User).where(User.email == data.email.lower()))
    if not user or user.role != "admin" or not pwd.verify(data.password, user.password_hash):
        raise HTTPException(401, "Admin email or password is incorrect")
    return {"token": token_for(user), "user": pack_user(user)}


@app.get("/api/admin/overview")
def admin_overview(db: Session = Depends(db_session), user: User = Depends(admin)):
    people = db.scalars(select(User).where(User.role.in_(["teacher", "student"])).order_by(User.name)).all()
    classes = db.scalars(select(Classroom).order_by(Classroom.name)).all()
    return {"users": [{**pack_user(person), "batch_ids": [e.classroom_id for e in db.scalars(select(Enrollment).where(Enrollment.student_id == person.id)).all()], "trainer_batches": [c.id for c in classes if c.owner_id == person.id]} for person in people], "batches": [{"id": c.id, "name": c.name, "class_id": c.class_id, "subject": c.subject, "trainer_id": c.owner_id, "student_count": len(c.enrollments)} for c in classes]}


@app.post("/api/admin/users")
def admin_create_user(data: ManagedUserInput, db: Session = Depends(db_session), user: User = Depends(admin)):
    email = data.email.lower()
    if data.role not in ("teacher", "student"): raise HTTPException(400, "Choose trainer or student")
    if not data.password: raise HTTPException(400, "A password is required for a new account")
    if db.scalar(select(User).where(User.email == email)): raise HTTPException(409, "An account with that email already exists")
    person = User(name=data.name.strip(), email=email, password_hash=pwd.hash(data.password), role=data.role)
    db.add(person); db.flush()
    if data.role == "student":
        for cid in set(data.batch_ids):
            db.add(Enrollment(classroom_id=cid, student_id=person.id))
    db.commit(); db.refresh(person)
    return pack_user(person)


@app.put("/api/admin/users/{user_id}")
def admin_update_user(user_id: int, data: ManagedUserInput, db: Session = Depends(db_session), user: User = Depends(admin)):
    person = db.get(User, user_id)
    if not person or person.role not in ("teacher", "student"): raise HTTPException(404, "Account not found")
    if data.role not in ("teacher", "student"): raise HTTPException(400, "Choose trainer or student")
    email = data.email.lower()
    duplicate = db.scalar(select(User).where(User.email == email, User.id != person.id))
    if duplicate: raise HTTPException(409, "An account with that email already exists")
    person.name = data.name.strip(); person.email = email
    if data.password: person.password_hash = pwd.hash(data.password)
    if person.role != data.role:
        if person.role == "teacher":
            for c in db.scalars(select(Classroom).where(Classroom.owner_id == person.id)).all(): c.owner_id = user.id
        else:
            db.query(Enrollment).filter(Enrollment.student_id == person.id).delete(synchronize_session=False)
        person.role = data.role
    if data.role == "student":
        valid = set(data.batch_ids)
        for e in db.scalars(select(Enrollment).where(Enrollment.student_id == person.id)).all():
            if e.classroom_id not in valid: db.delete(e)
        existing = {e.classroom_id for e in db.scalars(select(Enrollment).where(Enrollment.student_id == person.id)).all()}
        for cid in valid - existing:
            db.add(Enrollment(classroom_id=cid, student_id=person.id))
    db.commit(); return pack_user(person)


@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, db: Session = Depends(db_session), user: User = Depends(admin)):
    person = db.get(User, user_id)
    if not person or person.role not in ("teacher", "student"): raise HTTPException(404, "Account not found")
    if person.role == "teacher":
        for c in db.scalars(select(Classroom).where(Classroom.owner_id == person.id)).all():
            for doc in c.documents:
                path = UPLOAD_DIR / doc.stored_name
                if path.is_file(): path.unlink()
            db.delete(c)
    else:
        db.query(Enrollment).filter(Enrollment.student_id == person.id).delete(synchronize_session=False)
    db.delete(person); db.commit(); return {"ok": True}


@app.post("/api/admin/batches/{batch_id}/trainer/{trainer_id}")
def admin_assign_trainer(batch_id: int, trainer_id: int, db: Session = Depends(db_session), user: User = Depends(admin)):
    c = db.get(Classroom, batch_id); trainer_user = db.get(User, trainer_id)
    if not c: raise HTTPException(404, "Batch not found")
    if not trainer_user or trainer_user.role != "teacher": raise HTTPException(400, "Choose a trainer account")
    c.owner_id = trainer_user.id; db.commit(); return {"ok": True}


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)): return pack_user(user)


@app.get("/api/classrooms")
def classrooms(db: Session = Depends(db_session), user: User = Depends(current_user)):
    if user.role == "teacher": rows = db.scalars(select(Classroom).where(Classroom.owner_id == user.id).order_by(Classroom.created_at.desc())).all()
    else: rows = db.scalars(select(Classroom).join(Enrollment).where(Enrollment.student_id == user.id)).all()
    return [pack_class(c, db) for c in rows]


@app.post("/api/classrooms")
def create_class(data: ClassroomInput, db: Session = Depends(db_session), user: User = Depends(teacher)):
    prefix = re.sub(r"[^A-Z0-9]", "", data.subject.upper())[:4] or "ROOM"
    class_id = f"{prefix}-{secrets.token_hex(2).upper()}"
    c = Classroom(class_id=class_id, name=data.name.strip(), subject=data.subject.strip(), description=data.description.strip(), owner_id=user.id)
    db.add(c); db.commit(); db.refresh(c); return pack_class(c, db)


@app.post("/api/classrooms/join/{class_id}")
def join_class(class_id: str, db: Session = Depends(db_session), user: User = Depends(current_user)):
    c = db.scalar(select(Classroom).where(Classroom.class_id == class_id.upper()))
    if not c: raise HTTPException(404, "No classroom has that Class ID")
    if user.role != "student": raise HTTPException(403, "Only student accounts can join a classroom")
    if not db.scalar(select(Enrollment).where(Enrollment.classroom_id == c.id, Enrollment.student_id == user.id)):
        db.add(Enrollment(classroom_id=c.id, student_id=user.id)); db.commit()
    return pack_class(c, db)


@app.get("/api/classrooms/{cid}")
def get_class(cid: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    return pack_class(owned_class(db, cid, user), db)


@app.get("/api/classrooms/{cid}/students")
def students(cid: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    c = owned_class(db, cid, user)
    if user.role != "teacher": raise HTTPException(403, "Teacher access required")
    return [{**pack_user(e.student), "status": e.status, "enrolled_at": e.enrolled_at.isoformat()} for e in c.enrollments]


@app.post("/api/classrooms/{cid}/students")
def add_student(cid: int, data: Credentials, db: Session = Depends(db_session), user: User = Depends(teacher)):
    c = db.get(Classroom, cid)
    if not c or c.owner_id != user.id: raise HTTPException(404, "Classroom not found")
    student = db.scalar(select(User).where(User.email == data.email.lower()))
    if not student:
        student = User(name=(data.name or data.email.split("@")[0]).strip(), email=data.email.lower(), password_hash=pwd.hash(data.password), role="student")
        db.add(student); db.flush()
    if student.role != "student": raise HTTPException(400, "That email belongs to a teacher account")
    if not db.scalar(select(Enrollment).where(Enrollment.classroom_id == cid, Enrollment.student_id == student.id)):
        db.add(Enrollment(classroom_id=cid, student_id=student.id)); db.commit()
    return pack_user(student)


@app.get("/api/classrooms/{cid}/boards")
def boards(cid: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    c = owned_class(db, cid, user)
    return [{"id": b.id, "name": b.name, "saved_at": b.saved_at.isoformat()} for b in sorted(c.boards, key=lambda x: x.saved_at, reverse=True)]


@app.post("/api/classrooms/{cid}/boards")
def save_board(cid: int, data: BoardInput, db: Session = Depends(db_session), user: User = Depends(teacher)):
    c = db.get(Classroom, cid)
    if not c or c.owner_id != user.id: raise HTTPException(404, "Classroom not found")
    b = Board(classroom_id=cid, name=data.name, snapshot=__import__("json").dumps(data.snapshot))
    db.add(b); db.commit(); db.refresh(b)
    return {"id": b.id, "name": b.name, "saved_at": b.saved_at.isoformat()}


@app.get("/api/classrooms/{cid}/boards/{bid}")
def open_board(cid: int, bid: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    owned_class(db, cid, user)
    b = db.scalar(select(Board).where(Board.id == bid, Board.classroom_id == cid))
    if not b: raise HTTPException(404, "Saved board not found")
    import json
    return {"id": b.id, "name": b.name, "snapshot": json.loads(b.snapshot), "saved_at": b.saved_at.isoformat()}


@app.get("/api/classrooms/{cid}/documents")
def documents(cid: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    c = owned_class(db, cid, user)
    return [{"id": d.id, "name": d.name, "size": d.size, "content_type": d.content_type, "uploaded_at": d.uploaded_at.isoformat()} for d in sorted(c.documents, key=lambda x: x.uploaded_at, reverse=True)]


@app.post("/api/classrooms/{cid}/documents")
async def upload_document(cid: int, file: UploadFile = File(...), db: Session = Depends(db_session), user: User = Depends(teacher)):
    c = db.get(Classroom, cid)
    if not c or c.owner_id != user.id: raise HTTPException(404, "Classroom not found")
    name = Path(file.filename or "document").name
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED: raise HTTPException(415, f"File type .{ext} is not allowed")
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD: raise HTTPException(413, f"Files must be smaller than {MAX_UPLOAD // (1024 * 1024)} MB")
    stored = secrets.token_hex(16) + "." + ext
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    (UPLOAD_DIR / stored).write_bytes(data)
    doc = Document(classroom_id=cid, name=name, stored_name=stored, size=len(data), content_type=file.content_type or "application/octet-stream")
    db.add(doc); db.commit(); db.refresh(doc)
    return {"id": doc.id, "name": doc.name, "size": doc.size, "uploaded_at": doc.uploaded_at.isoformat()}


@app.get("/api/classrooms/{cid}/documents/{did}/download")
def download_document(cid: int, did: int, db: Session = Depends(db_session), user: User = Depends(current_user)):
    owned_class(db, cid, user)
    doc = db.scalar(select(Document).where(Document.id == did, Document.classroom_id == cid))
    if not doc: raise HTTPException(404, "Document not found")
    path = UPLOAD_DIR / doc.stored_name
    if not path.is_file(): raise HTTPException(404, "Document file is missing")
    return FileResponse(path, filename=doc.name, media_type=doc.content_type)


@app.delete("/api/classrooms/{cid}/documents/{did}")
def delete_document(cid: int, did: int, db: Session = Depends(db_session), user: User = Depends(teacher)):
    c = db.get(Classroom, cid)
    if not c or c.owner_id != user.id: raise HTTPException(404, "Classroom not found")
    doc = db.scalar(select(Document).where(Document.id == did, Document.classroom_id == cid))
    if not doc: raise HTTPException(404, "Document not found")
    path = UPLOAD_DIR / doc.stored_name
    if path.is_file(): path.unlink()
    db.delete(doc); db.commit(); return {"ok": True}
