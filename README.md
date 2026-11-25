# Chalkboard classroom portal

A full-stack teaching portal built with **React + TypeScript + Vite**, **FastAPI**, **SQLite**, and the official **tldraw SDK**. Uploaded files are stored in a private local folder (`backend/storage/uploads`) with random server-side filenames.

## Run locally

Requirements: Python 3.11+ and Node.js 18+.

1. Create the backend environment and install packages:

   ```powershell
   cd backend
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

   Set `SECRET_KEY` in `backend/.env` to a unique random value before using real accounts. The default SQLite database and upload location work without external services.

2. Start the API in the backend folder:

   ```powershell
   uvicorn main:app --reload
   ```

   The first start creates the tables and sample classroom. API documentation is at http://localhost:8000/docs.

3. In a second terminal, start the frontend:

   ```powershell
   cd frontend
   npm install
   npm run dev
   ```

   Open http://localhost:5173.

## Demo accounts

- Teacher: `teacher@demo.edu` / `teach1234`
- Student: `avery@demo.edu` / `learn1234`
- Sample Class ID: `BIO-101`

## Administrator access

Open `/admin/login` for the separate administrator sign-in. There is no public admin registration. After configuring `backend/.env`, create an administrator from the backend folder with:

```powershell
uvicorn main:app --reload
```

In another backend terminal, run:

```powershell
python main.py --create-admin --email admin@school.edu --name "School Admin" --password "use-a-unique-password-of-12-or-more-characters"
```

Sign in at `http://localhost:5173/admin/login`. Admins can add, edit, and remove trainer and student accounts, enroll students in batches, and assign trainers to batches. Removing a trainer also removes their classrooms and classroom materials.

The student may sign in to view the sample classroom. New self-registered accounts have the student role. A teacher creates student accounts from the classroom roster.

## Configuration and behavior

Copy `backend/.env.example` to `backend/.env`. Configure `SECRET_KEY`, `DATABASE_URL`, `UPLOAD_DIR`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `MAX_UPLOAD_SIZE_MB`, `ALLOWED_EXTENSIONS`, and `CORS_ORIGINS` there. No external service or credential is required for local development. For production, use a managed database and private object storage, HTTPS, a strong secret, and a deployment-specific CORS allowlist.

Teachers can create classrooms, enroll students, upload/remove materials, and save tldraw snapshots. Students can join with a Class ID, view class resources, download materials, and reopen saved boards. Board snapshots are saved as named versions in SQLite and can be restored from History. Document uploads have extension and size checks; files are served only through an authenticated classroom endpoint. Authentication uses signed bearer tokens; this starter uses bcrypt password hashes and should be deployed behind HTTPS.
