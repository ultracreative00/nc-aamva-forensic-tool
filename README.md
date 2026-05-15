# NC AAMVA Forensic Tool v4.0

Production-grade North Carolina driver license / ID barcode authentication tool.

## Architecture

| Layer | File | Role |
|---|---|---|
| Backend API | `app.py` | FastAPI server with `/api/analyse/text` and `/api/analyse/image` endpoints |
| Engine | `nc_aamva_engine.py` | 5-layer forensic analysis pipeline (parser → NC validator → forensic signals → classifier → report) |
| Template | `templates/index.html` | Web UI (place here) |

## Quick Start

```bash
pip install -r requirements.txt
python app.py
# Server at http://localhost:8000
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/analyse/text` | Analyse raw barcode string (`{"barcode": "..."}`) |
| `POST` | `/api/analyse/image` | Upload barcode image (multipart) |
| `GET` | `/` | Web UI |

## Forensic Signals (31 total)

- **Hard-fail signals** (instant UNAUTHENTIC): `encoding_binary`, `iin_registered`, `dl_subfile_found`
- **Scoring signals**: IIN/state match, AAMVA version, mandatory fields, NC 12-digit DL number, sex/eye/hair codes, height format, DOB age, birthday-linked expiry, ZIP format, DCK vendor, ZN subfile, and more

## Verdict Thresholds

| Confidence | Verdict |
|---|---|
| Any hard-fail | `UNAUTHENTIC` |
| >= 85% | `AUTHENTIC` |
| 60–84% | `INCONCLUSIVE` |
| < 60% | `UNAUTHENTIC` |

## NC-Specific Checks

- IIN must be `636004`
- DL number (DAQ): exactly 12 digits
- Expiry (DBA): must match DOB month/day (NC expires on birthday)
- ZN jurisdiction subfile: must be present
- DCK: 20 chars, first 12 match DAQ
