# Quick Start Guide - ML Model Integration

This is a quick reference guide to get the scanner running immediately.

## ⚡ 5-Minute Setup

### 1. Copy Model Files
```bash
cd SentinelFlow-BE
cp /path/to/malware_classifier.pkl ./
cp /path/to/malware_threshold.pkl ./
```

### 2. Install ML Dependencies
```bash
pip install -r requirements.txt
```

The following packages were added:
- scikit-learn==1.5.1
- joblib==1.4.2
- numpy==1.26.4
- pandas==2.2.2
- esprima==4.0.1

### 3. Start Backend
```bash
uvicorn app.main:app --reload
```

### 4. Get Auth Token
```bash
# Login via OAuth first to get a token
curl http://localhost:8000/api/auth/github/login
```

### 5. Test Scanner Health
```bash
curl http://localhost:8000/api/v1/scan/health \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

Expected response:
```json
{"status": "healthy", "model_loaded": true, "threshold": 0.5}
```

---

## 📦 Files Added

### New Files Created
```
app/services/scanner_service.py          # Core ML service (313 lines)
app/api/endpoints/scan.py                # API endpoints (276 lines)
app/api/schemas/scanner.py               # Pydantic models (96 lines)
app/api/schemas/__init__.py              # Package marker

SCANNER_INTEGRATION.md                   # Full technical docs
SCANNER_API_TESTING.md                   # Testing guide
IMPLEMENTATION_SUMMARY.md                # This implementation summary
QUICK_START.md                           # This quick start
```

### Files Modified
```
app/main.py                              # Added scan router (1 import, 1 router include)
requirements.txt                         # Added 5 ML packages
app/services/__init__.py                 # Updated docstring
```

---

## 🚀 Quick API Reference

### Scan Single Package
```bash
curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@package.whl"
```

### Scan Multiple Packages (Batch)
```bash
curl -X POST http://localhost:8000/api/v1/scan/batch \
  -H "Authorization: Bearer $TOKEN" \
  -F "files=@pkg1.whl" \
  -F "files=@pkg2.whl" \
  -F "files=@pkg3.whl"
```

### Check Service Health
```bash
curl http://localhost:8000/api/v1/scan/health \
  -H "Authorization: Bearer $TOKEN"
```

---

## ✅ What Was Integrated

### Features Extracted (13 total)
**From Code Analysis**:
- eval_count, exec_count, base64_count
- network_imports, settimeout_string_count
- child_process_count, buffer_count

**From Entropy Analysis**:
- max_entropy, avg_entropy

**Engineered**:
- entropy_gap, exec_eval_ratio
- network_exec_ratio, obfuscation_index

### Model Information
- **Algorithm**: Random Forest (scikit-learn)
- **Format**: joblib pickled object
- **Threshold**: 0.5 (configurable)
- **Output**: 
  - Classification (benign/malicious)
  - Probability (0-1)
  - Confidence score
  - Risk level (low/medium/high)

### Security Features
✅ JWT/OAuth2 authentication  
✅ File size limits (100MB)  
✅ Format validation (.zip, .whl, .tar.gz)  
✅ Path traversal protection  
✅ Automatic temp file cleanup  

---

## 🧪 Quick Test

```python
import requests

TOKEN = "your_bearer_token"
headers = {"Authorization": f"Bearer {TOKEN}"}

# Test health
resp = requests.get("http://localhost:8000/api/v1/scan/health", headers=headers)
print("Health:", resp.json())

# Scan a file
with open("test_package.whl", "rb") as f:
    resp = requests.post(
        "http://localhost:8000/api/v1/scan/dependency",
        files={"file": f},
        headers=headers
    )
    result = resp.json()
    print("Classification:", result["prediction"]["classification"])
    print("Confidence:", result["prediction"]["confidence"])
```

---

## 📊 Expected Response Example

```json
{
  "success": true,
  "archive_name": "requests-2.28.1.whl",
  "features": {
    "eval_count": 0.0,
    "exec_count": 0.0,
    "base64_count": 2.0,
    "network_imports": 15.0,
    "max_entropy": 6.45,
    "avg_entropy": 5.12,
    "entropy_gap": 1.33,
    "exec_eval_ratio": 1.0,
    "network_exec_ratio": 15.0,
    "obfuscation_index": 0.92
  },
  "prediction": {
    "classification": "benign",
    "probability_malicious": 0.08,
    "probability_benign": 0.92,
    "confidence": 0.92,
    "risk_level": "low",
    "threshold_used": 0.5
  }
}
```

---

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'sklearn'` | Run `pip install -r requirements.txt` |
| `FileNotFoundError: malware_classifier.pkl` | Copy model files to `SentinelFlow-BE/` root |
| `404 Not Found /api/v1/scan/health` | Make sure backend restarted after code changes |
| `401 Unauthorized` | Provide valid Bearer token in header |
| Model not loaded (health check shows `false`) | Check console for model loading errors |

---

## 📚 Documentation

Read these files for full details:

1. **IMPLEMENTATION_SUMMARY.md** - Complete overview of what was built
2. **SCANNER_INTEGRATION.md** - Technical reference and architecture
3. **SCANNER_API_TESTING.md** - Detailed testing guide with examples

---

## 🎯 Next Steps

1. ✅ Copy model files
2. ✅ Install dependencies  
3. ✅ Start backend
4. ✅ Test health endpoint
5. ✅ Upload and scan test packages
6. ✅ Verify classifications are correct
7. ⏳ Deploy to production

---

## 🔑 Key Files

**Backend Logic**:
- `app/services/scanner_service.py` - Feature extraction + model loading
- `app/api/endpoints/scan.py` - API endpoints
- `app/main.py` - Router registration

**ML Models** (add these):
- `malware_classifier.pkl` - Pre-trained Random Forest
- `malware_threshold.pkl` - Optimal decision threshold

**Configuration**:
- `requirements.txt` - Python dependencies

---

## 📞 Support

For detailed information, see:
- Architecture: IMPLEMENTATION_SUMMARY.md
- Features: SCANNER_INTEGRATION.md  
- Testing: SCANNER_API_TESTING.md

For issues:
1. Check backend logs
2. Verify model files exist
3. Test health endpoint
4. Review error messages in API response
