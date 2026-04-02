# API Testing Guide for Malware Scanner Integration

This guide walks you through testing the malware scanner endpoints integrated into SentinelFlow-BE.

## Prerequisites

1. **Backend Running**
   ```bash
   cd SentinelFlow-BE
   python -m uvicorn app.main:app --reload
   ```

2. **Valid Authentication Token**
   - Obtain a Bearer token via `/api/auth/github/login` or GitHub OAuth flow
   - Token required for all scanner endpoints

3. **Test Packages**
   - Sample test files: benign and malicious packages from the malicious-software-packages-dataset

## Test Scenarios

### Scenario 1: Health Check
**Purpose**: Verify scanner service is operational

```bash
curl -X GET http://localhost:8000/api/v1/scan/health \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

**Expected Response** (200 OK):
```json
{
  "status": "healthy",
  "model_loaded": true,
  "threshold": 0.5
}
```

**Success Criteria**:
- ✅ Status is "healthy"
- ✅ model_loaded is true
- ✅ threshold is a valid float

---

### Scenario 2: Scan Benign Package
**Purpose**: Confirm benign packages are correctly classified

1. Prepare a benign package (e.g., from `malicious-software-packages-dataset/samples/`)
2. Upload and scan:

```bash
curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@/path/to/benign_package.whl"
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "archive_name": "benign_package.whl",
  "features": {
    "eval_count": 0.0,
    "exec_count": 0.0,
    "base64_count": 0.0,
    "network_imports": 2.0,
    "settimeout_string_count": 0.0,
    "child_process_count": 0.0,
    "buffer_count": 0.0,
    "max_entropy": 5.8,
    "avg_entropy": 4.2,
    "entropy_gap": 1.6,
    "exec_eval_ratio": 1.0,
    "network_exec_ratio": 2.0,
    "obfuscation_index": 0.0
  },
  "prediction": {
    "classification": "benign",
    "probability_malicious": 0.15,
    "probability_benign": 0.85,
    "confidence": 0.85,
    "risk_level": "low",
    "threshold_used": 0.5
  }
}
```

**Success Criteria**:
- ✅ success is true
- ✅ classification is "benign"
- ✅ probability_malicious < 0.5
- ✅ risk_level is "low" or "medium"
- ✅ All features are numeric and non-negative

---

### Scenario 3: Scan Malicious Package
**Purpose**: Confirm malicious packages are correctly detected

1. Prepare a malicious package (e.g., from `malicious-software-packages-dataset/samples/npm/malicious_intent/`)
2. Upload and scan:

```bash
curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@/path/to/malicious_package.whl"
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "archive_name": "malicious_package.whl",
  "features": {
    "eval_count": 3.0,
    "exec_count": 5.0,
    "base64_count": 4.0,
    "network_imports": 8.0,
    "settimeout_string_count": 2.0,
    "child_process_count": 1.0,
    "buffer_count": 3.0,
    "max_entropy": 7.2,
    "avg_entropy": 6.1,
    "entropy_gap": 1.1,
    "exec_eval_ratio": 1.67,
    "network_exec_ratio": 1.6,
    "obfuscation_index": 4.4
  },
  "prediction": {
    "classification": "malicious",
    "probability_malicious": 0.82,
    "probability_benign": 0.18,
    "confidence": 0.82,
    "risk_level": "high",
    "threshold_used": 0.5
  }
}
```

**Success Criteria**:
- ✅ success is true
- ✅ classification is "malicious"
- ✅ probability_malicious > 0.5
- ✅ risk_level is "high"
- ✅ Features show suspicious patterns (high eval_count, exec_count, base64_count, etc.)

---

### Scenario 4: Batch Scanning
**Purpose**: Test multiple packages can be scanned efficiently

```bash
curl -X POST http://localhost:8000/api/v1/scan/batch \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "files=@/path/to/package1.whl" \
  -F "files=@/path/to/package2.whl" \
  -F "files=@/path/to/package3.whl"
```

**Expected Response** (200 OK):
```json
{
  "success": true,
  "total_files": 3,
  "scanned": 3,
  "malicious_count": 1,
  "benign_count": 2,
  "error_count": 0,
  "results": [
    {
      "file": "package1.whl",
      "prediction": {
        "classification": "benign",
        "probability_malicious": 0.22,
        "probability_benign": 0.78,
        "confidence": 0.78,
        "risk_level": "low",
        "threshold_used": 0.5
      }
    },
    {
      "file": "package2.whl",
      "prediction": {
        "classification": "malicious",
        "probability_malicious": 0.87,
        "probability_benign": 0.13,
        "confidence": 0.87,
        "risk_level": "high",
        "threshold_used": 0.5
      }
    },
    {
      "file": "package3.whl",
      "prediction": {
        "classification": "benign",
        "probability_malicious": 0.18,
        "probability_benign": 0.82,
        "confidence": 0.82,
        "risk_level": "low",
        "threshold_used": 0.5
      }
    }
  ]
}
```

**Success Criteria**:
- ✅ success is true
- ✅ scanned == total_files
- ✅ error_count == 0
- ✅ malicious_count + benign_count == total_files
- ✅ Each result contains valid prediction

---

### Scenario 5: Authentication Error
**Purpose**: Verify authentication is enforced

```bash
# No token provided
curl -X GET http://localhost:8000/api/v1/scan/health
```

**Expected Response** (403 Forbidden):
```json
{
  "detail": "Not authenticated"
}
```

**Success Criteria**:
- ✅ Returns 403 status
- ✅ Request is rejected without token

---

### Scenario 6: Invalid File Format
**Purpose**: Test error handling for unsupported formats

```bash
# Create a text file as test
echo "This is not a package" > test.txt

curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@test.txt"
```

**Expected Response** (400 Bad Request):
```json
{
  "success": false,
  "error": "Unsupported archive format: .txt"
}
```

**Success Criteria**:
- ✅ Returns 400 status
- ✅ success is false
- ✅ Descriptive error message provided

---

### Scenario 7: Large File Handling
**Purpose**: Verify file size limits are enforced

```bash
# Create a file larger than 100MB
dd if=/dev/zero of=big_file.whl bs=1M count=101

curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@big_file.whl"
```

**Expected Response** (413 Payload Too Large):
```json
{
  "detail": "File size exceeds 100MB limit"
}
```

**Success Criteria**:
- ✅ Returns 413 status
- ✅ Large files are rejected

---

### Scenario 8: Empty File
**Purpose**: Test handling of empty files

```bash
# Create an empty file
touch empty.whl

curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@empty.whl"
```

**Expected Response** (400 Bad Request):
```json
{
  "success": false,
  "error": "Uploaded file is empty"
}
```

**Success Criteria**:
- ✅ Returns 400 status
- ✅ Empty files are rejected with clear message

---

## Python Testing Script

Create a comprehensive test script:

```python
#!/usr/bin/env python3
"""
Comprehensive test script for Malware Scanner API
"""

import requests
import os
from pathlib import Path

BASE_URL = "http://localhost:8000"
TOKEN = "YOUR_BEARER_TOKEN_HERE"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

def test_health():
    """Test health check endpoint"""
    print("Testing /api/v1/scan/health...")
    response = requests.get(f"{BASE_URL}/api/v1/scan/health", headers=HEADERS)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}\n")
    assert response.status_code == 200
    assert response.json()["model_loaded"] == True

def test_scan_file(file_path):
    """Test single file scan"""
    print(f"Testing /api/v1/scan/dependency with {file_path}...")
    with open(file_path, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/api/v1/scan/dependency",
            files={"file": f},
            headers=HEADERS
        )
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Classification: {result['prediction']['classification']}")
    print(f"Confidence: {result['prediction']['confidence']:.2%}\n")
    assert response.status_code == 200
    assert result["success"] == True

def test_batch_scan(file_paths):
    """Test batch scan"""
    print(f"Testing /api/v1/scan/batch with {len(file_paths)} files...")
    files = [("files", open(fp, "rb")) for fp in file_paths]
    response = requests.post(
        f"{BASE_URL}/api/v1/scan/batch",
        files=files,
        headers=HEADERS
    )
    print(f"Status: {response.status_code}")
    result = response.json()
    print(f"Scanned: {result['scanned']}")
    print(f"Malicious: {result['malicious_count']}")
    print(f"Benign: {result['benign_count']}\n")
    assert response.status_code == 200
    assert result["success"] == True

if __name__ == "__main__":
    print("=== Scanner API Test Suite ===\n")
    
    # Test 1: Health
    test_health()
    
    # Test 2: Single file scan (requires test files)
    test_file = "test_package.whl"
    if os.path.exists(test_file):
        test_scan_file(test_file)
    
    # Test 3: Batch scan (requires multiple test files)
    test_files = ["package1.whl", "package2.whl"]
    if all(os.path.exists(f) for f in test_files):
        test_batch_scan(test_files)
    
    print("=== All tests completed ===")
```

## Integration Testing Checklist

- [ ] Model files exist in SentinelFlow-BE root
- [ ] Dependencies installed: `pip install -r requirements.txt`
- [ ] Backend starts without errors
- [ ] Health endpoint returns healthy status
- [ ] Benign package classified as benign
- [ ] Malicious package classified as malicious
- [ ] Batch scanning processes multiple files
- [ ] Authentication required for all endpoints
- [ ] File size limits enforced
- [ ] Invalid file formats rejected
- [ ] Empty files rejected
- [ ] Feature extraction produces valid numeric values
- [ ] Confidence scores are between 0 and 1
- [ ] Risk levels match probability ranges

## Performance Testing

```bash
# Measure scan time for single file
time curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -F "file=@test_package.whl"

# Expected: < 10 seconds for typical package
```

## Logs and Debugging

Enable verbose logging:

```python
# In app configuration
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check logs for:
- Model loading confirmation
- Feature extraction details
- Prediction confidence scores
- Any errors during processing

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Model not loading | Check files exist in root directory, verify permissions |
| Feature values are all 0 | Check if package contains .py or .js files |
| Classification always benign | Verify malware threshold is correct |
| High memory usage | Reduce batch size, close other applications |
| Slow response times | Check CPU usage, reduce concurrent scans |

## Next Steps

1. ✅ Test all endpoints with provided test cases
2. ✅ Verify feature extraction accuracy
3. ✅ Validate classification results
4. ✅ Performance test with large batches
5. ⏳ Deploy to production environment
6. ⏳ Monitor scanner performance metrics
7. ⏳ Collect user feedback and iterate
