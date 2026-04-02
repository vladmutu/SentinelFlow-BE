# Malware Scanner API Integration

## Overview

This document explains the integration of a pre-trained Random Forest machine learning model into the SentinelFlow-BE FastAPI backend for malware detection in software packages and dependencies.

## Architecture

### Components

1. **Scanner Service** (`app/services/scanner_service.py`)
   - Loads pre-trained Random Forest model from `malware_classifier.pkl`
   - Loads optimal classification threshold from `malware_threshold.pkl`
   - Extracts features from code files using AST parsing and entropy calculation

2. **Scanner Endpoint** (`app/api/endpoints/scan.py`)
   - REST API endpoints for package scanning
   - Authentication-protected routes
   - Supports single and batch scanning

3. **Data Models** (`app/api/schemas/scanner.py`)
   - Pydantic models for request/response validation
   - Type-safe API contracts

4. **Model Files**
   - `malware_classifier.pkl` - Random Forest classifier
   - `malware_threshold.pkl` - Optimal decision threshold

## Features Extracted

The scanner analyzes code to extract 13 features used by the ML model:

### AST-Based Features (7)
- **eval_count**: Number of `eval()` calls detected
- **exec_count**: Number of `exec()` calls detected
- **base64_count**: Number of base64 encoding/decoding operations
- **network_imports**: Count of network module imports (requests, socket, urllib)
- **settimeout_string_count**: `setTimeout()` calls with string arguments (JavaScript)
- **child_process_count**: Child process spawns (JavaScript)
- **buffer_count**: Buffer operations (JavaScript)

### Entropy Features (2)
- **max_entropy**: Maximum Shannon entropy across all files (0-8 bits/byte)
- **avg_entropy**: Average Shannon entropy across all files

### Engineered Features (4)
- **entropy_gap**: max_entropy - avg_entropy
- **exec_eval_ratio**: (exec_count + 1) / (eval_count + 1)
- **network_exec_ratio**: (network_imports + 1) / (exec_count + 1)
- **obfuscation_index**: entropy_gap * log(1 + base64_count)

## API Endpoints

### 1. Health Check
```
GET /api/v1/scan/health
```

**Authentication**: Required (Bearer token)

**Response**:
```json
{
  "status": "healthy",
  "model_loaded": true,
  "threshold": 0.5
}
```

---

### 2. Scan Single Dependency
```
POST /api/v1/scan/dependency
Content-Type: multipart/form-data

file: <archive file>
```

**Authentication**: Required (Bearer token)

**Supported Formats**: .zip, .whl, .tar.gz

**Request**: Upload a package archive

**Response (Success)**:
```json
{
  "success": true,
  "archive_name": "requests-2.28.1.whl",
  "features": {
    "eval_count": 0.0,
    "exec_count": 0.0,
    "base64_count": 2.0,
    "network_imports": 15.0,
    "settimeout_string_count": 0.0,
    "child_process_count": 0.0,
    "buffer_count": 0.0,
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

**Response (Error)**:
```json
{
  "success": false,
  "error": "Unsupported archive format: .rar"
}
```

---

### 3. Scan Repository (GitHub)
```
POST /api/v1/scan/repository
Content-Type: application/json

{
  "repo_url": "https://github.com/user/repo",
  "branch": "main"
}
```

**Authentication**: Required (Bearer token)

**Status**: Currently returns 501 Not Implemented (requires GitHub API integration)

---

### 4. Batch Scan
```
POST /api/v1/scan/batch
Content-Type: multipart/form-data

files: <multiple archive files>
```

**Authentication**: Required (Bearer token)

**Limits**: Maximum 50 files per batch

**Response**:
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
        "probability_malicious": 0.12,
        "confidence": 0.88,
        "risk_level": "low"
      }
    },
    {
      "file": "package2.whl",
      "prediction": {
        "classification": "malicious",
        "probability_malicious": 0.87,
        "confidence": 0.87,
        "risk_level": "high"
      }
    },
    {
      "file": "package3.whl",
      "prediction": {
        "classification": "benign",
        "probability_malicious": 0.05,
        "confidence": 0.95,
        "risk_level": "low"
      }
    }
  ]
}
```

## Classification Output

### Risk Levels
- **low**: probability_malicious < 0.3
- **medium**: 0.3 ≤ probability_malicious < 0.7
- **high**: probability_malicious ≥ 0.7

### Default Threshold
- Threshold: 0.5 (configurable via `malware_threshold.pkl`)
- Classification: malicious if probability_malicious ≥ threshold

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

Dependencies added:
- `scikit-learn==1.5.1` - Machine learning framework
- `joblib==1.4.2` - Model serialization
- `numpy==1.26.4` - Numerical operations
- `pandas==2.2.2` - Data analysis
- `esprima==4.0.1` - JavaScript parsing

### 2. Copy Model Files
Copy the pre-trained model files to the backend root:
```bash
cp malware_classifier.pkl SentinelFlow-BE/
cp malware_threshold.pkl SentinelFlow-BE/
```

These files should be at:
- `SentinelFlow-BE/malware_classifier.pkl`
- `SentinelFlow-BE/malware_threshold.pkl`

### 3. Start Backend
```bash
cd SentinelFlow-BE
python -m uvicorn app.main:app --reload
```

## Usage Examples

### Python (using requests)

```python
import requests

# Health check
response = requests.get(
    "http://localhost:8000/api/v1/scan/health",
    headers={"Authorization": "Bearer <your-token>"}
)
print(response.json())

# Scan a single file
with open("my_package.whl", "rb") as f:
    response = requests.post(
        "http://localhost:8000/api/v1/scan/dependency",
        files={"file": f},
        headers={"Authorization": "Bearer <your-token>"}
    )
    result = response.json()
    
    if result["success"]:
        prediction = result["prediction"]
        print(f"Classification: {prediction['classification']}")
        print(f"Risk Level: {prediction['risk_level']}")
        print(f"Confidence: {prediction['confidence']:.2%}")

# Batch scan
files = [
    ("files", open("package1.whl", "rb")),
    ("files", open("package2.whl", "rb")),
    ("files", open("package3.whl", "rb")),
]
response = requests.post(
    "http://localhost:8000/api/v1/scan/batch",
    files=files,
    headers={"Authorization": "Bearer <your-token>"}
)
results = response.json()
print(f"Malicious packages: {results['malicious_count']}")
```

### cURL

```bash
# Health check
curl -X GET http://localhost:8000/api/v1/scan/health \
  -H "Authorization: Bearer <your-token>"

# Scan single file
curl -X POST http://localhost:8000/api/v1/scan/dependency \
  -H "Authorization: Bearer <your-token>" \
  -F "file=@my_package.whl"

# Batch scan
curl -X POST http://localhost:8000/api/v1/scan/batch \
  -H "Authorization: Bearer <your-token>" \
  -F "files=@package1.whl" \
  -F "files=@package2.whl" \
  -F "files=@package3.whl"
```

## Implementation Details

### Feature Extraction Pipeline

1. **Archive Extraction**: Package is extracted to temporary directory
2. **File Discovery**: Locate all `.py` and `.js` files
3. **AST Parsing**: 
   - Python: Use Python's built-in `ast` module
   - JavaScript: Use `esprima` library
4. **Entropy Calculation**: Compute Shannon entropy for each file
5. **Feature Aggregation**: Sum counts across all files, compute statistics
6. **Feature Engineering**: Calculate derived features using mathematical formulas
7. **Normalization**: Prepare feature vector for model inference
8. **Prediction**: Pass to Random Forest model for classification

### Error Handling

- **Empty files**: Skipped, counts reset to 0
- **Parse errors**: Fallback to fast regex-based scan
- **Large files** (>1MB): Use fast regex scan instead of AST parsing
- **Invalid archives**: Return error with descriptive message
- **Missing model**: Service returns "unknown" classification with error details

### Performance Considerations

- **Timeout handling**: File processing is synchronous but handled within timeout
- **Memory management**: Uses temporary directories that are cleaned up automatically
- **Async operations**: File I/O is awaited in FastAPI async context
- **Batch limits**: Maximum 50 files per batch to prevent resource exhaustion

## Security

### Authentication
- All endpoints require Bearer token authentication
- Uses existing `get_current_user` dependency
- Token validation via JWT

### File Validation
- Maximum file size: 100MB
- Only ZIP, WHL, and TAR.GZ formats supported
- Archive extraction uses path traversal protection
- Temporary files cleaned up after processing

### Data Privacy
- Analysis is performed locally
- No files transmitted to external services
- Scan metadata stored per user

## Model Information

### Training Details
- **Algorithm**: Random Forest (scikit-learn)
- **Training samples**: ~5,000+ packages (benign + malicious)
- **Features**: 13 engineered features from AST + entropy
- **Performance**: 
  - High precision on malware detection
  - Calibrated probability estimates
  - Optimal threshold tuned for F1-score

### Model Files
- `malware_classifier.pkl`: Serialized Random Forest model
- `malware_threshold.pkl`: Optimal decision threshold (default 0.5)

## Troubleshooting

### Model not loading
- Check that model files exist in SentinelFlow-BE root directory
- Verify file permissions are readable
- Check error logs: `GET /api/v1/scan/health`

### Scan failures
- Check file format is supported (.zip, .whl, .tar.gz)
- Verify file is not corrupted: try extracting manually
- Check file size is under 100MB
- Review server logs for detailed error

### Authentication errors
- Verify Bearer token is valid and not expired
- Check token is included in Authorization header
- Confirm user exists and has access permissions

### Performance issues
- Reduce batch size (max 50 files)
- Check server disk space for temporary files
- Monitor memory usage during scans

## Future Enhancements

1. **GitHub Integration**: Direct scanning of repositories via GitHub API
2. **Caching**: Cache scan results for identical packages
3. **Threshold Tuning**: Per-ecosystem threshold customization
4. **Model Updates**: Automated model retraining pipeline
5. **Async Scanning**: Background job queue for large scans
6. **Detailed Reports**: HTML/PDF scan reports with findings
7. **Policy Enforcement**: Automated blocking of detected threats
8. **Analytics**: Scan statistics and trend analysis dashboard

## References

### Related Files
- Scanner Service: [app/services/scanner_service.py](app/services/scanner_service.py)
- Scanner Endpoint: [app/api/endpoints/scan.py](app/api/endpoints/scan.py)
- Data Models: [app/api/schemas/scanner.py](app/api/schemas/scanner.py)
- Main Application: [app/main.py](app/main.py)

### External Documentation
- FastAPI: https://fastapi.tiangolo.com/
- scikit-learn: https://scikit-learn.org/
- esprima: https://www.esprima.org/
