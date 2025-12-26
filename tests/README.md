# Test Files for NeuralScan Security Scanner

This directory contains test files with **intentional security vulnerabilities** for testing the NeuralScan security scanner.

⚠️ **WARNING**: These files contain dangerous code patterns. **DO NOT** use any code from these files in production environments!

## Test Files

### 1. `sql_injection_test.py`
**Vulnerabilities**: SQL Injection attacks
- Direct string concatenation in SQL queries
- String formatting (`%s`, `.format()`, f-strings) in SQL
- Multiple database types (SQLite, MySQL)
- Various SQL operations (SELECT, UPDATE, DELETE, INSERT)

**Expected detections**: ~8 SQL injection vulnerabilities

### 2. `command_injection_test.py`
**Vulnerabilities**: Command Injection and OS Command Execution
- `os.system()` with user input
- `subprocess.call()` with `shell=True`
- `os.popen()` with concatenated commands
- Various system commands (ping, grep, wget, nmap, etc.)

**Expected detections**: ~12 command injection vulnerabilities

### 3. `path_traversal_test.py`
**Vulnerabilities**: Path Traversal, File Handling, and Deserialization
- Unsanitized file path operations
- Arbitrary file read/write/delete
- Insecure deserialization (pickle, YAML)
- `eval()` and `exec()` usage
- Zip slip vulnerability

**Expected detections**: ~15 file handling and deserialization vulnerabilities

### 4. `crypto_secrets_test.py`
**Vulnerabilities**: Cryptography and Secrets Management
- Weak hashing algorithms (MD5, SHA1)
- Weak encryption (DES, RC4)
- Hardcoded API keys and credentials
- Hardcoded database passwords
- Hardcoded private keys
- Insecure random number generation
- Disabled SSL verification
- Plain text password storage

**Expected detections**: ~20 cryptography and secrets vulnerabilities

## Usage

To test the scanner with these files:

1. Open NeuralScan application
2. Click "Run Scan" or navigate to "Scan Target"
3. Select one of the test files
4. Review the detected vulnerabilities in the Results view

## Expected Total Detections

Approximately **55+ vulnerabilities** across all test files, categorized as:
- SQL Injection
- Command Injection
- Path Traversal
- Insecure Deserialization
- Weak Cryptography
- Hardcoded Secrets
- Insecure Network Communication

## Security Notes

These files are designed to trigger security scanners and should:
- Never be deployed to production
- Never be executed with real user input
- Only be used for testing security scanning tools
- Be kept in isolated test environments

---

**Created for**: ShieldEye NeuralScan Security Scanner
**Purpose**: Testing and demonstration of vulnerability detection capabilities
