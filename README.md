# pycrypt



# Modern Production-Ready Encryption Tool

A secure, fast, and professional-grade encryption/decryption utility built with industry-standard cryptographic primitives. This tool is designed to meet the security requirements of modern applications and provides both CLI and programmatic interfaces.

## 🔒 Security Features

### Encryption Algorithms
- **AES-256-GCM**: Industry-standard authenticated encryption (default)
- **ChaCha20-Poly1305**: Modern stream cipher with authentication (Google's choice)

### Key Derivation Functions
- **Argon2id**: Memory-hard, side-channel resistant (default, winner of password hashing competition)
- **PBKDF2-HMAC-SHA256**: Widely supported fallback (600,000+ iterations)

### Security Guarantees
- **Authenticated Encryption**: Prevents tampering and ensures integrity
- **Secure Random Generation**: Uses OS-provided CSPRNG
- **Memory-Hard KDF**: Resistant to GPU/ASIC attacks
- **Constant-Time Operations**: Prevents timing attacks
- **Secure Memory Handling**: Automatic zeroization of sensitive data
- **Forward Secrecy**: Each encryption uses unique salt/nonce

## 🚀 Installation

```bash
# Install required dependencies
pip install cryptography argon2-cffi click tqdm

# Download the tool
curl -O view-source:https://gitlab.com/mubashir2005/pycrypt/-/blob/main/encryptor.py?ref_type=heads
chmod +x encryptor.py
```

## 📋 Quick Start

### Command Line Usage

```bash
# Encrypt a file (interactive password prompt)
python encryptor.py encrypt-file document.pdf document.pdf.enc

# Decrypt a file
python encryptor.py decrypt-file document.pdf.enc document_decrypted.pdf

# Encrypt text (pipe input)
echo "Secret message" | python encryptor.py encrypt-text

# Decrypt text
echo "base64_encrypted_data" | python encryptor.py decrypt-text

# Use different algorithms
python encryptor.py -e chacha20-poly1305 -k pbkdf2 encrypt-file data.txt data.enc

# Run benchmarks
python  encryptor.py benchmark
```

### Programmatic Usage

```python
from modern_encryptor import ModernEncryptor, EncryptionMode, KDFMode

# Initialize encryptor
encryptor = ModernEncryptor(
    encryption_mode=EncryptionMode.AES_GCM,
    kdf_mode=KDFMode.ARGON2ID
)

# Encrypt data
data = b"Sensitive information"
password = "strong_password_123"
ciphertext, metadata = encryptor.encrypt_data(data, password)

# Decrypt data
plaintext = encryptor.decrypt_data(ciphertext, password, metadata)

# File operations
encryptor.encrypt_file("document.pdf", "document.enc", password)
encryptor.decrypt_file("document.enc", "document_restored.pdf", password)

# Text operations
encrypted_text = encryptor.encrypt_text("Hello, World!", password)
decrypted_text = encryptor.decrypt_text(encrypted_text, password)
```

## 🛠 Security Utilities

The tool includes additional security utilities for comprehensive cryptographic operations:

```bash
# Generate secure passwords
python security_utilities.py genpass --length 32 --count 5

# Check password strength
python security_utilities.py checkpass

# Generate Ed25519 signing keys
python security_utilities.py genkey --type ed25519 --output keys.json

# Generate X25519 key exchange keys
python security_utilities.py genkey --type x25519 --output exchange_keys.json

# Sign a message
python security_utilities.py sign "Important message" --key-file keys.json

# Verify signature
python security_utilities.py verify "Important message" "signature_base64" --key-file keys.json

# Securely delete files
python security_utilities.py secure-delete sensitive_file.txt

# Analyze file entropy
python security_utilities.py entropy encrypted_file.bin

# Generate cryptographic salts
python security_utilities.py gensalt --length 32 --format hex
```

## 🏗 Architecture

### Encryption Process
1. **Salt Generation**: Cryptographically secure random salt
2. **Key Derivation**: Argon2id/PBKDF2 with security parameters
3. **Nonce Generation**: Unique nonce for each encryption
4. **Encryption**: AES-GCM/ChaCha20-Poly1305 with authentication
5. **Metadata Storage**: Algorithm details and parameters

### File Format
Encrypted files use JSON structure:
```json
{
  "metadata": {
    "version": "2.0",
    "encryption_mode": "aes-256-gcm",
    "kdf_mode": "argon2id",
    "salt": "base64_encoded_salt",
    "nonce": "base64_encoded_nonce",
    "kdf_params": { "time_cost": 3, "memory_cost": 65536, ... },
    "timestamp": 1672531200.0
  },
  "ciphertext": "base64_encoded_encrypted_data"
}
```

## ⚡ Performance

### Benchmark Results (typical)
```
Test data size: 13,000 bytes
--------------------------------------------------
aes-256-gcm + argon2id:
  Encrypt: 0.045s
  Decrypt: 0.023s

aes-256-gcm + pbkdf2:
  Encrypt: 0.234s
  Decrypt: 0.221s

chacha20-poly1305 + argon2id:
  Encrypt: 0.047s
  Decrypt: 0.024s

chacha20-poly1305 + pbkdf2:
  Encrypt: 0.236s
  Decrypt: 0.223s
```

### Scalability
- **Small files** (< 1MB): Instant encryption/decryption
- **Medium files** (1-100MB): Progress bars, streaming processing
- **Large files** (> 100MB): Chunked processing with progress indication
- **Memory usage**: Constant regardless of file size

## 🔧 Configuration

### Argon2id Parameters (Default)
```python
argon2_params = {
    'time_cost': 3,        # iterations
    'memory_cost': 65536,  # 64 MB memory usage
    'parallelism': 4,      # 4 threads
    'hash_len': 32,        # 256-bit key
    'salt_len': 16,        # 128-bit salt
    'type': Type.ID        # Argon2id variant
}
```

### PBKDF2 Parameters
```python
pbkdf2_params = {
    'iterations': 600000,  # OWASP recommended minimum
    'salt_len': 16,        # 128-bit salt
    'key_len': 32          # 256-bit key
}
```

## 🔐 Security Considerations

### Password Requirements
- **Minimum length**: 12 characters recommended
- **Character diversity**: Use uppercase, lowercase, numbers, symbols
- **Avoid patterns**: No common sequences or dictionary words
- **Unique passwords**: Different password for each encrypted item

### Operational Security
- **Secure environments**: Run on trusted systems
- **Memory protection**: Tool automatically zeros sensitive data
- **File permissions**: Restrict access to encrypted files
- **Backup strategy**: Store encrypted backups in multiple locations
- **Key management**: Consider using dedicated password managers

### Threat Model
This tool provides protection against:
- **Data breaches**: Encrypted data is useless without passwords
- **Offline attacks**: Memory-hard KDF resists GPU/ASIC cracking
- **Tampering**: Authenticated encryption detects modifications
- **Side-channel attacks**: Constant-time implementations

### Limitations
- **Password security**: Tool security depends on password strength
- **Implementation security**: Based on well-audited libraries
- **Physical security**: Cannot protect against hardware keyloggers
- **Social engineering**: Cannot protect against password disclosure

## 🧪 Testing

### Unit Tests
```bash
# Run comprehensive test suite
python -m pytest tests/ -v

# Test specific components
python -m pytest tests/test_encryption.py -v
python -m pytest tests/test_key_derivation.py -v
```
## 📚 Advanced Usage

### Custom Encryption Parameters
```python
# High-security configuration for sensitive data
encryptor = ModernEncryptor()
encryptor.argon2_params.update({
    'time_cost': 10,        # More iterations
    'memory_cost': 262144,  # 256 MB memory
    'parallelism': 8        # More threads
})

# Fast configuration for less sensitive data
encryptor.argon2_params.update({
    'time_cost': 2,
    'memory_cost': 32768,   # 32 MB memory
    'parallelism': 2
})
```

### Digital Signatures
```python
from security_utilities import SecureKeyManager

key_manager = SecureKeyManager()

# Generate signing keypair
private_key, public_key = key_manager.generate_keypair_ed25519()

# Sign a message
message = b"Important document"
signature = key_manager.sign_message(message, private_key)

# Verify signature
is_valid = key_manager.verify_signature(message, signature, public_key)
```

### Key Exchange
```python
# Alice generates keypair
alice_private, alice_public = key_manager.generate_keypair_x25519()

# Bob generates keypair  
bob_private, bob_public = key_manager.generate_keypair_x25519()

# Both parties derive same shared secret
alice_shared = key_manager.perform_key_exchange(alice_private, bob_public)
bob_shared = key_manager.perform_key_exchange(bob_private, alice_public)

# Derive encryption key from shared secret
encryption_key = key_manager.derive_key_from_shared_secret(alice_shared)
```

## 🤝 Contributing

### Development Setup
```bash
git clone https://gitlab.com/mubashir2005/pycrypt
cd modern-encryptor
pip install -e ".[dev]"
pre-commit install
```

### Code Standards
- **PEP 8** compliance
- **Type hints** for all functions
- **Comprehensive docstrings**
- **Unit tests** for new features
- **Security review** for cryptographic changes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty. While built using industry-standard cryptographic libraries and best practices, users should evaluate the tool's suitability for their specific security requirements. The authors are not responsible for any data loss or security breaches.

## 🙏 Acknowledgments

- **PyCA Cryptography**: Robust cryptographic primitives
- **Argon2**: Password hashing competition winner
- **OWASP**: Security guidelines and recommendations
- **RFC 7539**: ChaCha20-Poly1305 specification
- **NIST**: AES and cryptographic standards