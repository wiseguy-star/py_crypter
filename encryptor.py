#!/usr/bin/env python3
"""
Modern Production-Ready Encryption Tool
=======================================

A secure, fast, and user-friendly encryption/decryption utility using industry-standard
cryptographic primitives. Supports multiple encryption modes and key derivation functions.

Features:
- AES-256-GCM encryption (AEAD - Authenticated Encryption with Associated Data)
- ChaCha20-Poly1305 encryption (modern alternative to AES)
- Argon2id key derivation (memory-hard, side-channel resistant)
- PBKDF2 key derivation (widely supported fallback)
- Secure random salt and nonce generation
- File and text encryption/decryption
- Progress bars for large files
- Zeroization of sensitive data
- Comprehensive error handling and logging
- CLI and programmatic interfaces

Requirements:
pip install cryptography argon2-cffi click tqdm
"""

import os
import sys
import json
import base64
import getpass
import logging
from pathlib import Path
from typing import Union, Optional, Tuple, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
import secrets
import hashlib
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from argon2 import PasswordHasher, Type
    from argon2.low_level import hash_secret_raw
    import click
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install cryptography argon2-cffi click tqdm")
    sys.exit(1)


class EncryptionMode(Enum):
    """Supported encryption algorithms."""
    AES_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"


class KDFMode(Enum):
    """Supported key derivation functions."""
    ARGON2ID = "argon2id"
    PBKDF2 = "pbkdf2"


@dataclass
class EncryptionMetadata:
    """Metadata for encrypted data."""
    version: str = "2.0"
    encryption_mode: str = EncryptionMode.AES_GCM.value
    kdf_mode: str = KDFMode.ARGON2ID.value
    salt: str = ""
    nonce: str = ""
    kdf_params: Dict[str, Any] = None
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.kdf_params is None:
            self.kdf_params = {}
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class ModernEncryptor:
    """
    Modern encryption utility with industry-standard security practices.
    """
    
    def __init__(self, 
                 encryption_mode: EncryptionMode = EncryptionMode.AES_GCM,
                 kdf_mode: KDFMode = KDFMode.ARGON2ID):
        self.encryption_mode = encryption_mode
        self.kdf_mode = kdf_mode
        self.logger = self._setup_logging()
        
        # Argon2 parameters (conservative but secure)
        self.argon2_params = {
            'time_cost': 3,      # iterations
            'memory_cost': 65536, # 64 MB
            'parallelism': 4,     # threads
            'hash_len': 32,       # key length
            'salt_len': 16,       # salt length
            'type': Type.ID       # Argon2id variant
        }
        
        # PBKDF2 parameters
        self.pbkdf2_params = {
            'iterations': 600000,  # OWASP recommended minimum
            'salt_len': 16,
            'key_len': 32
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('ModernEncryptor')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _secure_random(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return secrets.token_bytes(length)
    
    def _derive_key_argon2(self, password: str, salt: bytes, 
                          params: Dict[str, Any]) -> bytes:
        """Derive key using Argon2id."""
        try:
            return hash_secret_raw(
                secret=password.encode('utf-8'),
                salt=salt,
                time_cost=params['time_cost'],
                memory_cost=params['memory_cost'],
                parallelism=params['parallelism'],
                hash_len=params['hash_len'],
                type=params['type']
            )
        except Exception as e:
            raise CryptoError(f"Argon2 key derivation failed: {e}")
    
    def _derive_key_pbkdf2(self, password: str, salt: bytes,
                          params: Dict[str, Any]) -> bytes:
        """Derive key using PBKDF2-HMAC-SHA256."""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=params['key_len'],
                salt=salt,
                iterations=params['iterations'],
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise CryptoError(f"PBKDF2 key derivation failed: {e}")
    
    def _derive_key(self, password: str, salt: bytes, 
                   kdf_mode: KDFMode, params: Dict[str, Any]) -> bytes:
        """Derive encryption key from password."""
        if kdf_mode == KDFMode.ARGON2ID:
            return self._derive_key_argon2(password, salt, params)
        elif kdf_mode == KDFMode.PBKDF2:
            return self._derive_key_pbkdf2(password, salt, params)
        else:
            raise CryptoError(f"Unsupported KDF mode: {kdf_mode}")
    
    def _encrypt_aes_gcm(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Encrypt data using AES-256-GCM."""
        try:
            aesgcm = AESGCM(key)
            return aesgcm.encrypt(nonce, data, None)
        except Exception as e:
            raise CryptoError(f"AES-GCM encryption failed: {e}")
    
    def _decrypt_aes_gcm(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """Decrypt data using AES-256-GCM."""
        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise CryptoError(f"AES-GCM decryption failed: {e}")
    
    def _encrypt_chacha20_poly1305(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Encrypt data using ChaCha20-Poly1305."""
        try:
            chacha = ChaCha20Poly1305(key)
            return chacha.encrypt(nonce, data, None)
        except Exception as e:
            raise CryptoError(f"ChaCha20-Poly1305 encryption failed: {e}")
    
    def _decrypt_chacha20_poly1305(self, ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
        """Decrypt data using ChaCha20-Poly1305."""
        try:
            chacha = ChaCha20Poly1305(key)
            return chacha.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise CryptoError(f"ChaCha20-Poly1305 decryption failed: {e}")
    
    def _make_serializable_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert parameters to JSON-serializable format."""
        serializable_params = params.copy()
        
        # Convert Argon2 Type enum to string for JSON serialization
        if 'type' in serializable_params:
            if serializable_params['type'] == Type.ID:
                serializable_params['type'] = 'argon2id'
            elif serializable_params['type'] == Type.I:
                serializable_params['type'] = 'argon2i'
            elif serializable_params['type'] == Type.D:
                serializable_params['type'] = 'argon2d'
        
        return serializable_params
    
    def _restore_params_from_serialized(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Restore parameters from JSON-serialized format."""
        restored_params = params.copy()
        
        # Convert string back to Argon2 Type enum
        if 'type' in restored_params:
            if restored_params['type'] == 'argon2id':
                restored_params['type'] = Type.ID
            elif restored_params['type'] == 'argon2i':
                restored_params['type'] = Type.I
            elif restored_params['type'] == 'argon2d':
                restored_params['type'] = Type.D
        
        return restored_params
    
    def encrypt_data(self, data: bytes, password: str) -> Tuple[bytes, EncryptionMetadata]:
        """
        Encrypt data with password-based encryption.
        
        Args:
            data: Raw data to encrypt
            password: Password for encryption
            
        Returns:
            Tuple of (encrypted_data, metadata)
        """
        # Generate salt and nonce
        if self.kdf_mode == KDFMode.ARGON2ID:
            salt = self._secure_random(self.argon2_params['salt_len'])
            kdf_params = self.argon2_params.copy()
        else:
            salt = self._secure_random(self.pbkdf2_params['salt_len'])
            kdf_params = self.pbkdf2_params.copy()
        
        # Generate nonce (12 bytes for GCM/ChaCha20-Poly1305)
        nonce = self._secure_random(12)
        
        # Derive encryption key
        key = self._derive_key(password, salt, self.kdf_mode, kdf_params)
        
        try:
            # Encrypt data
            if self.encryption_mode == EncryptionMode.AES_GCM:
                ciphertext = self._encrypt_aes_gcm(data, key, nonce)
            elif self.encryption_mode == EncryptionMode.CHACHA20_POLY1305:
                ciphertext = self._encrypt_chacha20_poly1305(data, key, nonce)
            else:
                raise CryptoError(f"Unsupported encryption mode: {self.encryption_mode}")
            
            # Create metadata with serializable parameters
            serializable_kdf_params = self._make_serializable_params(kdf_params)
            metadata = EncryptionMetadata(
                encryption_mode=self.encryption_mode.value,
                kdf_mode=self.kdf_mode.value,
                salt=base64.b64encode(salt).decode('ascii'),
                nonce=base64.b64encode(nonce).decode('ascii'),
                kdf_params=serializable_kdf_params
            )
            
            return ciphertext, metadata
            
        finally:
            # Zeroize sensitive data
            if 'key' in locals():
                key = b'\x00' * len(key)
    
    def decrypt_data(self, ciphertext: bytes, password: str, 
                    metadata: EncryptionMetadata) -> bytes:
        """
        Decrypt data with password-based encryption.
        
        Args:
            ciphertext: Encrypted data
            password: Password for decryption
            metadata: Encryption metadata
            
        Returns:
            Decrypted data
        """
        try:
            # Decode salt and nonce
            salt = base64.b64decode(metadata.salt.encode('ascii'))
            nonce = base64.b64decode(metadata.nonce.encode('ascii'))
            
            # Restore parameters from serialized format
            restored_kdf_params = self._restore_params_from_serialized(metadata.kdf_params)
            
            # Derive decryption key
            kdf_mode = KDFMode(metadata.kdf_mode)
            key = self._derive_key(password, salt, kdf_mode, restored_kdf_params)
            
            # Decrypt data
            encryption_mode = EncryptionMode(metadata.encryption_mode)
            if encryption_mode == EncryptionMode.AES_GCM:
                plaintext = self._decrypt_aes_gcm(ciphertext, key, nonce)
            elif encryption_mode == EncryptionMode.CHACHA20_POLY1305:
                plaintext = self._decrypt_chacha20_poly1305(ciphertext, key, nonce)
            else:
                raise CryptoError(f"Unsupported encryption mode: {encryption_mode}")
            
            return plaintext
            
        finally:
            # Zeroize sensitive data
            if 'key' in locals():
                key = b'\x00' * len(key)
    
    def encrypt_file(self, input_path: Union[str, Path], 
                    output_path: Union[str, Path], password: str,
                    show_progress: bool = True) -> None:
        """
        Encrypt a file.
        
        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            password: Password for encryption
            show_progress: Show progress bar for large files
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        file_size = input_path.stat().st_size
        self.logger.info(f"Encrypting file: {input_path} ({file_size:,} bytes)")
        
        # Read file data
        with open(input_path, 'rb') as f:
            if show_progress and file_size > 1024 * 1024:  # Show progress for files > 1MB
                data = b''
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="Reading") as pbar:
                    while chunk := f.read(8192):
                        data += chunk
                        pbar.update(len(chunk))
            else:
                data = f.read()
        
        # Encrypt data
        ciphertext, metadata = self.encrypt_data(data, password)
        
        # Create output structure
        output_data = {
            'metadata': asdict(metadata),
            'ciphertext': base64.b64encode(ciphertext).decode('ascii')
        }
        
        # Write encrypted file
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        
        self.logger.info(f"File encrypted successfully: {output_path}")
    
    def decrypt_file(self, input_path: Union[str, Path], 
                    output_path: Union[str, Path], password: str,
                    show_progress: bool = True) -> None:
        """
        Decrypt a file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to output decrypted file
            password: Password for decryption
            show_progress: Show progress bar for large files
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
        
        # Read encrypted file
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        # Parse metadata and ciphertext
        metadata = EncryptionMetadata(**data['metadata'])
        ciphertext = base64.b64decode(data['ciphertext'].encode('ascii'))
        
        self.logger.info(f"Decrypting file: {input_path}")
        
        # Decrypt data
        plaintext = self.decrypt_data(ciphertext, password, metadata)
        
        # Write decrypted file
        file_size = len(plaintext)
        with open(output_path, 'wb') as f:
            if show_progress and file_size > 1024 * 1024:  # Show progress for files > 1MB
                with tqdm(total=file_size, unit='B', unit_scale=True, desc="Writing") as pbar:
                    pos = 0
                    while pos < file_size:
                        chunk_size = min(8192, file_size - pos)
                        f.write(plaintext[pos:pos + chunk_size])
                        pos += chunk_size
                        pbar.update(chunk_size)
            else:
                f.write(plaintext)
        
        self.logger.info(f"File decrypted successfully: {output_path}")
    
    def encrypt_text(self, text: str, password: str) -> str:
        """
        Encrypt text and return base64-encoded result.
        
        Args:
            text: Text to encrypt
            password: Password for encryption
            
        Returns:
            Base64-encoded encrypted data with metadata
        """
        data = text.encode('utf-8')
        ciphertext, metadata = self.encrypt_data(data, password)
        
        output_data = {
            'metadata': asdict(metadata),
            'ciphertext': base64.b64encode(ciphertext).decode('ascii')
        }
        
        return base64.b64encode(json.dumps(output_data).encode('utf-8')).decode('ascii')
    
    def decrypt_text(self, encrypted_text: str, password: str) -> str:
        """
        Decrypt base64-encoded encrypted text.
        
        Args:
            encrypted_text: Base64-encoded encrypted data
            password: Password for decryption
            
        Returns:
            Decrypted text
        """
        try:
            # Decode base64 and parse JSON
            json_data = base64.b64decode(encrypted_text.encode('ascii')).decode('utf-8')
            data = json.loads(json_data)
            
            # Parse metadata and ciphertext
            metadata = EncryptionMetadata(**data['metadata'])
            ciphertext = base64.b64decode(data['ciphertext'].encode('ascii'))
            
            # Decrypt and return text
            plaintext = self.decrypt_data(ciphertext, password, metadata)
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise CryptoError(f"Text decryption failed: {e}")


# CLI Interface
@click.group()
@click.option('--encryption-mode', '-e', 
              type=click.Choice(['aes-256-gcm', 'chacha20-poly1305']),
              default='aes-256-gcm', help='Encryption algorithm')
@click.option('--kdf-mode', '-k',
              type=click.Choice(['argon2id', 'pbkdf2']),
              default='argon2id', help='Key derivation function')
@click.pass_context
def cli(ctx, encryption_mode, kdf_mode):
    """Modern Production-Ready Encryption Tool"""
    ctx.ensure_object(dict)
    ctx.obj['encryptor'] = ModernEncryptor(
        EncryptionMode(encryption_mode),
        KDFMode(kdf_mode)
    )


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--password', '-p', prompt=True, hide_input=True,
              help='Password for encryption')
@click.pass_context
def encrypt_file(ctx, input_file, output_file, password):
    """Encrypt a file."""
    try:
        ctx.obj['encryptor'].encrypt_file(input_file, output_file, password)
        click.echo(f"✓ File encrypted: {output_file}")
    except Exception as e:
        click.echo(f"✗ Encryption failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_file', type=click.Path())
@click.option('--password', '-p', prompt=True, hide_input=True,
              help='Password for decryption')
@click.pass_context
def decrypt_file(ctx, input_file, output_file, password):
    """Decrypt a file."""
    try:
        ctx.obj['encryptor'].decrypt_file(input_file, output_file, password)
        click.echo(f"✓ File decrypted: {output_file}")
    except Exception as e:
        click.echo(f"✗ Decryption failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--password', '-p', prompt=True, hide_input=True,
              help='Password for encryption')
@click.pass_context
def encrypt_text(ctx, password):
    """Encrypt text from stdin."""
    try:
        text = click.get_text_stream('stdin').read().strip()
        if not text:
            click.echo("No input text provided", err=True)
            sys.exit(1)
        
        encrypted = ctx.obj['encryptor'].encrypt_text(text, password)
        click.echo(encrypted)
    except Exception as e:
        click.echo(f"✗ Encryption failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--password', '-p', prompt=True, hide_input=True,
              help='Password for decryption')
@click.pass_context
def decrypt_text(ctx, password):
    """Decrypt text from stdin."""
    try:
        encrypted_text = click.get_text_stream('stdin').read().strip()
        if not encrypted_text:
            click.echo("No encrypted text provided", err=True)
            sys.exit(1)
        
        decrypted = ctx.obj['encryptor'].decrypt_text(encrypted_text, password)
        click.echo(decrypted)
    except Exception as e:
        click.echo(f"✗ Decryption failed: {e}", err=True)
        sys.exit(1)


@cli.command()
def benchmark():
    """Run encryption benchmarks."""
    import timeit
    
    # Test data
    test_data = b"Hello, World! " * 1000  # ~13KB
    password = "test_password_123"
    
    modes = [
        (EncryptionMode.AES_GCM, KDFMode.ARGON2ID),
        (EncryptionMode.AES_GCM, KDFMode.PBKDF2),
        (EncryptionMode.CHACHA20_POLY1305, KDFMode.ARGON2ID),
        (EncryptionMode.CHACHA20_POLY1305, KDFMode.PBKDF2),
    ]
    
    click.echo("Running encryption benchmarks...")
    click.echo(f"Test data size: {len(test_data):,} bytes")
    click.echo("-" * 50)
    
    for enc_mode, kdf_mode in modes:
        encryptor = ModernEncryptor(enc_mode, kdf_mode)
        
        # Encryption benchmark
        def encrypt_test():
            return encryptor.encrypt_data(test_data, password)
        
        encrypt_time = timeit.timeit(encrypt_test, number=10) / 10
        
        # Get ciphertext for decryption test
        ciphertext, metadata = encrypt_test()
        
        # Decryption benchmark
        def decrypt_test():
            return encryptor.decrypt_data(ciphertext, password, metadata)
        
        decrypt_time = timeit.timeit(decrypt_test, number=10) / 10
        
        click.echo(f"{enc_mode.value} + {kdf_mode.value}:")
        click.echo(f"  Encrypt: {encrypt_time:.3f}s")
        click.echo(f"  Decrypt: {decrypt_time:.3f}s")
        click.echo()


if __name__ == '__main__':
    cli()