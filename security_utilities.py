#!/usr/bin/env python3
"""
Security Utilities and Key Management
====================================

Additional security utilities to complement the modern encryption tool:
- Secure key generation and management
- Password strength assessment
- Digital signatures (Ed25519)
- Key exchange (X25519)
- Secure deletion utilities
- Entropy analysis
"""

import os
import sys
import secrets
import hashlib
import getpass
import platform
from pathlib import Path
from typing import Optional, Tuple, List
import base64
import json
import re
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    import click
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Install with: pip install cryptography click")
    sys.exit(1)


@dataclass
class PasswordStrength:
    """Password strength assessment result."""
    score: int  # 0-100
    issues: List[str]
    suggestions: List[str]
    estimated_crack_time: str


class SecureKeyManager:
    """Secure key generation and management utilities."""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_password(self, length: int = 32, 
                         use_symbols: bool = True,
                         use_numbers: bool = True,
                         use_uppercase: bool = True,
                         use_lowercase: bool = True) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length: Password length
            use_symbols: Include symbols
            use_numbers: Include numbers
            use_uppercase: Include uppercase letters
            use_lowercase: Include lowercase letters
            
        Returns:
            Generated password
        """
        if not any([use_symbols, use_numbers, use_uppercase, use_lowercase]):
            raise ValueError("At least one character type must be enabled")
        
        chars = ""
        if use_lowercase:
            chars += "abcdefghijklmnopqrstuvwxyz"
        if use_uppercase:
            chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if use_numbers:
            chars += "0123456789"
        if use_symbols:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one character from each enabled type
        password = []
        if use_lowercase:
            password.append(secrets.choice("abcdefghijklmnopqrstuvwxyz"))
        if use_uppercase:
            password.append(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        if use_numbers:
            password.append(secrets.choice("0123456789"))
        if use_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill remaining length
        for _ in range(length - len(password)):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def assess_password_strength(self, password: str) -> PasswordStrength:
        """
        Assess password strength and provide recommendations.
        
        Args:
            password: Password to assess
            
        Returns:
            PasswordStrength object with score and recommendations
        """
        score = 0
        issues = []
        suggestions = []
        
        # Length check
        if len(password) < 8:
            issues.append("Password is too short")
            suggestions.append("Use at least 12 characters")
        elif len(password) < 12:
            issues.append("Password could be longer")
            suggestions.append("Consider using 16+ characters")
        else:
            score += 20
        
        # Character diversity
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        score += char_types * 15
        
        if not has_lower:
            suggestions.append("Include lowercase letters")
        if not has_upper:
            suggestions.append("Include uppercase letters")
        if not has_digit:
            suggestions.append("Include numbers")
        if not has_symbol:
            suggestions.append("Include symbols")
        
        # Common patterns check
        common_patterns = [
            r'123', r'abc', r'qwerty', r'password', r'admin',
            r'(\w)\1{2,}', r'\d{4,}'  # repeated chars, long numbers
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password.lower()):
                issues.append("Contains common patterns")
                suggestions.append("Avoid common patterns and sequences")
                score -= 10
                break
        
        # Entropy calculation (simplified)
        unique_chars = len(set(password))
        if unique_chars < len(password) * 0.7:
            issues.append("Too many repeated characters")
            suggestions.append("Use more diverse characters")
            score -= 5
        
        score = max(0, min(100, score))
        
        # Estimated crack time (very rough approximation)
        if score < 30:
            crack_time = "minutes to hours"
        elif score < 50:
            crack_time = "days to weeks"
        elif score < 70:
            crack_time = "months to years"
        elif score < 90:
            crack_time = "decades"
        else:
            crack_time = "centuries"
        
        return PasswordStrength(
            score=score,
            issues=issues,
            suggestions=suggestions,
            estimated_crack_time=crack_time
        )
    
    def generate_keypair_ed25519(self) -> Tuple[bytes, bytes]:
        """
        Generate Ed25519 signing keypair.
        
        Returns:
            Tuple of (private_key_bytes, public_key_bytes)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    def generate_keypair_x25519(self) -> Tuple[bytes, bytes]:
        """
        Generate X25519 key exchange keypair.
        
        Returns:
            Tuple of (private_key_bytes, public_key_bytes)
        """
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw
        )
        
        return private_bytes, public_bytes
    
    def sign_message(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign a message using Ed25519.
        
        Args:
            message: Message to sign
            private_key: Ed25519 private key bytes
            
        Returns:
            Signature bytes
        """
        key = Ed25519PrivateKey.from_private_bytes(private_key)
        return key.sign(message)
    
    def verify_signature(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify Ed25519 signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Ed25519 public key bytes
            
        Returns:
            True if signature is valid
        """
        try:
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, message)
            return True
        except Exception:
            return False
    
    def perform_key_exchange(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """
        Perform X25519 key exchange.
        
        Args:
            private_key: Our X25519 private key
            peer_public_key: Peer's X25519 public key
            
        Returns:
            Shared secret (32 bytes)
        """
        private = X25519PrivateKey.from_private_bytes(private_key)
        public = X25519PublicKey.from_public_bytes(peer_public_key)
        shared_key = private.exchange(public)
        return shared_key
    
    def derive_key_from_shared_secret(self, shared_secret: bytes, 
                                    info: bytes = b"", length: int = 32) -> bytes:
        """
        Derive key from shared secret using HKDF.
        
        Args:
            shared_secret: Shared secret from key exchange
            info: Optional context information
            length: Desired key length
            
        Returns:
            Derived key
        """
        hkdf = HKDF(
            algorithm=SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=self.backend
        )
        return hkdf.derive(shared_secret)


class SecureFileUtils:
    """Secure file handling utilities."""
    
    @staticmethod
    def secure_delete(file_path: Path, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting it multiple times.
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes
            
        Returns:
            True if successful
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return True
            
            file_size = file_path.stat().st_size
            
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    # Overwrite with random data
                    f.write(secrets.token_bytes(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Remove the file
            file_path.unlink()
            return True
            
        except Exception as e:
            print(f"Secure delete failed: {e}")
            return False
    
    @staticmethod
    def analyze_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Args:
            data: Data to analyze
            
        Returns:
            Entropy value (0-8 bits per byte)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """Generate cryptographically secure salt."""
        return secrets.token_bytes(length)
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        
        return result == 0


# CLI for security utilities
@click.group()
def security_cli():
    """Security utilities and key management tools."""
    pass


@security_cli.command()
@click.option('--length', '-l', default=32, help='Password length')
@click.option('--no-symbols', is_flag=True, help='Exclude symbols')
@click.option('--no-numbers', is_flag=True, help='Exclude numbers')
@click.option('--no-uppercase', is_flag=True, help='Exclude uppercase')
@click.option('--no-lowercase', is_flag=True, help='Exclude lowercase')
@click.option('--count', '-c', default=1, help='Number of passwords to generate')
def genpass(length, no_symbols, no_numbers, no_uppercase, no_lowercase, count):
    """Generate secure passwords."""
    key_manager = SecureKeyManager()
    
    for _ in range(count):
        password = key_manager.generate_password(
            length=length,
            use_symbols=not no_symbols,
            use_numbers=not no_numbers,
            use_uppercase=not no_uppercase,
            use_lowercase=not no_lowercase
        )
        click.echo(password)


@security_cli.command()
@click.option('--password', '-p', prompt=True, hide_input=True, help='Password to check')
def checkpass(password):
    """Assess password strength."""
    key_manager = SecureKeyManager()
    strength = key_manager.assess_password_strength(password)
    
    click.echo(f"Password Strength Score: {strength.score}/100")
    click.echo(f"Estimated crack time: {strength.estimated_crack_time}")
    
    if strength.issues:
        click.echo("\nIssues found:")
        for issue in strength.issues:
            click.echo(f"  • {issue}")
    
    if strength.suggestions:
        click.echo("\nSuggestions:")
        for suggestion in strength.suggestions:
            click.echo(f"  • {suggestion}")


@security_cli.command()
@click.option('--type', '-t', type=click.Choice(['ed25519', 'x25519']), 
              default='ed25519', help='Key type')
@click.option('--output', '-o', help='Output file (default: stdout)')
def genkey(type, output):
    """Generate cryptographic keypairs."""
    key_manager = SecureKeyManager()
    
    if type == 'ed25519':
        private_key, public_key = key_manager.generate_keypair_ed25519()
        key_type = "Ed25519 (Signing)"
    else:
        private_key, public_key = key_manager.generate_keypair_x25519()
        key_type = "X25519 (Key Exchange)"
    
    key_data = {
        'type': key_type,
        'private_key': base64.b64encode(private_key).decode('ascii'),
        'public_key': base64.b64encode(public_key).decode('ascii'),
        'generated_at': click.DateTime().convert(click.Context(security_cli), None, None)
    }
    
    result = json.dumps(key_data, indent=2)
    
    if output:
        with open(output, 'w') as f:
            f.write(result)
        click.echo(f"Keypair saved to {output}")
    else:
        click.echo(result)


@security_cli.command()
@click.argument('message')
@click.option('--key-file', '-k', required=True, help='Private key file')
@click.option('--output', '-o', help='Output signature file')
def sign(message, key_file, output):
    """Sign a message with Ed25519."""
    key_manager = SecureKeyManager()
    
    # Load private key
    with open(key_file, 'r') as f:
        key_data = json.load(f)
    
    if 'Ed25519' not in key_data['type']:
        click.echo("Error: Key file must contain Ed25519 signing key", err=True)
        sys.exit(1)
    
    private_key = base64.b64decode(key_data['private_key'])
    message_bytes = message.encode('utf-8')
    
    signature = key_manager.sign_message(message_bytes, private_key)
    signature_b64 = base64.b64encode(signature).decode('ascii')
    
    if output:
        with open(output, 'w') as f:
            f.write(signature_b64)
        click.echo(f"Signature saved to {output}")
    else:
        click.echo(signature_b64)


@security_cli.command()
@click.argument('message')
@click.argument('signature')
@click.option('--key-file', '-k', required=True, help='Public key file')
def verify(message, signature, key_file):
    """Verify a message signature."""
    key_manager = SecureKeyManager()
    
    # Load public key
    with open(key_file, 'r') as f:
        key_data = json.load(f)
    
    if 'Ed25519' not in key_data['type']:
        click.echo("Error: Key file must contain Ed25519 signing key", err=True)
        sys.exit(1)
    
    public_key = base64.b64decode(key_data['public_key'])
    message_bytes = message.encode('utf-8')
    signature_bytes = base64.b64decode(signature)
    
    is_valid = key_manager.verify_signature(message_bytes, signature_bytes, public_key)
    
    if is_valid:
        click.echo("✓ Signature is valid")
    else:
        click.echo("✗ Signature is invalid")
        sys.exit(1)


@security_cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--passes', '-p', default=3, help='Number of overwrite passes')
def secure_delete(file, passes):
    """Securely delete a file."""
    file_path = Path(file)
    
    if SecureFileUtils.secure_delete(file_path, passes):
        click.echo(f"✓ File securely deleted: {file}")
    else:
        click.echo(f"✗ Failed to securely delete: {file}")
        sys.exit(1)


@security_cli.command()
@click.argument('file', type=click.Path(exists=True))
def entropy(file):
    """Analyze entropy of a file."""
    with open(file, 'rb') as f:
        data = f.read()
    
    entropy_value = SecureFileUtils.analyze_entropy(data)
    file_size = len(data)
    
    click.echo(f"File: {file}")
    click.echo(f"Size: {file_size:,} bytes")
    click.echo(f"Entropy: {entropy_value:.4f} bits per byte")
    
    if entropy_value < 1.0:
        click.echo("⚠  Very low entropy - likely not encrypted/compressed")
    elif entropy_value < 6.0:
        click.echo("⚠  Low entropy - may contain patterns")
    elif entropy_value < 7.5:
        click.echo("ℹ  Medium entropy - reasonably random")
    else:
        click.echo("✓ High entropy - likely encrypted or compressed")


@security_cli.command()
@click.option('--length', '-l', default=32, help='Salt length in bytes')
@click.option('--count', '-c', default=1, help='Number of salts to generate')
@click.option('--format', '-f', type=click.Choice(['hex', 'base64']), 
              default='base64', help='Output format')
def gensalt(length, count, format):
    """Generate cryptographic salts."""
    for _ in range(count):
        salt = SecureFileUtils.generate_salt(length)
        
        if format == 'hex':
            click.echo(salt.hex())
        else:
            click.echo(base64.b64encode(salt).decode('ascii'))


if __name__ == '__main__':
    security_cli()
