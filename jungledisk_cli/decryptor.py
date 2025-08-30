"""JungleDisk file decryption module.

- Uses EVP_BytesToKey for key derivation
- Uses AES-CTR mode for file encryption
- 0.key file contains the actual encryption keys
"""

import os
import logging
import hashlib
import struct
from typing import Optional, Dict, Any, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import xml.etree.ElementTree as ET
import base64

logger = logging.getLogger(__name__)


class JungleDiskDecryptor:
    """Handles decryption of JungleDisk encrypted files."""
    
    def __init__(self, password: str = None):
        """Initialize the decryptor.
        
        Args:
            password: Master password for key decryption
        """
        self.password = password
        self.encryption_key = None
        self.decryption_keys = {}
        self.filename_key = None
        self.key_loaded = False
        
    def evp_bytes_to_key(self, salt: bytes, data: bytes, count: int, key_len: int = 32, iv_len: int = 16) -> Tuple[bytes, bytes]:
        """This is the key derivation function used by JungleDisk.
        
        Args:
            salt: Salt bytes (empty for JungleDisk)
            data: Data to derive key from (password + salt_hex)
            count: Number of iterations (1 for JungleDisk)
            key_len: Desired key length in bytes (32 for AES-256)
            iv_len: Desired IV length in bytes (16 for AES)
            
        Returns:
            Tuple of (key, iv)
        """
        m = []
        i = 0
        
        while len(b''.join(m)) < key_len + iv_len:
            md = hashlib.md5()
            if i > 0:
                md.update(m[i-1])
            md.update(data)
            md.update(salt)
            m.append(md.digest())
            i += 1
        
        ms = b''.join(m)
        return ms[:key_len], ms[key_len:key_len + iv_len]
        
    def load_key_file(self, key_file_content: bytes, metadata: Dict[str, str] = None) -> bool:
        """Load and decrypt the 0.key file.
        
        Args:
            key_file_content: Raw content of the 0.key file
            metadata: S3 metadata containing encryption info
            
        Returns:
            True if keys loaded successfully
        """
        if not self.password:
            logger.error("No password provided for key decryption")
            return False
            
        try:
            # Check if the file is encrypted
            if metadata and 'crypt' in metadata:
                # File is encrypted, decrypt it first
                logger.info(f"0.key is encrypted with method: {metadata.get('crypt')}")
                decrypted_content = self._decrypt_key_file(key_file_content, metadata)
                if not decrypted_content:
                    logger.error("Failed to decrypt 0.key file")
                    return False
                key_file_content = decrypted_content
                
            # Parse the XML keyfile
            self._parse_key_xml(key_file_content)
            self.key_loaded = True
            logger.info("Key file loaded and decrypted successfully")
            return True
                
        except Exception as e:
            logger.error(f"Failed to load key file: {e}")
            return False
            
    def _decrypt_key_file(self, encrypted_data: bytes, metadata: Dict[str, str]) -> Optional[bytes]:
        """Decrypt the 0.key file using the password and metadata.
        
        - Uses EVP_BytesToKey for key derivation
        - Uses AES-256 in CTR mode
        - Key = EVP_BytesToKey(password + salt_hex)
        - IV = MD5(salt_hex_string)
        
        Args:
            encrypted_data: Encrypted 0.key file content
            metadata: Metadata containing crypt info and salt
            
        Returns:
            Decrypted content or None
        """
        try:
            # Extract metadata
            crypt_info = metadata.get('crypt', '')
            salt_hex = metadata.get('crypt-salt', '')
            
            if not salt_hex:
                logger.error("No salt found in metadata")
                return None
                
            logger.debug(f"Crypt info: {crypt_info}")
            logger.debug(f"Salt hex: {salt_hex}")
            
            # According to C# source: keyString = EncryptionKey + KeySalt
            key_string = self.password + salt_hex
            logger.debug(f"Key string: password + salt_hex")
            
            # Derive 256-bit key using EVP_BytesToKey
            # C#: Crypto.EVP_BytesToKey(new byte[0], Encoding.Default.GetBytes(keyString), 1, keyBytes, new byte[0]);
            key, _ = self.evp_bytes_to_key(b'', key_string.encode(), 1, 32, 0)
            logger.debug(f"Derived key (256-bit): {key.hex()[:32]}...")
            
            # IV is MD5(salt_hex_string) as per C# code
            # C#: aes.IV = md5.ComputeHash(keySaltBytes);
            iv = hashlib.md5(salt_hex.encode()).digest()
            logger.debug(f"IV (MD5 of salt string): {iv.hex()}")
            
            # JungleDisk uses AES-CTR mode for encryption
            # Create CTR cipher with nonce from IV
            nonce = iv[:8]
            counter_value = struct.unpack('>Q', iv[8:])[0]
            
            cipher = Cipher(
                algorithms.AES(key),  # 256-bit key
                modes.CTR(nonce + struct.pack('>Q', counter_value)),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Validate it's XML
            if b'<keyfile' in decrypted[:50] or b'<?xml' in decrypted[:50]:
                logger.info("Successfully decrypted 0.key file")
                return decrypted
            else:
                logger.error("Decrypted data does not appear to be valid XML")
                logger.debug(f"First 100 bytes: {decrypted[:100]}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to decrypt key file: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
            
    def _parse_key_xml(self, xml_content: bytes):
        """Parse the decrypted key file XML.
        
        Args:
            xml_content: Decrypted XML content
        """
        try:
            root = ET.fromstring(xml_content.decode('utf-8'))
            
            # Extract encryption settings
            encrypt_new = root.find('.//encryptnewfiles')
            if encrypt_new is not None:
                self.encrypt_new_files = encrypt_new.text == '1'
                logger.debug(f"Encrypt new files: {self.encrypt_new_files}")
                
            encrypt_fn = root.find('.//encryptfilenames')
            if encrypt_fn is not None:
                self.encrypt_filenames = encrypt_fn.text == '1'
                logger.debug(f"Encrypt filenames: {self.encrypt_filenames}")
            
            # Extract encryption key
            enc_key_elem = root.find('.//encryptionkey')
            if enc_key_elem is not None and enc_key_elem.text:
                # The key is stored as a Base64 string but used as-is for encryption
                # (not decoded) according to C# implementation
                self.encryption_key = enc_key_elem.text
                logger.debug(f"Loaded encryption key: {self.encryption_key[:10]}...")
                
            # Extract decryption keys
            for key_elem in root.findall('.//decryptionkeys/value'):
                if key_elem.text:
                    # Store keys as strings (not decoded) per C# implementation
                    key_id = str(len(self.decryption_keys) + 1)
                    self.decryption_keys[key_id] = key_elem.text
                    logger.debug(f"Loaded decryption key {key_id}: {key_elem.text[:10]}...")
                    
            # Extract filename encryption key if present
            filename_key_elem = root.find('.//filenameencryptionkey')
            if filename_key_elem is not None and filename_key_elem.text:
                self.filename_key = self._decode_jungledisk_base64(filename_key_elem.text)
                logger.debug(f"Loaded filename key: {len(self.filename_key)} bytes")
            elif self.encrypt_filenames and self.encryption_key:
                # If filename encryption is enabled but no separate key, derive it from encryption key
                # According to JungleDisk source: EVP_BytesToKey(new byte[0], Encoding.Default.GetBytes(encryptionKey), 1, keyBytes, new byte[0])
                # The encryptionKey is used as-is (not base64 decoded) for the derivation
                key_bytes, _ = self.evp_bytes_to_key(b'', self.encryption_key.encode(), 1, 32, 0)
                self.filename_key = key_bytes  # Store as bytes, not string
                logger.debug(f"Derived filename key from encryption key: {len(self.filename_key)} bytes")
                
        except Exception as e:
            logger.error(f"Failed to parse key XML: {e}")
            raise
            
    def _decode_jungledisk_base64(self, encoded: str) -> bytes:
        """Decode JungleDisk's custom base64 encoding.
        
        JungleDisk uses custom characters for base64:
        - '_' for padding
        - '[' for 62
        - ']' for 63
        
        Args:
            encoded: JungleDisk base64 encoded string
            
        Returns:
            Decoded bytes
        """
        # Replace custom characters with standard base64
        standard = encoded.replace('_', '=').replace('[', '+').replace(']', '/')
        return base64.b64decode(standard)
        
    def _encode_jungledisk_base64(self, data: bytes) -> str:
        """Encode to JungleDisk's custom base64 format.
        
        Args:
            data: Bytes to encode
            
        Returns:
            JungleDisk base64 encoded string
        """
        standard = base64.b64encode(data).decode('ascii')
        return standard.replace('=', '_').replace('+', '[').replace('/', ']')
            
    def decrypt_filename(self, encrypted_name: str, marker: str = None) -> Optional[str]:
        """Decrypt an encrypted filename.
        
        JungleDisk encrypts filenames using AES-256 CBC mode with the filename key.
        The IV is derived from the file/directory marker (UUID).
        
        Args:
            encrypted_name: Base64-encoded encrypted filename (using JungleDisk encoding)
            marker: The UUID marker of the file/directory (required for CBC mode)
            
        Returns:
            Decrypted filename or None if decryption fails
        """
        if not self.filename_key:
            logger.debug("No filename encryption key available")
            return None
            
        if not marker:
            logger.debug("No marker provided for filename decryption")
            return None
            
        try:
            # Remove any trailing underscores (used as markers, not padding)
            clean_name = encrypted_name.rstrip('_')
            
            # Replace JungleDisk chars with standard base64
            standard = clean_name.replace('[', '+').replace(']', '/')
            
            # Add proper padding if needed
            padding = (4 - len(standard) % 4) % 4
            standard = standard + '=' * padding
            
            # Decode base64
            encrypted_bytes = base64.b64decode(standard)
            
            # Derive IV from marker (based on JungleDisk source: IvecFromMarker)
            # Convert hex string marker to bytes for IV
            iv = bytes.fromhex(marker[:32])  # Use first 16 bytes (32 hex chars)
            
            # Decrypt using AES-256 CBC mode
            cipher = Cipher(
                algorithms.AES(self.filename_key[:32]),  # Use first 32 bytes for AES-256
                modes.CBC(iv),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_bytes) + decryptor.finalize()
            
            # Remove null bytes and any padding
            # JungleDisk uses null termination for strings
            result = decrypted.rstrip(b'\x00').decode('utf-8', errors='ignore')
            
            # Remove any remaining non-printable characters at the end
            while result and ord(result[-1]) < 32:
                result = result[:-1]
            
            return result
            
        except Exception as e:
            logger.debug(f"Failed to decrypt filename '{encrypted_name}' with marker '{marker}': {e}")
            return None
    
    def decrypt_file(self, encrypted_data: bytes, metadata: Dict[str, str] = None) -> Optional[bytes]:
        """Decrypt a JungleDisk encrypted file.
        
        Args:
            encrypted_data: Encrypted file content
            metadata: S3 metadata containing encryption info
            
        Returns:
            Decrypted content or None
        """
        if not self.key_loaded:
            logger.error("Keys not loaded. Call load_key_file first.")
            return None
            
        try:
            # For files, JungleDisk uses the encryption key from the keyfile
            # Get the key to use
            key_to_use = None
            
            if metadata and 'crypt' in metadata:
                # File has specific encryption metadata
                salt_hex = metadata.get('crypt-salt', '')
                
                # Try using the main encryption key
                if self.encryption_key:
                    key_to_use = self.encryption_key
                    logger.debug("Using main encryption key from keyfile")
            else:
                # No encryption metadata, file might not be encrypted
                logger.warning("File has no encryption metadata")
                return encrypted_data
                
            if not key_to_use:
                logger.error("No suitable decryption key found")
                return None
                
            # Derive actual AES key using EVP_BytesToKey
            # For files, keyString = encryptionKey + salt
            if isinstance(key_to_use, bytes):
                key_to_use = key_to_use.decode('utf-8', errors='replace')
                
            key_string = key_to_use + salt_hex
            key, _ = self.evp_bytes_to_key(b'', key_string.encode(), 1, 32, 0)
            
            # IV is MD5(salt)
            iv = hashlib.md5(salt_hex.encode()).digest()
            
            # Use AES-CTR mode
            nonce = iv[:8]
            counter_value = struct.unpack('>Q', iv[8:])[0]
            
            cipher = Cipher(
                algorithms.AES(key),
                modes.CTR(nonce + struct.pack('>Q', counter_value)),
                backend=default_backend()
            )
            
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
            
            logger.info("Successfully decrypted file")
            return decrypted
            
        except Exception as e:
            logger.error(f"Failed to decrypt file: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return None
