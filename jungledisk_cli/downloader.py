"""JungleDisk file downloader module."""

import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .s3_client import JungleDiskS3Client
from .parser import JungleDiskParser
from .decryptor import JungleDiskDecryptor
from .jungledisk_lister import JungleDiskLister
from .utils import normalize_name_for_comparison

logger = logging.getLogger(__name__)


class JungleDiskDownloader:
    """Downloads files from JungleDisk buckets."""
    
    def __init__(self, client: JungleDiskS3Client, parser: JungleDiskParser, 
                 lister: JungleDiskLister, password: str = None):
        """Initialize the downloader.
        
        Args:
            client: S3 client instance
            parser: Parser instance
            lister: Lister instance for directory traversal
            password: Optional password for decryption
        """
        self.client = client
        self.parser = parser
        self.lister = lister
        self.decryptor = None
        
        # Initialize decryptor if password provided
        if password:
            self._initialize_decryptor(password)
            
    def _initialize_decryptor(self, password: str):
        """Initialize the decryptor with the 0.key file.
        
        Args:
            password: Master password for decryption
        """
        try:
            # Look for 0.key file in each user directory
            prefix = ""
            response = self.client.s3_client.list_objects_v2(
                Bucket=self.client.bucket_name,
                Delimiter='/',
                MaxKeys=10
            )
            
            # Get user directories (top-level prefixes)
            for prefix_info in response.get('CommonPrefixes', []):
                user_prefix = prefix_info['Prefix'].rstrip('/')
                key_file_path = f"{user_prefix}/0.key"
                
                try:
                    logger.info(f"Looking for 0.key file at {key_file_path}")
                    key_content = self.client.download_object(key_file_path)
                    
                    if key_content:
                        # Get metadata for the key file
                        metadata = self.client.get_object_metadata(key_file_path)
                        
                        # Initialize decryptor
                        self.decryptor = JungleDiskDecryptor(password)
                        
                        # Load and decrypt the key file
                        logger.info(f"Found 0.key file at {key_file_path}, attempting to decrypt...")
                        if self.decryptor.load_key_file(key_content, metadata):
                            logger.info("Decryption keys loaded successfully")
                            return
                        else:
                            logger.warning("Failed to decrypt 0.key file - invalid password or parameters")
                            self.decryptor = None
                            
                except Exception as e:
                    logger.debug(f"No 0.key file at {key_file_path}: {e}")
                    continue
                    
            logger.warning("No 0.key file found or could not decrypt")
            
        except Exception as e:
            logger.error(f"Error initializing decryptor: {e}")
            
    def _is_encrypted(self, s3_key: str, metadata: Dict[str, str]) -> bool:
        """Check if a file is encrypted based on its metadata.
        
        Args:
            s3_key: S3 object key
            metadata: Object metadata
            
        Returns:
            True if encrypted
        """
        # Check for encryption metadata
        if 'crypt' in metadata:
            return True
            
        # Also check if the decryptor has encryption enabled
        if self.decryptor and self.decryptor.key_loaded:
            return self.decryptor.encrypt_new_files
            
        return False
            
    def should_download_file(self, local_path: str, remote_size: int = None, skip_existing: bool = True) -> bool:
        """Check if a file should be downloaded.
        
        Args:
            local_path: Local file path
            remote_size: Remote file size in bytes (optional)
            skip_existing: Whether to skip existing files
            
        Returns:
            True if file should be downloaded
        """
        if not skip_existing:
            return True
            
        if not os.path.exists(local_path):
            return True
            
        # If we have remote size, compare it
        if remote_size is not None:
            local_size = os.path.getsize(local_path)
            if local_size != remote_size:
                logger.debug(f"Size mismatch for {local_path}: local={local_size}, remote={remote_size}")
                return True
            else:
                logger.debug(f"Skipping existing file with matching size: {local_path}")
                return False
        
        # If no remote size, skip if file exists
        logger.debug(f"Skipping existing file: {local_path}")
        return False
    
    def download_file(self, remote_path: str, local_path: str, skip_existing: bool = True) -> bool:
        """Download a file from JungleDisk.
        
        According to JungleDisk documentation:
        - Pointer objects contain file metadata: /parent/marker/file/name/size/blocksize/attrs
        - File content is in: /FILES/marker/blockindex
        
        Args:
            remote_path: Path in JungleDisk (e.g., /helen/backups/file.txt)
            local_path: Local path to save the file
            skip_existing: Whether to skip existing files with matching size
            
        Returns:
            True if download successful
        """
        try:
            # Normalize paths
            remote_path = self.parser.parse_path(remote_path).rstrip('/')
            
            # Find the pointer key for this file
            pointer_key = self._resolve_file_s3_key(remote_path)
            
            if not pointer_key:
                logger.error(f"Could not find file: {remote_path}")
                return False
                
            logger.info(f"Found file pointer at: {pointer_key}")
            
            # Parse the pointer to extract marker and block info
            file_info = self._parse_pointer_key(pointer_key)
            if not file_info:
                logger.error(f"Could not parse pointer key: {pointer_key}")
                return False
                
            marker = file_info['marker']
            blocksize = file_info.get('blocksize', 0)
            total_size = file_info.get('size', 0)
            
            # Check if we should skip this file
            if skip_existing and not self.should_download_file(local_path, total_size, skip_existing):
                logger.info(f"Skipping existing file: {local_path}")
                return True  # Return True as it's not an error
            
            # Download actual file content from FILES/marker/blockindex
            file_content = self._download_file_blocks(marker, blocksize, total_size, pointer_key)
            
            if file_content is None:
                logger.error(f"Failed to download file content")
                return False
                
            # Get metadata for decryption
            metadata = {}
            if file_content and len(file_content) > 0:
                # First check if we downloaded from FILES/ location
                user_bucket = pointer_key.split('/')[0] if pointer_key else None
                file_key = f"{user_bucket}/FILES/{marker}/0" if user_bucket else f"FILES/{marker}/0"
                
                # Try to get metadata from the FILES object
                try:
                    file_metadata = self.client.get_object_metadata(file_key)
                    if file_metadata:
                        metadata = file_metadata
                        logger.debug(f"Using metadata from FILES object: {metadata}")
                except:
                    # If not from FILES, try the pointer
                    try:
                        pointer_metadata = self.client.get_object_metadata(pointer_key)
                        if pointer_metadata:
                            metadata = pointer_metadata
                            logger.debug(f"Using metadata from pointer: {metadata}")
                    except:
                        pass
                    
                # If no metadata and content is very small, it might be encrypted with master key
                if not metadata and len(file_content) <= 16:
                    logger.info("Small inline content, may use master encryption key directly")
                
            # Decrypt if necessary
            if self.decryptor and file_content:
                # Check if we should decrypt
                if metadata and 'crypt' in metadata:
                    # Has explicit encryption metadata
                    logger.info("Decrypting file with metadata...")
                    decrypted_content = self.decryptor.decrypt_file(file_content, metadata)
                    if decrypted_content:
                        file_content = decrypted_content
                    else:
                        logger.warning("Decryption failed, saving encrypted content")
                elif self.decryptor.key_loaded and self.decryptor.encrypt_new_files and len(file_content) == 16:
                    # Small inline content might be encrypted with master key
                    logger.info("Attempting to decrypt small inline content...")
                    # Try simple AES decryption with master key
                    decrypted_content = self._decrypt_inline_content(file_content)
                    if decrypted_content:
                        file_content = decrypted_content
                    
            # Create local directory if needed
            local_file = Path(local_path)
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(local_file, 'wb') as f:
                f.write(file_content)
                
            logger.info(f"File saved to: {local_path}")
            return True
            
        except Exception as e:
            logger.error(f"Download failed: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return False
            
    def _parse_pointer_key(self, pointer_key: str) -> Optional[Dict[str, Any]]:
        """Parse a pointer key to extract file information.
        
        Pointer format: username/parent_marker/marker/file/name/size/blocksize/attributes
        
        Args:
            pointer_key: S3 pointer key
            
        Returns:
            Dictionary with parsed information
        """
        parts = pointer_key.split('/')
        
        # Need at least: username/parent/marker/file/name/size
        if len(parts) < 6 or parts[3] != 'file':
            return None
            
        result = {
            'username': parts[0],
            'parent_marker': parts[1],
            'marker': parts[2],
            'name': parts[4],
            'size': int(parts[5]) if parts[5].isdigit() else 0
        }
        
        # Get blocksize if available (0 means single block)
        if len(parts) > 6 and parts[6].isdigit():
            result['blocksize'] = int(parts[6])
        else:
            result['blocksize'] = 0
            
        return result
        
    def _download_file_blocks(self, marker: str, blocksize: int, total_size: int, pointer_key: str = None) -> Optional[bytes]:
        """Download file content from FILES/marker/blockindex.
        
        Args:
            marker: File marker (UUID)
            blocksize: Size of each block (0 for single block)
            total_size: Total file size
            pointer_key: S3 key of the pointer object (for inline content)
            
        Returns:
            Complete file content or None
        """
        try:
            # Extract the user bucket from the pointer key
            # Pointer format: username/parent/marker/file/...
            user_bucket = pointer_key.split('/')[0] if pointer_key else None
            
            # First check if the file exists in user_bucket/FILES/
            file_key = f"{user_bucket}/FILES/{marker}/0" if user_bucket else f"FILES/{marker}/0"
            
            # Try to download from FILES/ location
            try:
                if blocksize == 0:
                    # Single block file
                    logger.info(f"Downloading single block from: {file_key}")
                    content = self.client.download_object(file_key)
                    if content:
                        return content
                else:
                    # Multi-block file
                    content_parts = []
                    block_index = 0
                    bytes_downloaded = 0
                    
                    while bytes_downloaded < total_size:
                        file_key = f"{user_bucket}/FILES/{marker}/{block_index}" if user_bucket else f"FILES/{marker}/{block_index}"
                        logger.info(f"Downloading block {block_index} from: {file_key}")
                        
                        block_content = self.client.download_object(file_key)
                        if not block_content:
                            break
                            
                        content_parts.append(block_content)
                        bytes_downloaded += len(block_content)
                        block_index += 1
                        
                    if content_parts:
                        return b''.join(content_parts)
            except Exception as e:
                logger.debug(f"Could not download from FILES/ location: {e}")
            
            # If FILES/ doesn't exist, the content might be inline in the pointer
            # (for very small files, JungleDisk sometimes stores content inline)
            if pointer_key:
                logger.info("File not found in FILES/, checking if content is inline in pointer")
                try:
                    # Download the pointer object itself
                    inline_content = self.client.download_object(pointer_key)
                    if inline_content:
                        logger.info(f"Found inline content in pointer ({len(inline_content)} bytes)")
                        return inline_content
                except Exception as e:
                    logger.debug(f"Could not get inline content from pointer: {e}")
            
            # If we still have no content and size is 0, return empty
            if total_size == 0:
                logger.info("File has size 0, returning empty content")
                return b''
            
            logger.warning("Could not retrieve file content from FILES/ or pointer")
            return None
                
        except Exception as e:
            logger.error(f"Error downloading file blocks: {e}")
            return None
            
    def _resolve_file_s3_key(self, remote_path: str) -> Optional[str]:
        """Resolve a logical path to its S3 pointer key.
        
        Args:
            remote_path: Logical path (e.g., /helen/file.txt)
            
        Returns:
            S3 pointer key or None if not found
        """
        # Remove leading slash
        path = remote_path.lstrip('/')
        parts = path.split('/')
        
        if len(parts) < 2:
            return None
            
        username = parts[0]
        
        # If it's a root file
        if len(parts) == 2:
            filename = parts[1]
            # Search in ROOT
            return self._find_file_in_directory(username, 'ROOT', filename)
        else:
            # It's in a subdirectory - need to resolve the path
            dir_path = '/'.join(parts[1:-1])
            filename = parts[-1]
            
            # Resolve directory UUID
            dir_uuid = self.lister._resolve_directory_uuid(username, dir_path)
            if dir_uuid:
                return self._find_file_in_directory(username, dir_uuid, filename)
                
        return None
        
    def _find_file_in_directory(self, username: str, parent_uuid: str, filename: str) -> Optional[str]:
        """Find a file's S3 key in a specific directory.
        
        Args:
            username: JungleDisk username
            parent_uuid: Parent directory UUID
            filename: Name of the file to find
            
        Returns:
            S3 key of the file or None
        """
        # List objects with the parent UUID prefix
        prefix = f"{username}/{parent_uuid}/"
        
        # Normalize the search filename for comparison
        normalized_filename = normalize_name_for_comparison(filename)
        
        try:
            response = self.client.s3_client.list_objects_v2(
                Bucket=self.client.bucket_name,
                Prefix=prefix,
                MaxKeys=1000
            )
            
            for obj in response.get('Contents', []):
                key = obj['Key']
                parsed = self.parser.parse_jungledisk_path(key)
                
                if parsed and parsed.get('name'):
                    # Normalize the found name for comparison
                    normalized_found_name = normalize_name_for_comparison(parsed['name'])
                    if normalized_found_name == normalized_filename and parsed['type'] == 'file':
                        return key
                    
        except Exception as e:
            logger.error(f"Error searching for file: {e}")
            
        return None
    
        
    def _decrypt_inline_content(self, content: bytes) -> Optional[bytes]:
        """Attempt to decrypt small inline content.
        
        For very small files, JungleDisk may store encrypted content directly
        in the pointer object without separate metadata.
        
        Args:
            content: Encrypted content (typically 16 bytes)
            
        Returns:
            Decrypted content or None
        """
        try:
            if not self.decryptor or not self.decryptor.encryption_key:
                return None
                
            # For 16-byte content, this might be an AES block
            # Try decrypting with the master key directly
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            import hashlib
            
            # Use the master encryption key
            key = self.decryptor.encryption_key
            if isinstance(key, bytes) and len(key) >= 16:
                # Try ECB mode for single block
                cipher = Cipher(
                    algorithms.AES(key[:16]),
                    modes.ECB(),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                decrypted = decryptor.update(content) + decryptor.finalize()
                
                # Check if it looks like valid data
                # For now, just return it
                logger.debug(f"Decrypted inline content: {decrypted.hex()}")
                return decrypted
                
        except Exception as e:
            logger.debug(f"Could not decrypt inline content: {e}")
            
        return None