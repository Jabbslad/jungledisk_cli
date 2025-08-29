"""Parser for JungleDisk file structure."""

import os
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from datetime import datetime
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class JungleDiskParser:
    """Parser for JungleDisk S3 bucket structure."""
    
    # Known metadata/system file patterns to exclude
    METADATA_PATTERNS = [
        'metadata/',
        'config/',
        '.key',
        'file_list',
        'directory_structure',
        'bucket_configuration.xml',
        '.json',
        'pointers/',
        'blocks/',
        'chunks/',
        'backups/',
        '.db',
        '.sqlite',
        '0.dir',  # Directory mapping file
        '0.key',  # Key file
    ]
    
    # Special JungleDisk directories to handle
    SPECIAL_DIRS = ['FILES', 'ROOT']
    
    def __init__(self):
        """Initialize the parser."""
        self.directory_cache = {}  # Cache for directory names
        
    def parse_jungledisk_path(self, key: str) -> Optional[Dict[str, Any]]:
        """Parse a JungleDisk S3 object key to extract file information.
        
        JungleDisk path format:
        username/parent_uuid/item_uuid/type/filename/size/...
        
        Args:
            key: S3 object key
            
        Returns:
            Dictionary with parsed information or None if not a valid file/dir
        """
        parts = key.split('/')
        
        # Need at least username/uuid/uuid/type
        if len(parts) < 4:
            return None
            
        username = parts[0]
        parent_uuid = parts[1]
        item_uuid = parts[2]
        item_type = parts[3]
        
        # Skip if this is just a UUID directory (no type specified)
        if item_type not in ['file', 'dir']:
            return None
            
        result = {
            'username': username,
            'parent_uuid': parent_uuid,
            'item_uuid': item_uuid,
            'type': item_type,
            'full_path': key
        }
        
        if item_type == 'file' and len(parts) > 4:
            # File entry: extract filename and metadata
            result['name'] = parts[4]
            result['is_dir'] = False
            
            # Extract size if available
            if len(parts) > 5:
                try:
                    result['size'] = int(parts[5])
                except (ValueError, IndexError):
                    result['size'] = 0
                    
            # Extract metadata from the last part if it exists
            if len(parts) > 6:
                metadata = parts[-1]
                # Parse metadata like: mode-33188-mtime-1243626912-ctime-1243626912-md5-de7289fa...
                if 'mtime-' in metadata:
                    match = re.search(r'mtime-(\d+)', metadata)
                    if match:
                        result['mtime'] = int(match.group(1))
                if 'md5-' in metadata:
                    match = re.search(r'md5-([a-f0-9]+)', metadata)
                    if match:
                        result['md5'] = match.group(1)
                        
        elif item_type == 'dir' and len(parts) > 4:
            # Directory entry
            result['name'] = parts[4] if parts[4] != 'Contents' else parent_uuid
            result['is_dir'] = True
            result['size'] = 0
            
        return result
        
    def is_metadata_file(self, key: str) -> bool:
        """Check if a key represents a metadata/system file.
        
        Args:
            key: S3 object key
            
        Returns:
            True if this is a metadata file, False otherwise
        """
        # Check for known metadata patterns
        for pattern in self.METADATA_PATTERNS:
            if pattern in key.lower():
                return True
                
        # Check for specific JungleDisk metadata files
        basename = os.path.basename(key)
        if basename in ['0.key', 'file_list.json', 'directory_structure.json']:
            return True
            
        # Check for UUID-based metadata files (like uuid.json)
        if basename.endswith('.json') and '-' in basename:
            return True
            
        return False
        
    def parse_path(self, path: str) -> str:
        """Normalize and parse a path for JungleDisk structure.
        
        Args:
            path: Input path
            
        Returns:
            Normalized path with trailing slash for directories
        """
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
            
        # Ensure directory paths end with /
        if path != '/' and not path.endswith('/'):
            path = path + '/'
            
        # Remove double slashes
        while '//' in path:
            path = path.replace('//', '/')
            
        return path
        
    def extract_logical_files(self, objects: List[Dict[str, Any]], 
                             prefix: str = '') -> List[Dict[str, Any]]:
        """Extract logical files from S3 object listing.
        
        Args:
            objects: List of S3 objects
            prefix: Current prefix being listed
            
        Returns:
            List of logical file information
        """
        logical_files = []
        seen_items = set()  # Track unique items
        
        for obj in objects:
            key = obj.get('Key', '')
            
            # Skip metadata files
            if self.is_metadata_file(key):
                continue
                
            # Skip if it's the prefix itself
            if key == prefix:
                continue
                
            # Try to parse as JungleDisk path
            parsed = self.parse_jungledisk_path(key)
            if parsed and parsed.get('name'):
                # Create unique identifier
                item_id = f"{parsed['parent_uuid']}/{parsed['name']}"
                
                # Skip duplicates
                if item_id in seen_items:
                    continue
                seen_items.add(item_id)
                
                # Build file info from parsed data
                file_info = {
                    'name': parsed['name'],
                    'path': key,
                    'size': parsed.get('size', 0),
                    'is_dir': parsed.get('is_dir', False),
                    'parent_uuid': parsed['parent_uuid'],
                    'item_uuid': parsed['item_uuid']
                }
                
                # Add modification time if available
                if 'mtime' in parsed:
                    try:
                        file_info['last_modified'] = datetime.fromtimestamp(parsed['mtime'])
                    except:
                        pass
                        
                # Add MD5 if available
                if 'md5' in parsed:
                    file_info['etag'] = parsed['md5']
                    
                logical_files.append(file_info)
            else:
                # Fall back to original extraction for non-JungleDisk paths
                file_info = self._extract_file_info(obj, prefix)
                if file_info:
                    logical_files.append(file_info)
                
        return logical_files
        
    def _extract_file_info(self, obj: Dict[str, Any], prefix: str) -> Optional[Dict[str, Any]]:
        """Extract file information from S3 object.
        
        Args:
            obj: S3 object dictionary
            prefix: Current prefix
            
        Returns:
            Dictionary with file information or None
        """
        key = obj.get('Key', '')
        
        # Get relative path from prefix
        if prefix and key.startswith(prefix):
            relative_path = key[len(prefix):]
        else:
            relative_path = key
            
        # Skip if it's in a subdirectory (for non-recursive listing)
        if '/' in relative_path.rstrip('/'):
            return None
            
        # Build file information
        file_info = {
            'name': os.path.basename(key.rstrip('/')),
            'path': key,
            'size': obj.get('Size', 0),
            'last_modified': obj.get('LastModified'),
            'etag': obj.get('ETag', '').strip('"'),
            'storage_class': obj.get('StorageClass', 'STANDARD')
        }
        
        # Format last modified time
        if file_info['last_modified']:
            if isinstance(file_info['last_modified'], datetime):
                file_info['last_modified'] = file_info['last_modified'].isoformat()
                
        return file_info
        
    def format_directory_entries(self, prefixes: List[str], prefix: str) -> List[Dict[str, Any]]:
        """Format directory entries from common prefixes.
        
        Args:
            prefixes: List of common prefixes (directories)
            prefix: Current prefix
            
        Returns:
            List of directory information
        """
        directories = []
        
        for p in prefixes:
            # Skip metadata directories
            if self.is_metadata_file(p):
                continue
                
            # Get directory name
            if prefix and p.startswith(prefix):
                relative_path = p[len(prefix):]
            else:
                relative_path = p
                
            dir_name = relative_path.rstrip('/').split('/')[-1]
            
            if dir_name:  # Skip empty names
                directories.append({
                    'name': dir_name + '/',
                    'path': p,
                    'type': 'directory',
                    'size': 0
                })
                
        return directories