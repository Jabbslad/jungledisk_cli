"""Specialized lister for JungleDisk directory structures."""

from typing import Dict, List, Any, Set, Optional
import logging
from collections import defaultdict
from .s3_client import JungleDiskS3Client
from .parser import JungleDiskParser
from .utils import normalize_name_for_comparison

logger = logging.getLogger(__name__)


class JungleDiskLister:
    """Handles listing operations for JungleDisk buckets with proper directory resolution."""
    
    def __init__(self, client: JungleDiskS3Client, parser: JungleDiskParser):
        """Initialize the lister.
        
        Args:
            client: JungleDisk S3 client instance
            parser: JungleDisk parser instance
        """
        self.client = client
        self.parser = parser
        self.directory_map = {}  # Cache for directory UUID to name mapping
        
    def list_path(self, path: str) -> Dict[str, Any]:
        """List files and directories at the specified path (non-recursive).
        
        This method handles the JungleDisk structure where files are stored with UUIDs
        but need to be displayed with their actual names.
        
        Args:
            path: Path to list (should end with / for directories)
            
        Returns:
            Dictionary containing files and directories at the path
        """
        # Normalize the path
        normalized_path = self.parser.parse_path(path)
        
        # For S3, we need to remove the leading / for non-root paths
        prefix = normalized_path.lstrip('/')
        
        logger.debug(f"Listing JungleDisk path: '{prefix}'")
        
        # JungleDisk structure:
        # - Items directly under a user (e.g., /helen/) are stored in username/ROOT/
        # - Subdirectories are stored with their parent's UUID
        
        # Check if we're listing a user root (e.g., helen/)
        parts = prefix.rstrip('/').split('/')
        if len(parts) == 1 and parts[0]:
            # This is a user root, list from ROOT directory
            return self._list_user_root(prefix)
        else:
            # This is a subdirectory path
            return self._list_subdirectory(prefix)
            
    def _list_user_root(self, prefix: str) -> Dict[str, Any]:
        """List the root directory of a user (e.g., /helen/).
        
        Items directly under a user are stored in username/ROOT/.
        """
        username = prefix.rstrip('/')
        root_prefix = f"{username}/ROOT/"
        
        # Get all objects in the ROOT directory
        response = self.client.s3_client.list_objects_v2(
            Bucket=self.client.bucket_name,
            Prefix=root_prefix,
            MaxKeys=1000
        )
        
        files = []
        directories = []
        seen_items = set()
        
        for obj in response.get('Contents', []):
            key = obj['Key']
            
            # Skip metadata files
            if self.parser.is_metadata_file(key):
                continue
            
            # Parse the path: username/ROOT/uuid/type/name/...
            parts = key.split('/')
            if len(parts) >= 5 and parts[1] == 'ROOT':
                item_uuid = parts[2]
                item_type = parts[3]
                item_name = parts[4]
                
                # Create unique identifier
                item_id = f"{item_uuid}/{item_name}"
                
                if item_id not in seen_items:
                    seen_items.add(item_id)
                    
                    if item_type == 'dir':
                        directories.append({
                            'name': item_name + '/',
                            'path': key,
                            'type': 'directory',
                            'size': 0,
                            'uuid': item_uuid
                        })
                    elif item_type == 'file':
                        file_info = {
                            'name': item_name,
                            'path': key,
                            'size': 0,
                            'uuid': item_uuid
                        }
                        
                        # Extract size if available
                        if len(parts) > 5:
                            try:
                                file_info['size'] = int(parts[5])
                            except ValueError:
                                pass
                        
                        # Extract mtime if available
                        if len(parts) > 6:
                            metadata = parts[-1]
                            if 'mtime-' in metadata:
                                import re
                                match = re.search(r'mtime-(\d+)', metadata)
                                if match:
                                    from datetime import datetime
                                    try:
                                        file_info['last_modified'] = datetime.fromtimestamp(int(match.group(1))).isoformat()
                                    except:
                                        pass
                        
                        files.append(file_info)
        
        return {
            'path': '/' + prefix,
            'files': sorted(files, key=lambda x: x['name']),
            'directories': sorted(directories, key=lambda x: x['name']),
            'total_objects': len(files) + len(directories)
        }
    
    def _list_subdirectory(self, prefix: str) -> Dict[str, Any]:
        """List a subdirectory path.
        
        This needs to find the UUID for the directory and list its contents.
        """
        # Parse the path to get username and directory path
        parts = prefix.rstrip('/').split('/')
        if len(parts) < 2:
            return {
                'path': '/' + prefix,
                'files': [],
                'directories': [],
                'total_objects': 0
            }
        
        username = parts[0]
        dir_path = '/'.join(parts[1:])
        
        # Find the UUID for this directory path
        dir_uuid = self._resolve_directory_uuid(username, dir_path)
        
        if not dir_uuid:
            logger.warning(f"Could not resolve UUID for directory: {dir_path}")
            return {
                'path': '/' + prefix,
                'files': [],
                'directories': [],
                'total_objects': 0
            }
        
        # List contents of this UUID directory
        return self._list_directory_by_uuid(username, dir_uuid, prefix)
    
    def _resolve_directory_uuid(self, username: str, dir_path: str) -> Optional[str]:
        """Resolve a directory path to its UUID.
        
        Args:
            username: Username (e.g., 'helen')
            dir_path: Directory path relative to user root (e.g., 'backups')
            
        Returns:
            UUID of the directory or None if not found
        """
        # Start from ROOT to find the directory
        path_parts = dir_path.split('/')
        current_prefix = f"{username}/ROOT/"
        current_uuid = None
        
        for part_name in path_parts:
            if not part_name:
                continue
                
            # Search for this directory name in the current location
            response = self.client.s3_client.list_objects_v2(
                Bucket=self.client.bucket_name,
                Prefix=current_prefix,
                MaxKeys=1000
            )
            
            found = False
            for obj in response.get('Contents', []):
                key = obj['Key']
                parts = key.split('/')
                
                # Check if this is a directory entry with matching name
                if len(parts) >= 5:
                    item_type = parts[3]
                    item_name = parts[4]
                    
                    # Normalize names for comparison (handle smart quotes and other variations)
                    normalized_item_name = normalize_name_for_comparison(item_name)
                    normalized_part_name = normalize_name_for_comparison(part_name)
                    
                    if item_type == 'dir' and normalized_item_name == normalized_part_name:
                        # Found the directory, get its UUID
                        current_uuid = parts[2]
                        # Update prefix for next level
                        current_prefix = f"{username}/{current_uuid}/"
                        found = True
                        break
            
            if not found:
                return None
        
        return current_uuid
    
    
    def _list_directory_by_uuid(self, username: str, dir_uuid: str, original_prefix: str) -> Dict[str, Any]:
        """List contents of a directory by its UUID.
        
        Args:
            username: Username
            dir_uuid: UUID of the directory
            original_prefix: Original path prefix for display
            
        Returns:
            Dictionary with files and directories
        """
        uuid_prefix = f"{username}/{dir_uuid}/"
        
        # Get all objects in this UUID directory
        response = self.client.s3_client.list_objects_v2(
            Bucket=self.client.bucket_name,
            Prefix=uuid_prefix,
            MaxKeys=1000
        )
        
        files = []
        directories = []
        seen_items = set()
        
        for obj in response.get('Contents', []):
            key = obj['Key']
            
            # Skip metadata files
            if self.parser.is_metadata_file(key):
                continue
            
            # Parse the path: username/parent_uuid/item_uuid/type/name/...
            parts = key.split('/')
            if len(parts) >= 5:
                parent_uuid = parts[1]
                item_uuid = parts[2]
                item_type = parts[3]
                item_name = parts[4]
                
                # Only include items that are direct children of this directory
                if parent_uuid == dir_uuid:
                    item_id = f"{item_uuid}/{item_name}"
                    
                    if item_id not in seen_items:
                        seen_items.add(item_id)
                        
                        if item_type == 'dir':
                            directories.append({
                                'name': item_name + '/',
                                'path': key,
                                'type': 'directory',
                                'size': 0,
                                'uuid': item_uuid
                            })
                        elif item_type == 'file':
                            file_info = {
                                'name': item_name,
                                'path': key,
                                'size': 0,
                                'uuid': item_uuid
                            }
                            
                            # Extract size if available
                            if len(parts) > 5:
                                try:
                                    file_info['size'] = int(parts[5])
                                except ValueError:
                                    pass
                            
                            # Extract mtime if available
                            if len(parts) > 6:
                                metadata = parts[-1]
                                if 'mtime-' in metadata:
                                    import re
                                    match = re.search(r'mtime-(\d+)', metadata)
                                    if match:
                                        from datetime import datetime
                                        try:
                                            file_info['last_modified'] = datetime.fromtimestamp(int(match.group(1))).isoformat()
                                        except:
                                            pass
                            
                            files.append(file_info)
        
        return {
            'path': '/' + original_prefix,
            'files': sorted(files, key=lambda x: x['name']),
            'directories': sorted(directories, key=lambda x: x['name']),
            'total_objects': len(files) + len(directories)
        }
    
    def _list_regular_path(self, prefix: str) -> Dict[str, Any]:
        """List a regular path with proper JungleDisk file resolution."""
        
        # For paths like helen/uuid/, we need to list contents of that specific UUID
        # For paths like helen/, we use delimiter to get direct children
        
        # Check if we're listing a UUID directory
        parts = prefix.rstrip('/').split('/')
        is_uuid_dir = len(parts) >= 2 and len(parts[-1]) == 32
        
        if is_uuid_dir:
            # We're inside a UUID directory, list its contents
            return self._list_uuid_directory_contents(prefix)
        else:
            # Use delimiter to get only direct children
            response = self.client.s3_client.list_objects_v2(
                Bucket=self.client.bucket_name,
                Prefix=prefix,
                Delimiter='/',
                MaxKeys=1000
            )
            
            directories = []
            files = []
            
            # Process common prefixes (directories)
            for prefix_info in response.get('CommonPrefixes', []):
                dir_path = prefix_info['Prefix']
                dir_name = dir_path.rstrip('/').split('/')[-1]
                
                # Skip metadata directories
                if dir_name in ['FILES', 'ROOT'] or self.parser.is_metadata_file(dir_name):
                    continue
                    
                # If it's a UUID, try to get the real name
                if len(dir_name) == 32:
                    real_name = self._get_directory_name(dir_path.rstrip('/'))
                    if real_name:
                        directories.append({
                            'name': real_name + '/',
                            'path': dir_path,
                            'type': 'directory',
                            'size': 0
                        })
                    else:
                        directories.append({
                            'name': dir_name + '/',
                            'path': dir_path,
                            'type': 'directory',
                            'size': 0
                        })
                else:
                    directories.append({
                        'name': dir_name + '/',
                        'path': dir_path,
                        'type': 'directory',
                        'size': 0
                    })
                    
            # Process direct files (if any)
            for obj in response.get('Contents', []):
                key = obj['Key']
                
                # Skip metadata files
                if self.parser.is_metadata_file(key):
                    continue
                    
                # Only include files directly in this prefix (no subdirectories)
                relative = key[len(prefix):] if key.startswith(prefix) else key
                if '/' not in relative:
                    files.append({
                        'name': relative,
                        'path': key,
                        'size': obj.get('Size', 0),
                        'last_modified': obj.get('LastModified', '').isoformat() if obj.get('LastModified') else None
                    })
                    
            return {
                'path': '/' + prefix if prefix else '/',
                'files': sorted(files, key=lambda x: x['name']),
                'directories': sorted(directories, key=lambda x: x['name']),
                'total_objects': len(files) + len(directories)
            }
    
    def _list_uuid_directory_contents(self, prefix: str) -> Dict[str, Any]:
        """List contents of a UUID directory, extracting real filenames."""
        
        # Get all objects in this UUID directory
        all_objects = []
        continuation_token = None
        
        while True:
            if continuation_token:
                response = self.client.s3_client.list_objects_v2(
                    Bucket=self.client.bucket_name,
                    Prefix=prefix,
                    ContinuationToken=continuation_token,
                    MaxKeys=1000
                )
            else:
                response = self.client.s3_client.list_objects_v2(
                    Bucket=self.client.bucket_name,
                    Prefix=prefix,
                    MaxKeys=1000
                )
                
            all_objects.extend(response.get('Contents', []))
            
            if not response.get('IsTruncated'):
                break
            continuation_token = response.get('NextContinuationToken')
            
        # Process objects to extract files and directories
        files = []
        directories = set()
        seen_items = set()
        
        for obj in all_objects:
            key = obj['Key']
            
            # Skip metadata files
            if self.parser.is_metadata_file(key):
                continue
                
            # Parse the JungleDisk path
            parsed = self.parser.parse_jungledisk_path(key)
            
            if parsed and parsed.get('name'):
                # Check if this item is directly in our UUID directory
                # Format: username/parent_uuid/item_uuid/type/name/...
                # We want items where parent_uuid matches our current UUID
                parts = prefix.rstrip('/').split('/')
                if len(parts) >= 2:
                    current_uuid = parts[-1]
                    if parsed['parent_uuid'] == current_uuid:
                        item_id = f"{parsed['item_uuid']}/{parsed['name']}"
                        
                        if item_id not in seen_items:
                            seen_items.add(item_id)
                            
                            if parsed['is_dir']:
                                directories.add(parsed['name'])
                            else:
                                file_info = {
                                    'name': parsed['name'],
                                    'path': key,
                                    'size': parsed.get('size', 0),
                                    'last_modified': None
                                }
                                
                                if 'mtime' in parsed:
                                    from datetime import datetime
                                    try:
                                        file_info['last_modified'] = datetime.fromtimestamp(parsed['mtime']).isoformat()
                                    except:
                                        pass
                                        
                                files.append(file_info)
                            
        # Convert directories set to list of dicts
        directory_list = [{'name': d + '/', 'path': prefix + d + '/', 'type': 'directory', 'size': 0} 
                         for d in sorted(directories)]
        
        return {
            'path': '/' + prefix if prefix else '/',
            'files': sorted(files, key=lambda x: x['name']),
            'directories': directory_list,
            'total_objects': len(files) + len(directory_list)
        }
        
    def _list_jungledisk_root(self, prefix: str) -> Dict[str, Any]:
        """List the root directory of a JungleDisk user, resolving directory names."""
        
        # List all UUID directories
        response = self.client.s3_client.list_objects_v2(
            Bucket=self.client.bucket_name,
            Prefix=prefix,
            Delimiter='/',
            MaxKeys=1000
        )
        
        directories = []
        files = []
        
        # Process common prefixes (directories)
        for prefix_info in response.get('CommonPrefixes', []):
            dir_path = prefix_info['Prefix']
            dir_name = dir_path.rstrip('/').split('/')[-1]
            
            # Skip metadata directories
            if dir_name in ['FILES', 'ROOT'] or dir_name.endswith('.key') or dir_name.endswith('.dir'):
                continue
                
            # Try to get the real name of this directory
            real_name = self._get_directory_name(dir_path.rstrip('/'))
            
            if real_name:
                directories.append({
                    'name': real_name + '/',
                    'path': dir_path,
                    'type': 'directory',
                    'size': 0,
                    'uuid': dir_name
                })
            else:
                # If we can't resolve the name, show the UUID
                directories.append({
                    'name': dir_name + '/',
                    'path': dir_path,
                    'type': 'directory', 
                    'size': 0
                })
                
        # Process files in the root
        for obj in response.get('Contents', []):
            key = obj['Key']
            
            # Skip metadata files
            if self.parser.is_metadata_file(key):
                continue
                
            # Parse the file
            parsed = self.parser.parse_jungledisk_path(key)
            if parsed and parsed.get('name') and not parsed['is_dir']:
                files.append({
                    'name': parsed['name'],
                    'path': key,
                    'size': parsed.get('size', 0)
                })
                
        return {
            'path': '/' + prefix if prefix else '/',
            'files': sorted(files, key=lambda x: x['name']),
            'directories': sorted(directories, key=lambda x: x['name']),
            'total_objects': len(files) + len(directories)
        }
        
    def _get_directory_name(self, dir_path: str) -> Optional[str]:
        """Try to get the real name of a directory from its contents.
        
        Args:
            dir_path: Path to the directory (without trailing /)
            
        Returns:
            Real directory name or None if not found
        """
        # Check cache first
        if dir_path in self.directory_map:
            return self.directory_map[dir_path]
            
        # For now, return the UUID - in a real implementation,
        # we would need to decrypt the directory metadata to get the real name
        # This would require accessing the 0.key file and decrypting the filenames
        
        # Extract just the UUID part for display
        parts = dir_path.split('/')
        if parts and len(parts[-1]) == 32:
            # Return a shortened version for readability
            uuid = parts[-1]
            return f"{uuid[:8]}..."
                    
        return None
        
    def _is_direct_child(self, key: str, prefix: str) -> bool:
        """Check if a key is a direct child of the prefix (not in a subdirectory).
        
        Args:
            key: S3 object key
            prefix: Current prefix
            
        Returns:
            True if the key is a direct child of the prefix
        """
        if not key.startswith(prefix):
            return False
            
        relative = key[len(prefix):]
        
        # Count the number of UUID segments after the prefix
        parts = relative.split('/')
        
        # For JungleDisk, a direct child would be: uuid/uuid/type/name/...
        # We want items where the parent UUID is directly under our prefix
        uuid_count = 0
        for part in parts:
            if len(part) == 32:  # UUID length
                uuid_count += 1
            else:
                break
                
        # Direct child has exactly 2 UUIDs (parent and item)
        return uuid_count <= 2