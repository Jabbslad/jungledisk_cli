"""Main CLI interface for JungleDisk CLI tool."""

import click
import logging
import sys
import os
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from .s3_client import JungleDiskS3Client
from .parser import JungleDiskParser
from .jungledisk_lister import JungleDiskLister
from .downloader import JungleDiskDownloader

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.option('--debug/--no-debug', default=False, help='Enable debug logging')
def cli(debug: bool):
    """JungleDisk CLI tool for listing files in S3 buckets."""
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        

@cli.command()
@click.option('--access-key', '-a', 
              default=lambda: os.environ.get('AWS_ACCESS_KEY_ID', ''),
              help='AWS access key ID (or set AWS_ACCESS_KEY_ID env var)')
@click.option('--secret-key', '-s', 
              default=lambda: os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
              help='AWS secret access key (or set AWS_SECRET_ACCESS_KEY env var)')
@click.option('--bucket', '-b', 
              default=lambda: os.environ.get('JUNGLEDISK_BUCKET', ''),
              help='S3 bucket name (or set JUNGLEDISK_BUCKET env var)')
@click.option('--region', '-r', 
              default=lambda: os.environ.get('AWS_REGION', 'us-east-1'),
              help='AWS region (or set AWS_REGION env var)')
@click.option('--password', '-p',
              default=None,
              help='JungleDisk password for decrypting filenames (or set JUNGLEDISK_PASSWORD env var)')
@click.option('--format', '-f', type=click.Choice(['simple', 'detailed', 'json']), 
              default='simple', help='Output format')
@click.argument('path', default='/')
def list(access_key: str, secret_key: str, bucket: str, region: str, 
         password: str, format: str, path: str):
    """List files in a JungleDisk S3 bucket path (non-recursive).
    
    PATH is the directory path to list (default: /)
    """
    # Validate required credentials
    if not access_key:
        logger.error("AWS access key is required. Set via --access-key or AWS_ACCESS_KEY_ID env var")
        sys.exit(1)
    if not secret_key:
        logger.error("AWS secret key is required. Set via --secret-key or AWS_SECRET_ACCESS_KEY env var")
        sys.exit(1)
    if not bucket:
        logger.error("Bucket name is required. Set via --bucket or JUNGLEDISK_BUCKET env var")
        sys.exit(1)
    
    # Use password from command line if provided, otherwise fall back to environment
    if password is None:
        password = os.environ.get('JUNGLEDISK_PASSWORD', '')
        
    try:
        # Initialize components
        client = JungleDiskS3Client(access_key, secret_key, bucket, region)
        parser = JungleDiskParser()
        
        # Initialize decryptor if password provided
        decryptor = None
        if password:
            from .decryptor import JungleDiskDecryptor
            # Try to find and load the 0.key file
            try:
                # Look for 0.key file in the user's directory from the path
                username = path.strip('/').split('/')[0] if path.strip('/') else None
                
                if username:
                    key_file_path = f"{username}/0.key"
                    logger.debug(f"Looking for 0.key file at {key_file_path}")
                    
                    try:
                        key_content = client.download_object(key_file_path)
                        metadata = client.get_object_metadata(key_file_path)
                        
                        decryptor = JungleDiskDecryptor(password)
                        if decryptor.load_key_file(key_content, metadata):
                            logger.info("Encryption keys loaded for filename decryption")
                        else:
                            logger.warning("Failed to load encryption keys - filenames may appear encrypted")
                            decryptor = None
                    except Exception as e:
                        logger.debug(f"Could not load 0.key file: {e}")
                        # Try all users if no specific user in path
                        if not username or '/' not in path.strip('/'):
                            response = client.s3_client.list_objects_v2(
                                Bucket=client.bucket_name,
                                Delimiter='/',
                                MaxKeys=10
                            )
                            for prefix_info in response.get('CommonPrefixes', []):
                                user_prefix = prefix_info['Prefix'].rstrip('/')
                                key_file_path = f"{user_prefix}/0.key"
                                try:
                                    key_content = client.download_object(key_file_path)
                                    metadata = client.get_object_metadata(key_file_path)
                                    decryptor = JungleDiskDecryptor(password)
                                    if decryptor.load_key_file(key_content, metadata):
                                        logger.info(f"Encryption keys loaded from {key_file_path}")
                                        break
                                    else:
                                        decryptor = None
                                except:
                                    continue
            except Exception as e:
                logger.debug(f"Could not initialize decryptor: {e}")
        
        lister = JungleDiskLister(client, parser, decryptor)
        
        # Normalize path
        normalized_path = parser.parse_path(path)
        
        logger.debug(f"Listing path: {normalized_path}")
        
        # List files
        results = lister.list_path(normalized_path)
        
        # Format and display results
        if format == 'json':
            import json
            click.echo(json.dumps(results, indent=2, default=str))
        elif format == 'detailed':
            _display_detailed(results)
        else:
            _display_simple(results)
            
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        sys.exit(1)
        

def _display_simple(results: dict):
    """Display results in simple format.
    
    Args:
        results: Dictionary containing files and directories
    """
    # Display directories first
    directories = results.get('directories', [])
    for dir_info in directories:
        click.echo(f"[DIR]  {dir_info['name']}")
        
    # Display files
    files = results.get('files', [])
    for file_info in files:
        size_str = _format_size(file_info['size'])
        click.echo(f"[FILE] {file_info['name']} ({size_str})")
        
    # Display summary
    click.echo(f"\nTotal: {len(directories)} directories, {len(files)} files")
    

def _display_detailed(results: dict):
    """Display results in detailed format.
    
    Args:
        results: Dictionary containing files and directories
    """
    click.echo(f"Listing: {results.get('path', '/')}")
    click.echo("-" * 80)
    
    # Header
    click.echo(f"{'Type':<6} {'Size':>10} {'Modified':<20} {'Name'}")
    click.echo("-" * 80)
    
    # Display directories first
    directories = results.get('directories', [])
    for dir_info in directories:
        click.echo(f"{'DIR':<6} {'':>10} {'':20} {dir_info['name']}")
        
    # Display files
    files = results.get('files', [])
    for file_info in files:
        size_str = _format_size(file_info['size'])
        modified = file_info.get('last_modified', '')
        if modified and len(modified) > 19:
            modified = modified[:19]
        click.echo(f"{'FILE':<6} {size_str:>10} {modified:<20} {file_info['name']}")
        
    # Display summary
    click.echo("-" * 80)
    total_size = sum(f['size'] for f in files)
    click.echo(f"Total: {len(directories)} directories, {len(files)} files ({_format_size(total_size)})")
    

def _format_size(size: int) -> str:
    """Format file size in human-readable format.
    
    Args:
        size: Size in bytes
        
    Returns:
        Formatted size string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            if unit == 'B':
                return f"{size} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def _download_recursive(downloader, lister, parser, remote_path: str, local_path: Optional[str], 
                       password: str, skip_existing: bool = True, max_concurrent: int = 5, 
                       no_progress: bool = False):
    """Download all files from a directory recursively with concurrent downloads.
    
    Args:
        downloader: JungleDiskDownloader instance
        lister: JungleDiskLister instance
        parser: JungleDiskParser instance
        remote_path: Remote directory path
        local_path: Local directory to save files (optional)
        password: Decryption password (optional)
        skip_existing: Whether to skip existing files
        max_concurrent: Maximum concurrent downloads
        no_progress: Disable progress bar
    """
    # Normalize remote path
    remote_path = parser.parse_path(remote_path)
    
    # If no local path specified, use the directory name from remote path
    if not local_path:
        remote_dir = os.path.basename(remote_path.rstrip('/'))
        if not remote_dir or remote_dir == '/':
            local_path = 'downloads'
        else:
            local_path = remote_dir
    
    # Create local directory if it doesn't exist
    local_dir = Path(local_path)
    local_dir.mkdir(parents=True, exist_ok=True)
    
    # Log what we're using as the local directory
    logger.info(f"Using local directory: {local_dir.absolute()}")
    
    click.echo(f"Scanning {remote_path} for files...")
    
    # Use the efficient recursive listing method
    try:
        files_list, total_count = lister.list_recursive(remote_path)
    except Exception as e:
        logger.error(f"Failed to list directory {remote_path}: {e}")
        click.echo(f"Error: Failed to list directory: {e}")
        return
    
    # Convert the flat list to the format needed for downloading
    all_files = []
    base_path_parts = len(remote_path.rstrip('/').split('/'))
    
    # Debug first file to understand path structure
    if files_list and len(files_list) > 0:
        first_file = files_list[0]
        logger.debug(f"First file path from list_recursive: {first_file['path']}")
        logger.debug(f"Remote path: {remote_path}, base_path_parts: {base_path_parts}")
        # Find first file with 'iPhoto' in path for debugging
        for f in files_list[:100]:
            if 'iPhoto' in f['path']:
                logger.debug(f"iPhoto file path: {f['path']}")
                break
    
    for file_info in files_list:
        # Get the full remote path
        remote_file_path = file_info['path']
        
        # Calculate the relative path from the base directory
        path_parts = remote_file_path.split('/')
        relative_parts = path_parts[base_path_parts:]
        
        # Debug problematic paths
        if relative_parts and relative_parts[0] and relative_parts[0].startswith('iPhoto'):
            logger.debug(f"DEBUG iPhoto: remote_file_path={remote_file_path}")
            logger.debug(f"DEBUG iPhoto: path_parts={path_parts}")
            logger.debug(f"DEBUG iPhoto: relative_parts={relative_parts}")
        
        # Construct the local path maintaining directory structure
        if relative_parts:
            # Filter out any empty parts and join
            clean_parts = [p for p in relative_parts if p]
            if clean_parts:
                relative_path = '/'.join(clean_parts)
                local_file_path = local_dir / relative_path
            else:
                local_file_path = local_dir / file_info['name']
        else:
            # File is in the root of the remote path
            local_file_path = local_dir / file_info['name']
        
        # Ensure the parent directory exists (safely)
        try:
            local_file_path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            logger.error(f"Permission error creating directory {local_file_path.parent}: {e}")
            logger.error(f"Full path was: {local_file_path}")
            continue
        
        all_files.append({
            'remote_path': remote_file_path,
            'local_path': str(local_file_path),
            'size': file_info['size'],
            'name': file_info['name']
        })
    
    if not all_files:
        click.echo("No files found to download.")
        return
    
    # Filter out existing files if skip_existing
    files_to_download = []
    skipped_files = []
    
    for file_info in all_files:
        if downloader.should_download_file(file_info['local_path'], 
                                          file_info['size'], 
                                          skip_existing):
            files_to_download.append(file_info)
        else:
            skipped_files.append(file_info)
    
    if skipped_files:
        click.echo(f"Skipping {len(skipped_files)} existing files")
    
    if not files_to_download:
        click.echo("All files already exist locally.")
        return
    
    total_size = sum(f['size'] for f in files_to_download)
    click.echo(f"\nDownloading {len(files_to_download)} files ({_format_size(total_size)}) "
               f"with {max_concurrent} concurrent downloads...")
    
    # Download files concurrently
    failed_files = []
    successful_downloads = 0
    downloaded_size = 0
    
    # Create progress bars
    if not no_progress:
        file_pbar = tqdm(total=len(files_to_download), unit='files', desc='Files')
        size_pbar = tqdm(total=total_size, unit='B', unit_scale=True, desc='Size')
    
    def download_file_wrapper(file_info):
        """Wrapper to download a single file."""
        try:
            success = downloader.download_file(
                file_info['remote_path'], 
                file_info['local_path'],
                skip_existing=skip_existing
            )
            return file_info, success
        except Exception as e:
            logger.error(f"Error downloading {file_info['remote_path']}: {e}")
            return file_info, False
    
    # Use ThreadPoolExecutor for concurrent downloads
    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = {
            executor.submit(download_file_wrapper, file_info): file_info 
            for file_info in files_to_download
        }
        
        for future in as_completed(futures):
            file_info, success = future.result()
            
            if success:
                successful_downloads += 1
                downloaded_size += file_info['size']
                if not no_progress:
                    file_pbar.update(1)
                    size_pbar.update(file_info['size'])
            else:
                failed_files.append(file_info['remote_path'])
                if not no_progress:
                    file_pbar.update(1)
                    file_pbar.set_postfix({'failed': len(failed_files)})
    
    # Close progress bars
    if not no_progress:
        file_pbar.close()
        size_pbar.close()
    
    # Show summary
    click.echo("\n" + "=" * 60)
    click.echo(f"Download complete:")
    click.echo(f"  Files downloaded: {successful_downloads}/{len(files_to_download)}")
    click.echo(f"  Total size: {_format_size(downloaded_size)}")
    
    if skipped_files:
        click.echo(f"  Files skipped: {len(skipped_files)}")
    
    if password and downloader.decryptor and downloader.decryptor.key_loaded:
        click.echo("  Status: Decrypted")
    else:
        click.echo("  Status: Downloaded (no decryption)")
    
    if failed_files:
        click.echo(f"\n  Failed downloads: {len(failed_files)}")
        for failed in failed_files[:5]:
            click.echo(f"    - {failed}")
        if len(failed_files) > 5:
            click.echo(f"    ... and {len(failed_files) - 5} more")


@cli.command()
@click.option('--access-key', '-a', 
              default=lambda: os.environ.get('AWS_ACCESS_KEY_ID', ''),
              help='AWS access key ID (or set AWS_ACCESS_KEY_ID env var)')
@click.option('--secret-key', '-s', 
              default=lambda: os.environ.get('AWS_SECRET_ACCESS_KEY', ''),
              help='AWS secret access key (or set AWS_SECRET_ACCESS_KEY env var)')
@click.option('--bucket', '-b', 
              default=lambda: os.environ.get('JUNGLEDISK_BUCKET', ''),
              help='S3 bucket name (or set JUNGLEDISK_BUCKET env var)')
@click.option('--region', '-r', 
              default=lambda: os.environ.get('AWS_REGION', 'us-east-1'),
              help='AWS region (or set AWS_REGION env var)')
@click.option('--password', '-p',
              default=None,
              help='JungleDisk password for decryption (or set JUNGLEDISK_PASSWORD env var)')
@click.option('--recursive', '-R', is_flag=True,
              help='Download all files recursively from a directory')
@click.option('--skip-existing', is_flag=True, default=True,
              help='Skip files that already exist locally with matching size (default: True)')
@click.option('--max-concurrent', '-j', default=5, type=int,
              help='Maximum concurrent downloads (default: 5)')
@click.option('--no-progress', is_flag=True,
              help='Disable progress bar')
@click.argument('remote_path')
@click.argument('local_path', required=False)
def download(access_key: str, secret_key: str, bucket: str, region: str,
             password: str, recursive: bool, skip_existing: bool, max_concurrent: int,
             no_progress: bool, remote_path: str, local_path: Optional[str]):
    """Download a file or directory from JungleDisk S3 bucket.
    
    REMOTE_PATH is the path in JungleDisk (e.g., /helen/file.txt or /helen/backups/)
    LOCAL_PATH is where to save the file(s) locally (optional, defaults to current directory)
    
    Use --recursive to download all files from a directory.
    """
    # Validate required credentials
    if not access_key:
        logger.error("AWS access key is required. Set via --access-key or AWS_ACCESS_KEY_ID env var")
        sys.exit(1)
    if not secret_key:
        logger.error("AWS secret key is required. Set via --secret-key or AWS_SECRET_ACCESS_KEY env var")
        sys.exit(1)
    if not bucket:
        logger.error("Bucket name is required. Set via --bucket or JUNGLEDISK_BUCKET env var")
        sys.exit(1)
    
    # Use password from command line if provided, otherwise fall back to environment
    if password is None:
        password = os.environ.get('JUNGLEDISK_PASSWORD', '')
        
    try:
        # Initialize components
        client = JungleDiskS3Client(access_key, secret_key, bucket, region)
        parser = JungleDiskParser()
        lister = JungleDiskLister(client, parser)
        downloader = JungleDiskDownloader(client, parser, lister, password)
        
        if recursive:
            # Recursive download of a directory
            _download_recursive(downloader, lister, parser, remote_path, local_path, password,
                              skip_existing, max_concurrent, no_progress)
        else:
            # Single file download - first check if it's actually a directory
            # Normalize the path
            normalized_path = parser.parse_path(remote_path)
            
            # Check if the target is a directory by trying to list it
            is_directory = False
            try:
                listing_result = lister.list_path(normalized_path)
                # If we successfully listed it, check if it's actually a directory
                # A valid directory will have actual content (files or directories) or be a known empty directory
                if (listing_result and 
                    isinstance(listing_result, dict) and 
                    'path' in listing_result and 
                    # Either has actual contents OR has total_objects > 0 (non-empty directory)
                    (listing_result.get('files') or listing_result.get('directories') or 
                     listing_result.get('total_objects', 0) > 0)):
                    is_directory = True
            except Exception as e:
                # If listing fails with specific errors that indicate it's not a directory, continue
                logger.debug(f"Directory check failed: {e}")
                pass
            
            if is_directory:
                click.echo(f"Error: '{remote_path}' is a directory.")
                click.echo("Use the --recursive flag to download directories:")
                click.echo(f"  jungledisk download --recursive \"{remote_path}\"")
                sys.exit(1)
            
            # If no local path specified, use the filename from remote path
            if not local_path:
                # Extract filename from remote path
                remote_filename = os.path.basename(remote_path.rstrip('/'))
                if not remote_filename:
                    logger.error("Cannot determine filename from remote path")
                    sys.exit(1)
                local_path = remote_filename
                logger.debug(f"Using filename from remote path: {local_path}")
            
            logger.info(f"Downloading {remote_path} to {local_path}")
            
            # Download the file
            success = downloader.download_file(remote_path, local_path, skip_existing)
            
            if success:
                click.echo(f"✓ File downloaded successfully to {local_path}")
                
                # Check file size
                file_size = Path(local_path).stat().st_size
                click.echo(f"  Size: {_format_size(file_size)}")
                
                if password and downloader.decryptor and downloader.decryptor.key_loaded:
                    click.echo("  Status: Decrypted")
                else:
                    click.echo("  Status: Downloaded (no decryption)")
            else:
                logger.error("Download failed")
                sys.exit(1)
            
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()