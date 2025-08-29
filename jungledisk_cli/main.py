"""Main CLI interface for JungleDisk CLI tool."""

import click
import logging
import sys
import os
from typing import Optional
from pathlib import Path
from dotenv import load_dotenv
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
@click.option('--format', '-f', type=click.Choice(['simple', 'detailed', 'json']), 
              default='simple', help='Output format')
@click.argument('path', default='/')
def list(access_key: str, secret_key: str, bucket: str, region: str, 
         format: str, path: str):
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
        
    try:
        # Initialize components
        client = JungleDiskS3Client(access_key, secret_key, bucket, region)
        parser = JungleDiskParser()
        lister = JungleDiskLister(client, parser)
        
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


def _download_recursive(downloader, lister, parser, remote_path: str, local_path: Optional[str], password: str):
    """Download all files from a directory recursively.
    
    Args:
        downloader: JungleDiskDownloader instance
        lister: JungleDiskLister instance
        parser: JungleDiskParser instance
        remote_path: Remote directory path
        local_path: Local directory to save files (optional)
        password: Decryption password (optional)
    """
    # Normalize remote path
    remote_path = parser.parse_path(remote_path)
    
    # If no local path specified, use the directory name from remote path
    if not local_path:
        # Extract directory name from remote path
        remote_dir = os.path.basename(remote_path.rstrip('/'))
        if not remote_dir or remote_dir == '/':
            # If downloading root or can't determine name, use 'downloads'
            local_path = 'downloads'
        else:
            local_path = remote_dir
    
    # Create local directory if it doesn't exist
    local_dir = Path(local_path)
    local_dir.mkdir(parents=True, exist_ok=True)
    
    click.echo(f"Downloading files from {remote_path} to {local_path}/")
    
    # Track statistics
    total_files = 0
    total_size = 0
    failed_files = []
    
    def download_directory(remote_dir: str, local_dir: Path, indent: int = 0):
        """Recursively download files from a directory."""
        nonlocal total_files, total_size, failed_files
        
        # List contents of the directory
        try:
            results = lister.list_path(remote_dir)
        except Exception as e:
            logger.error(f"Failed to list directory {remote_dir}: {e}")
            return
        
        # Process files first
        files = results.get('files', [])
        for file_info in files:
            file_name = file_info['name']
            file_size = file_info['size']
            
            # Build full remote and local paths
            remote_file_path = os.path.join(remote_dir, file_name).replace('\\', '/')
            local_file_path = local_dir / file_name
            
            # Show progress
            indent_str = "  " * indent
            click.echo(f"{indent_str}Downloading: {file_name} ({_format_size(file_size)})")
            
            # Download the file
            try:
                success = downloader.download_file(remote_file_path, str(local_file_path))
                if success:
                    total_files += 1
                    total_size += file_size
                    click.echo(f"{indent_str}  ✓ Saved to: {local_file_path}")
                else:
                    failed_files.append(remote_file_path)
                    click.echo(f"{indent_str}  ✗ Failed to download")
            except Exception as e:
                failed_files.append(remote_file_path)
                click.echo(f"{indent_str}  ✗ Error: {e}")
        
        # Process subdirectories
        directories = results.get('directories', [])
        for dir_info in directories:
            dir_name = dir_info['name']
            
            # Build paths for subdirectory
            remote_subdir = os.path.join(remote_dir, dir_name).replace('\\', '/')
            local_subdir = local_dir / dir_name
            
            # Create local subdirectory
            local_subdir.mkdir(parents=True, exist_ok=True)
            
            # Show directory being processed
            indent_str = "  " * indent
            click.echo(f"{indent_str}[DIR] {dir_name}/")
            
            # Recursively download subdirectory
            download_directory(remote_subdir, local_subdir, indent + 1)
    
    # Start recursive download
    download_directory(remote_path, local_dir)
    
    # Show summary
    click.echo("\n" + "=" * 60)
    click.echo(f"Download complete:")
    click.echo(f"  Files downloaded: {total_files}")
    click.echo(f"  Total size: {_format_size(total_size)}")
    
    if password and downloader.decryptor and downloader.decryptor.key_loaded:
        click.echo("  Status: Decrypted")
    else:
        click.echo("  Status: Downloaded (no decryption)")
    
    if failed_files:
        click.echo(f"\n  Failed downloads: {len(failed_files)}")
        for failed in failed_files[:5]:  # Show first 5 failures
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
              default=lambda: os.environ.get('JUNGLEDISK_PASSWORD', ''),
              help='JungleDisk password for decryption (or set JUNGLEDISK_PASSWORD env var)')
@click.option('--recursive', '-R', is_flag=True,
              help='Download all files recursively from a directory')
@click.argument('remote_path')
@click.argument('local_path', required=False)
def download(access_key: str, secret_key: str, bucket: str, region: str,
             password: str, recursive: bool, remote_path: str, local_path: Optional[str]):
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
        
    try:
        # Initialize components
        client = JungleDiskS3Client(access_key, secret_key, bucket, region)
        parser = JungleDiskParser()
        lister = JungleDiskLister(client, parser)
        downloader = JungleDiskDownloader(client, parser, lister, password)
        
        if recursive:
            # Recursive download of a directory
            _download_recursive(downloader, lister, parser, remote_path, local_path, password)
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
            success = downloader.download_file(remote_path, local_path)
            
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