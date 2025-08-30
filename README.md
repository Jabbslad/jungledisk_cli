# JungleDisk CLI

A Python command-line interface for accessing JungleDisk encrypted S3 buckets. This tool allows you to list, download, and decrypt files from JungleDisk 2.0 buckets.

## Background

JungleDisk was a popular backup service that stored encrypted files in Amazon S3. This CLI tool provides read-only access to JungleDisk 2.0 format buckets, allowing users to retrieve their backed-up data even after the service has been discontinued.

## Installation

This project uses `uv` for dependency management:

```bash
# Install uv if you haven't already
pip install uv

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e .
```

## Configuration

Create a `.env` file in the project root with your AWS credentials and JungleDisk password:

```env
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=eu-west-1
JUNGLEDISK_BUCKET=jd2-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-eu
JUNGLEDISK_PASSWORD=your_password
```

The bucket name follows the format: `jd2-MD5(access_key)-region` where region is `us` or `eu`.

## Usage

### List Files

```bash
# List root directory for a user
jungledisk list /username/

# List subdirectory with detailed output
jungledisk list --format detailed /username/directory/

# List with JSON output
jungledisk list --format json /username/directory/

# List with debug logging
jungledisk list --debug /username/
```

### Download Files

```bash
# Download a file (local filename defaults to remote filename)
jungledisk download /username/file.txt

# Download with explicit local path
jungledisk download /username/file.txt ./local_file.txt

# Download recursively (entire directory)
jungledisk download --recursive /username/directory/

# Download to specific local directory
jungledisk download --recursive /username/directory/ ./local_backup/

# Download with more concurrent connections for faster speed
jungledisk download --recursive --max-concurrent 10 /username/directory/

# Force re-download all files (don't skip existing)
jungledisk download --recursive --no-skip-existing /username/directory/

# Download without progress bars (useful for scripts)
jungledisk download --recursive --no-progress /username/directory/
```

### Command-line Options

#### Global Options
- `--debug`: Enable debug logging

#### List Command Options
- `--access-key`, `-a`: AWS access key (overrides AWS_ACCESS_KEY_ID env var)
- `--secret-key`, `-s`: AWS secret access key (overrides AWS_SECRET_ACCESS_KEY env var)
- `--bucket`, `-b`: S3 bucket name (overrides JUNGLEDISK_BUCKET env var)
- `--region`, `-r`: AWS region (overrides AWS_REGION env var, default: us-east-1)
- `--format`, `-f`: Output format (simple, detailed, json) (default: simple)

#### Download Command Options
- `--access-key`, `-a`: AWS access key (overrides AWS_ACCESS_KEY_ID env var)
- `--secret-key`, `-s`: AWS secret access key (overrides AWS_SECRET_ACCESS_KEY env var)
- `--bucket`, `-b`: S3 bucket name (overrides JUNGLEDISK_BUCKET env var)
- `--region`, `-r`: AWS region (overrides AWS_REGION env var, default: us-east-1)
- `--password`, `-p`: JungleDisk password for decryption (overrides JUNGLEDISK_PASSWORD env var)
- `--recursive`, `-R`: Download all files recursively from a directory
- `--skip-existing`: Skip files that already exist locally with matching size (default: True)
- `--max-concurrent`, `-j`: Maximum concurrent downloads (default: 5)
- `--no-progress`: Disable progress bars

## Features

- **High-performance downloads** with concurrent connections (5-10x faster for multiple files)
- **Smart file skipping** automatically skips existing files with matching size
- **Progress tracking** with real-time progress bars showing files and data transfer
- **List files and directories** in JungleDisk buckets with multiple output formats
- **Download files** with automatic decryption (single files or entire directories)
- **Recursive downloads** for backing up entire directory structures
- **JungleDisk 2.0 format support** including custom Base64 encoding and EVP_BytesToKey
- **Filename encryption support** automatically decrypts encrypted filenames when password is provided
- **Smart path resolution** handles filenames with special characters and Unicode
- **Multiple authentication methods**: environment variables, .env files, or command-line options
- **Flexible output formats**: simple, detailed, or JSON for integration with other tools
- **Error handling**: clear messages for common issues (e.g., trying to download directories without --recursive)
- **Connection pooling** for efficient S3 API usage

## License

MIT License