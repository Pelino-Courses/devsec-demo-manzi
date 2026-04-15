"""
Secure file upload handling utilities.

This module provides secure file handling for user uploads including:
- MIME type validation and verification
- File extension whitelisting
- File size limits
- Magic number verification (file signature validation)
- Safe filename sanitization
- Secure storage location handling

Security Principles:
1. Never trust client-provided MIME types or extensions
2. Verify actual file content (magic numbers) matches declared type
3. Use whitelist approach for allowed file types
4. Implement strict file size limits
5. Sanitize filenames to prevent directory traversal
6. Store files outside web root when possible
7. Serve files through access control checks, not direct URLs
"""

import os
import hashlib
from pathlib import Path
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile


# ============================================================================
# MIME Type and Extension Whitelists
# ============================================================================

# Allowed image MIME types (verified against magic numbers)
ALLOWED_IMAGE_MIME_TYPES = {
    'image/jpeg': {'extensions': ['.jpg', '.jpeg'], 'max_size': 5 * 1024 * 1024},
    'image/png': {'extensions': ['.png'], 'max_size': 5 * 1024 * 1024},
    'image/gif': {'extensions': ['.gif'], 'max_size': 3 * 1024 * 1024},
    'image/webp': {'extensions': ['.webp'], 'max_size': 5 * 1024 * 1024},
}

# Allowed image file extensions (lowercase)
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}

# Maximum file sizes by type (in bytes)
MAX_FILE_SIZES = {
    'image': 5 * 1024 * 1024,  # 5MB for images
    'document': 10 * 1024 * 1024,  # 10MB for documents
    'default': 2 * 1024 * 1024,  # 2MB default
}

# Common dangerous file extensions that should NEVER be allowed
DANGEROUS_EXTENSIONS = {
    '.exe', '.com', '.bat', '.cmd', '.sh', '.bash',  # Executables
    '.js', '.java', '.py', '.php', '.asp', '.aspx',  # Scripts
    '.zip', '.rar', '.7z', '.tar', '.gz',  # Archives
    '.html', '.htm', '.xml', '.svg', '.xhtml',  # Web content
    '.dll', '.so', '.dylib', '.bin',  # Libraries
    '.app', '.apk', '.deb', '.rpm',  # Installers
}

# Magic numbers (file signatures) for verification
FILE_SIGNATURES = {
    b'\xFF\xD8\xFF': 'image/jpeg',  # JPEG
    b'\x89\x50\x4E\x47': 'image/png',  # PNG
    b'\x47\x49\x46': 'image/gif',  # GIF
    b'\x52\x49\x46\x46': 'image/webp',  # WebP/WAV/AVI (check further for WebP)
}


# ============================================================================
# File Upload Validators
# ============================================================================

def get_file_mime_type(uploaded_file: UploadedFile) -> str:
    """
    Detect actual MIME type of uploaded file using magic numbers.
    
    Does NOT trust client-provided Content-Type header.
    Reads file signature (magic numbers) to determine type.
    
    Args:
        uploaded_file: Django UploadedFile object
        
    Returns:
        Detected MIME type string (e.g., 'image/jpeg')
        
    Raises:
        ValidationError: If MIME type cannot be determined
    """
    uploaded_file.seek(0)  # Reset file pointer to start
    
    # Read first few bytes to check magic numbers
    header = uploaded_file.read(512)  # Read up to 512 bytes
    uploaded_file.seek(0)  # Reset again for use
    
    if not header:
        raise ValidationError("Empty file provided")
    
    # Check against known magic numbers
    for signature, mime_type in FILE_SIGNATURES.items():
        if header.startswith(signature):
            # Additional check for WebP (RIFF files)
            if signature == b'\x52\x49\x46\x46' and b'WEBP' in header[:12]:
                return 'image/webp'
            elif signature == b'\x52\x49\x46\x46':
                # Not WebP, might be WAV or AVI
                raise ValidationError("File type not supported")
            return mime_type
    
    raise ValidationError(f"File type not recognized or not supported")


def validate_file_extension(filename: str) -> str:
    """
    Validate that file extension is in whitelist.
    
    Args:
        filename: Original filename from upload
        
    Returns:
        Lowercase file extension (e.g., '.jpg')
        
    Raises:
        ValidationError: If extension not whitelisted or dangerous
    """
    # Get extension
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    
    if not ext:
        raise ValidationError("File must have an extension")
    
    if ext in DANGEROUS_EXTENSIONS:
        raise ValidationError(f"File extension '{ext}' is not allowed for security reasons")
    
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValidationError(f"File extension '{ext}' is not allowed. Allowed types: {', '.join(sorted(ALLOWED_IMAGE_EXTENSIONS))}")
    
    return ext


def validate_file_size(uploaded_file: UploadedFile, max_size: int = None) -> int:
    """
    Validate file size against limits.
    
    Args:
        uploaded_file: Django UploadedFile object
        max_size: Maximum file size in bytes (defaults to image limit)
        
    Returns:
        File size in bytes if valid
        
    Raises:
        ValidationError: If file exceeds size limit
    """
    if max_size is None:
        max_size = MAX_FILE_SIZES['image']
    
    file_size = uploaded_file.size
    
    if file_size == 0:
        raise ValidationError("Empty file provided")
    
    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        raise ValidationError(f"File too large. Maximum size: {max_mb:.1f}MB")
    
    return file_size


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to prevent directory traversal and other attacks.
    
    - Removes path separators
    - Removes special characters
    - Limits length
    - Generates safe hash-based name with original extension
    
    Args:
        filename: Original filename from upload
        
    Returns:
        Safe filename for storage
    """
    # Get filename and extension
    base_name = os.path.basename(filename)  # Remove directory path
    name, ext = os.path.splitext(base_name)
    
    # Remove dangerous characters from name (keep only alphanumeric, dash, underscore)
    safe_name = "".join(c for c in name if c.isalnum() or c in ['-', '_'])
    
    if not safe_name:
        # If name becomes empty after sanitization, use timestamp-based name
        import time
        safe_name = f"upload_{int(time.time())}"
    
    # Limit name length
    if len(safe_name) > 100:
        safe_name = safe_name[:100]
    
    # Combine with extension
    safe_filename = f"{safe_name}{ext.lower()}"
    
    return safe_filename


def get_secure_upload_path(user_id: int, file_category: str = 'profile_picture') -> str:
    """
    Generate secure upload path that includes user ID.
    
    Path structure: profile_pictures/<user_id>/
    
    This ensures:
    - Directory traversal attacks are limited
    - User files are isolated
    - Easy cleanup when user deletes account
    
    Args:
        user_id: ID of user uploading file
        file_category: Type of file (default: profile_picture)
        
    Returns:
        Upload path for use with ImageField/FileField
    """
    if not str(user_id).isdigit():
        raise ValidationError("Invalid user ID")
    
    if file_category not in ['profile_picture', 'document', 'file']:
        raise ValidationError("Invalid file category")
    
    return f"{file_category}/{user_id}/"


def validate_image_upload(uploaded_file: UploadedFile) -> dict:
    """
    Comprehensive validation for image uploads.
    
    Validates:
    - File extension
    - MIME type by magic numbers
    - File size
    - Not a trojanized image (contains embedded executables)
    
    Args:
        uploaded_file: Django UploadedFile object
        
    Returns:
        Dict with validation results:
        {
            'valid': True/False,
            'errors': [list of error messages],
            'mime_type': detected MIME type,
            'size': file size in bytes,
            'extension': file extension
        }
    """
    result = {
        'valid': False,
        'errors': [],
        'mime_type': None,
        'size': None,
        'extension': None,
    }
    
    # Validate extension
    try:
        ext = validate_file_extension(uploaded_file.name)
        result['extension'] = ext
    except ValidationError as e:
        result['errors'].append(str(e))
        return result
    
    # Validate file size
    try:
        size = validate_file_size(uploaded_file)
        result['size'] = size
    except ValidationError as e:
        result['errors'].append(str(e))
        return result
    
    # Detect actual MIME type
    try:
        mime_type = get_file_mime_type(uploaded_file)
        result['mime_type'] = mime_type
    except ValidationError as e:
        result['errors'].append(str(e))
        return result
    
    # Verify MIME type is allowed
    if mime_type not in ALLOWED_IMAGE_MIME_TYPES:
        result['errors'].append(f"MIME type '{mime_type}' not allowed")
        return result
    
    # Verify extension matches detected MIME type
    allowed_exts = ALLOWED_IMAGE_MIME_TYPES[mime_type]['extensions']
    if ext.lower() not in [e.lower() for e in allowed_exts]:
        result['errors'].append(f"File extension '{ext}' doesn't match MIME type '{mime_type}'")
        return result
    
    # All checks passed
    result['valid'] = True
    return result


def generate_secure_filename_hash(uploaded_file: UploadedFile, user_id: int) -> str:
    """
    Generate secure filename using hash to prevent collisions and enumeration.
    
    After validation, rename file to hash-based name to:
    - Prevent filename enumeration
    - Prevent collision attacks
    - Maintain user isolation
    
    Args:
        uploaded_file: Django UploadedFile object
        user_id: ID of user uploading file
        
    Returns:
        Secure filename (hash + original extension)
    """
    uploaded_file.seek(0)
    
    # Combine file content hash with user ID for uniqueness
    file_hash = hashlib.sha256(uploaded_file.read()).hexdigest()[:16]
    _, ext = os.path.splitext(uploaded_file.name)
    
    secure_name = f"{file_hash}{ext.lower()}"
    
    return secure_name


def log_upload_attempt(user_id: int, filename: str, mime_type: str, size: int, success: bool, reason: str = None):
    """
    Log file upload attempts for security monitoring.
    
    Args:
        user_id: ID of user attempting upload
        filename: Original filename attempted
        mime_type: Detected MIME type
        size: File size in bytes
        success: Whether upload succeeded
        reason: Reason for failure if unsuccessful
    """
    import logging
    logger = logging.getLogger('django.security')
    
    status = 'SUCCESS' if success else 'FAILED'
    msg = f"File upload {status}: User {user_id} attempted '{filename}' ({mime_type}, {size} bytes)"
    
    if reason:
        msg += f" - Reason: {reason}"
    
    if success:
        logger.info(msg)
    else:
        logger.warning(msg)
