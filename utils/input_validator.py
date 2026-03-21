import re


def validate_filename(filename):
    """Validate and sanitize filename to prevent path traversal"""
    if not filename:
        return False
    # Remove any path traversal attempts
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    # Allow only safe characters
    if not re.match(r"^[a-zA-Z0-9_.-]+$", filename):
        return False
    return True


def sanitize_input(text):
    """Sanitize user input to prevent XSS"""
    if not text:
        return text
    # Escape HTML special characters
    import html

    return html.escape(text)


def validate_policy_rule(rule):
    """Validate policy rule structure"""
    if not rule:
        return False
    required_fields = ["Effect", "Action", "Resource"]
    for field in required_fields:
        if field not in rule:
            return False
    # Validate Effect is Allow or Deny
    if rule["Effect"] not in ["Allow", "Deny"]:
        return False
    return True


def validate_file_content(content, filename):
    """Validate file content based on type"""
    if not content:
        return False

    # Check file size (max 5MB)
    if len(content) > 5 * 1024 * 1024:
        return False

    # Check for binary content
    if b"\x00" in content[:1000]:  # Check first 1000 bytes
        return False

    return True
