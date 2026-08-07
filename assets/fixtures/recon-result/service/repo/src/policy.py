def validate_import_url(value):
    """Fixture policy location for Recon coverage evidence."""
    return isinstance(value, str) and value.startswith("https://")


DEFAULT_TIMEOUT_SECONDS = 3
