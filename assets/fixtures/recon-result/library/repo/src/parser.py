def parse_document(text, options=None):
    """Fixture public library API for source-location binding."""
    options = options or {}
    return {"length": len(text), "strict": bool(options.get("strict"))}
