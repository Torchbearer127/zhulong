from urllib.request import urlopen


def import_url(request):
    """Fixture route that records an attacker-controlled URL input."""
    target_url = request.json["url"]
    return urlopen(target_url, timeout=3).read()


def health():
    return {"status": "ok"}
