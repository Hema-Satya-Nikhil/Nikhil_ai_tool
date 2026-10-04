"""HTTPX-compatible probing adapter implemented on the mandatory scoped client."""
from nikhil_ai_modules.http_probe import probe_http_https


def probe(context, target):
    # Deliberately delegate to the existing shared HTTP client rather than
    # launching httpx, which would otherwise bypass connected-peer validation.
    return probe_http_https(target, context=context)
