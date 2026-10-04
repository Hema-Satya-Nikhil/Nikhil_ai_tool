"""Nuclei is intentionally not launched by this safe assessment platform."""
from nikhil_ai_modules.scope import ScopeError


def run(*_args, **_kwargs):
    raise ScopeError("Nuclei template execution is disabled; use native review modules and human-approved test plans")
