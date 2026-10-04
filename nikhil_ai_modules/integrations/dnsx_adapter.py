"""Scope-checked DNS resolution adapter; no standalone dnsx network bypass."""
from nikhil_ai_modules.scope import host_from_target


def resolve(context, target):
    host = host_from_target(str(target))
    addresses = context.scope.validate_host(host, resolve=True)
    return {"host": host, "addresses": addresses, "scope_validated": True}
