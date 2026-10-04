"""TLS adapter delegated to NIKHIL's native Scope Guard-aware TLS module."""
from nikhil_ai_modules.ssl_check import check_ssl


def inspect(context, target):
    return check_ssl(target, context=context)
