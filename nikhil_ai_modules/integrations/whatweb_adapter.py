"""WhatWeb-compatible indicators using the central native scoped probe."""
from nikhil_ai_modules.tech_detect import detect_technology


def inspect(context, target):
    return detect_technology(target, context=context)
