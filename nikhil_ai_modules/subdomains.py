"""Passive certificate-transparency enumeration with strict scope filtering."""
from __future__ import annotations

import json
from nikhil_ai_modules.context import resolve_context
from nikhil_ai_modules.output import good, header, info, section, warn
from nikhil_ai_modules.scope import ScopeError, normalize_host


def _seed_is_authorized_for_passive_query(domain: str, context) -> bool:
    if context.scope.is_in_scope(domain):
        return True
    # A wildcard rule may authorize passive enumeration for its apex as a query
    # seed only. The apex itself is never probed unless it also matches scope.
    wildcard_covers = any(rule == f"*.{domain}" for rule in context.scope.in_scope)
    return wildcard_covers and not any(context.scope._matches(domain, rule) for rule in context.scope.exclusions)


def _crtsh_names(domain: str, context):
    url = "https://crt.sh/"
    response = context.http.get(
        url,
        params={"q": f"%.{domain}", "output": "json"},
        purpose="passive_source",
        timeout=min(15.0, float(context.config.get("timeout", 6.0)) + 6),
    )
    if response.status_code != 200:
        raise RuntimeError(f"crt.sh returned HTTP {response.status_code}")
    try:
        rows = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("crt.sh response was not valid JSON") from exc
    names = set()
    for row in rows[:5000] if isinstance(rows, list) else []:
        value = str(row.get("name_value", ""))
        for name in value.splitlines():
            normalized = name.strip().lower().lstrip("*.").rstrip(".")
            try:
                names.add(normalize_host(normalized))
            except ValueError:
                continue
    return sorted(names)[:500]


def enumerate_subdomains(domain, context=None, *, use_ct: bool = False, max_probes: int = 50):
    ctx = resolve_context(context)
    seed = normalize_host(str(domain).strip().lstrip("*."))
    if not _seed_is_authorized_for_passive_query(seed, ctx):
        raise ScopeError(f"Enumeration seed {seed} is not covered by the current scope")
    # The base domain may be a passive query seed for a wildcard allow rule,
    # but any active request still passes the normal target Scope Guard.
    names = {seed}
    source = "scope seed"
    if use_ct:
        info("Querying crt.sh certificate-transparency metadata (passive source; target results remain scope-filtered).")
        names.update(_crtsh_names(seed, ctx))
        source = "crt.sh certificate transparency"

    rows = []
    skipped = 0
    for candidate in sorted(names)[:max(1, min(int(max_probes), 100))]:
        if not ctx.scope.is_in_scope(candidate):
            skipped += 1
            continue
        try:
            addresses = ctx.scope.validate_host(candidate, resolve=True)
            url = f"https://{candidate}/"
            try:
                response = ctx.http.head(url)
            except Exception:
                url = f"http://{candidate}/"
                response = ctx.http.head(url)
            if response.status_code in (405, 501):
                response = ctx.http.get(url)
            status = "LIVE" if 200 <= response.status_code < 400 else str(response.status_code)
            row = {"host": candidate, "status": status, "http_status": response.status_code, "addresses": addresses, "source": source}
        except Exception as exc:
            row = {"host": candidate, "status": "DEAD", "error": str(exc)[:250], "source": source}
        rows.append(row)

    header("Passive Subdomain Enumeration")
    section("Scope-filtered Results")
    print(f"{'Subdomain':<42}Status")
    print("-" * 60)
    for row in rows:
        print(f"{row['host']:<42}{row['status']}")
    info(f"Skipped {skipped} discovered name(s) because they were outside explicit scope.")
    return {
        "seed": seed,
        "source": source,
        "subdomains": rows,
        "assets": [{"host": row["host"], "status": row["status"], "source": source} for row in rows],
        "potential_findings": [],
    }
