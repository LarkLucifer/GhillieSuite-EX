import sys

file_path = 'ghilliesuite_ex/arsenal.py'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

target = """            cmd = _apply_nuclei_tuning(
                cmd,
                rate_limit=getattr(_cfg, "nuclei_rate_limit", None),
                concurrency=getattr(_cfg, "nuclei_concurrency", None),
                http_timeout=getattr(_cfg, "nuclei_http_timeout", None),
                severity=_sev,
                tags=_tags,
            )"""

replacement = """            _rate_limit = getattr(_cfg, "nuclei_rate_limit", None)
            _concurrency = getattr(_cfg, "nuclei_concurrency", None)
            _fast_nuclei = getattr(_cfg, "fast_nuclei", False)

            if _fast_nuclei:
                _rate_limit = int(_rate_limit) * 5 if _rate_limit else 500
                _concurrency = int(_concurrency) * 3 if _concurrency else 50
                if "-ni" not in cmd:
                    cmd.append("-ni")

            cmd = _apply_nuclei_tuning(
                cmd,
                rate_limit=_rate_limit,
                concurrency=_concurrency,
                http_timeout=getattr(_cfg, "nuclei_http_timeout", None),
                severity=_sev,
                tags=_tags,
            )"""

if target in content:
    content = content.replace(target, replacement)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Success")
else:
    print("Target not found.")
