import sys
from pathlib import Path

p = Path('arsenal.py')
text = p.read_text(encoding='utf-8')

replacements = [
    (
'''    if extra_args:
        cmd.extend(extra_args)

    if tool_name == "nuclei":''',
'''    if extra_args:
        cmd.extend(extra_args)

    # Inject global proxy if configured
    try:
        from ghilliesuite_ex.config import cfg as _cfg
        if _cfg.proxy:
            proxy_str = _cfg.proxy
            if tool_name == "httpx":
                cmd.extend(["-http-proxy", proxy_str])
            elif tool_name in ("nuclei", "katana"):
                cmd.extend(["-proxy", proxy_str])
            elif tool_name in ("sqlmap", "dalfox"):
                cmd.extend(["--proxy", proxy_str])
            elif tool_name == "ffuf":
                cmd.extend(["-x", proxy_str])
    except Exception:
        pass

    if tool_name == "nuclei":'''
    )
]

for old, new in replacements:
    if old in text:
        text = text.replace(old, new)
        print('SUCCESS:', old.splitlines()[0][:30])
    else:
        print('FAILED TO FIND:', old.splitlines()[0][:30])

p.write_text(text, encoding='utf-8')
