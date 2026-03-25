import sys
from pathlib import Path

p = Path('waf_engine.py')
text = p.read_text(encoding='utf-8')

replacements = [
    (
'''    try:
        import requests as _requests
    except ImportError:
        return BypassResult(evidence="requests library not available")''',
'''    try:
        import curl_cffi.requests as _requests
    except ImportError:
        return BypassResult(evidence="curl_cffi library not available")'''
    ),
    (
'''        if '_verify_session' not in globals() or _verify_session is None:
            _verify_session = _requests.Session()
            _verify_session.verify = False''',
'''        if '_verify_session' not in globals() or _verify_session is None:
            _verify_session = _requests.Session(impersonate="chrome120")
            _verify_session.verify = False
            
            try:
                from ghilliesuite_ex.config import cfg as _cfg
                if getattr(_cfg, "proxy", None):
                    proxy_url = _cfg.proxy
                    _verify_session.proxies = {"http": proxy_url, "https": proxy_url}
            except Exception:
                pass'''
    )
]

for old, new in replacements:
    if old in text:
        text = text.replace(old, new)
        print('SUCCESS:', old.splitlines()[0][:30])
    else:
        print('FAILED TO FIND:', old.splitlines()[0][:30])

p.write_text(text, encoding='utf-8')
