import re
from pathlib import Path

for file_path in ['agents/exploit.py', 'agents/recon.py']:
    p = Path(file_path)
    if not p.exists(): continue
    text = p.read_text(encoding='utf-8')
    
    # We want to import cfg at the top of these files if not already there
    if 'from ghilliesuite_ex.config import cfg' not in text:
        text = text.replace('import asyncio', 'import asyncio\nfrom ghilliesuite_ex.config import cfg')
        
    # Replace requests import with curl_cffi
    text = text.replace('import requests', 'import curl_cffi.requests as requests')
    
    # Inject proxies into requests.get
    proxy_kwarg = 'proxies={"http": getattr(cfg, "proxy", None), "https": getattr(cfg, "proxy", None)} if getattr(cfg, "proxy", None) else None'
    
    # Add impersonalization to GET requests
    proxy_kwarg += ', impersonate="chrome120"'
    
    # Only replace if not already replaced
    if 'impersonate="chrome120"' not in text:
        text = re.sub(r'requests\.get\((?!.*impersonate)', f'requests.get({proxy_kwarg}, ', text)
        text = re.sub(r'requests\.post\((?!.*impersonate)', f'requests.post({proxy_kwarg}, ', text)
        text = re.sub(r'requests\.Session\((?!.*impersonate)', f'requests.Session({proxy_kwarg}, ', text)
        print(f'Patched {file_path}')
        p.write_text(text, encoding='utf-8')
