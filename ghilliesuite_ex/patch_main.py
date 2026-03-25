import sys
from pathlib import Path

p = Path('main.py')
text = p.read_text(encoding='utf-8')

replacements = [
    (
'''    screenshots: bool = typer.Option(
        False,
        "--screenshots",
        help="Enable gowitness screenshots during recon (optional).",
        is_flag=True,
    ),''',
'''    screenshots: bool = typer.Option(
        False,
        "--screenshots",
        help="Enable gowitness screenshots during recon (optional).",
        is_flag=True,
    ),
    proxy: Optional[str] = typer.Option(
        None,
        "--proxy", "-p",
        help="Global HTTP/SOCKS5 proxy for all tools (e.g. http://127.0.0.1:8080 or socks5://127.0.0.1:9050).",
        show_default=False,
    ),'''
    ),
    (
'''        cookie=cookie,
        header=header,
        screenshots=screenshots,''',
'''        cookie=cookie,
        header=header,
        proxy=proxy,
        screenshots=screenshots,'''
    ),
    (
'''    cookie: str | None,
    header: str | None,
    screenshots: bool = False,''',
'''    cookie: str | None,
    header: str | None,
    proxy: str | None = None,
    screenshots: bool = False,'''
    ),
    (
'''    if header:
        cfg.auth_header = header.strip()

    cfg.enable_screenshots = bool(screenshots)''',
'''    if header:
        cfg.auth_header = header.strip()
    if proxy:
        cfg.proxy = proxy.strip()

    cfg.enable_screenshots = bool(screenshots)'''
    )
]

for old, new in replacements:
    if old in text:
        text = text.replace(old, new)
        print('SUCCESS:', old.splitlines()[0][:30])
    else:
        print('FAILED TO FIND:', old.splitlines()[0][:30])

p.write_text(text, encoding='utf-8')
