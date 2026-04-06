import sys
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path("c:/Users/Fauzan/Documents/GitHub/GhillieSuite-EX")))

from ghilliesuite_ex.arsenal import build_command
from ghilliesuite_ex.config import cfg

# Mock config
cfg.auth_cookie = "session=test12345"

test_cases = [
    ("sqlmap", "https://example.com/api?id=1"),
    ("dalfox", "/tmp/targets.txt"),
    ("nuclei", "https://example.com"),
    ("httpx", "https://example.com"),
    ("katana", "https://example.com"),
]

for tool, target in test_cases:
    cmd = build_command(
        tool, target, 
        output_file="/tmp/out.json" if tool != "nuclei" else None,
        input_file="/tmp/in.txt" if tool in ("httpx", "arjun", "dnsx", "subzy", "gowitness") else None
    )
    joined = " ".join(cmd)
    print(f"Tool: {tool}")
    print(f"CMD: {joined}")
    
    # Assertions
    if tool == "sqlmap":
        assert "--cookie=session=test12345" in joined
    elif tool == "dalfox":
        assert "-C session=test12345" in joined
    elif tool in ("nuclei", "httpx", "katana"):
        assert "Cookie: session=test12345" in joined

print("\nSUCCESS: All cookie injections verified!")
