import sys
from pathlib import Path

# Add the project root to sys.path to import ghilliesuite_ex
sys.path.append(str(Path("c:/Users/Fauzan/Documents/GitHub/GhillieSuite-EX")))

from ghilliesuite_ex.waf_engine import _js_hex_function_obfuscation

test_payload = "alert(1)"
obfuscated = _js_hex_function_obfuscation(test_payload)
print(f"Original: {test_payload}")
print(f"Obfuscated: {obfuscated}")

expected = 'Function("\\x61\\x6c\\x65\\x72\\x74\\x28\\x31\\x29")()'
if obfuscated == expected:
    print("SUCCESS: Mutation works as expected!")
else:
    print(f"FAILURE: Expected {expected}, got {obfuscated}")
