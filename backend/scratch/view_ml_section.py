with open(r"C:\Users\window 11\.gemini\antigravity\scratch\apk_sentinel_ai\frontend\src\app\page.tsx", "r", encoding="utf-8") as f:
    content = f.read()

import re
matches = [m.start() for m in re.finditer("machine_learning", content)]

for idx in matches:
    # Print 20 lines before and after
    line_start_idx = idx
    for _ in range(15):
        line_start_idx = content.rfind("\n", 0, line_start_idx)
    line_end_idx = idx
    for _ in range(15):
        line_end_idx = content.find("\n", line_end_idx + 1)
    
    print("--- MATCH AT CHAR", idx, "---")
    print(content[line_start_idx:line_end_idx])
    print("---------------------------------")
