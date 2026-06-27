with open(r"C:\Users\window 11\.gemini\antigravity\scratch\apk_sentinel_ai\frontend\src\app\page.tsx", "r", encoding="utf-8") as f:
    content = f.read()

import re
matches = [m.start() for m in re.finditer("machine_learning", content)]
print(f"Total 'machine_learning' occurrences: {len(matches)}")
for idx in matches[:5]:
    line_start = content.rfind("\n", 0, idx) + 1
    line_end = content.find("\n", idx)
    print(f"Line: {content[line_start:line_end].strip()}")

matches_xgb = [m.start() for m in re.finditer("xgboost", content, re.IGNORECASE)]
print(f"Total 'xgboost' occurrences: {len(matches_xgb)}")
for idx in matches_xgb[:5]:
    line_start = content.rfind("\n", 0, idx) + 1
    line_end = content.find("\n", idx)
    print(f"Line: {content[line_start:line_end].strip()}")

matches_ml = [m.start() for m in re.finditer("ML Detection", content)]
print(f"Total 'ML Detection' occurrences: {len(matches_ml)}")
for idx in matches_ml[:5]:
    line_start = content.rfind("\n", 0, idx) + 1
    line_end = content.find("\n", idx)
    print(f"Line: {content[line_start:line_end].strip()}")
