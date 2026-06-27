import re

with open(r"C:\Users\window 11\.gemini\antigravity\scratch\apk_sentinel_ai\frontend\src\app\page.tsx", "r", encoding="utf-8") as f:
    content = f.read()

# Let's search for "online" or "model" or "status" in the file
online_matches = [m.start() for m in re.finditer("online", content, re.IGNORECASE)]
model_matches = [m.start() for m in re.finditer("online_model", content, re.IGNORECASE)]

print(f"Total 'online' occurrences: {len(online_matches)}")
print(f"Total 'online_model' occurrences: {len(model_matches)}")

# Let's print some lines containing online_model
for start_idx in model_matches[:5]:
    # find line start and end
    line_start = content.rfind("\n", 0, start_idx) + 1
    line_end = content.find("\n", start_idx)
    print(f"Line: {content[line_start:line_end].strip()}")
