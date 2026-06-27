with open("C:/Users/window 11/.gemini/antigravity/scratch/apk_sentinel_ai/frontend/src/app/page.tsx", "r", encoding="utf-8") as f:
    content = f.read()

lines = content.split("\n")
for i, line in enumerate(lines):
    if "ResponsiveContainer" in line:
        print(f"L{i+1}: {line.strip()}")
