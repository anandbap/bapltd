import os, glob

for root, dirs, files in os.walk('.'):
    if any(p in root for p in ['.git', '.bapstate', 'node_modules', 'dist', 'tmp']):
        continue
    for file in files:
        if file.endswith(('.bat', '.ps1', '.py', '.md')):
            path = os.path.join(root, file)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        if '4-layer' in line.lower() or 'four-layer' in line.lower() or '3-tier layer' in line.lower():
                            print(f"{path}:{i}: {line.strip()[:100]}")
            except Exception:
                pass
