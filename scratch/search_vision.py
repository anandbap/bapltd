with open('VISION.md', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if any(w in line.lower() for w in ['layer', 'plane 2', 'plane 3', 'pillar 9', 'defense-in-depth']):
            cleaned = line.rstrip()[:120].encode('ascii', errors='replace').decode('ascii')
            print(f"{i}: {cleaned}")
