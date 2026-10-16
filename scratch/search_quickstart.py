with open('scripts/quickstart_vision_demo.py', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if any(w in line.lower() for w in ['layer', 'defense', 'pillar 9', '4-layer', 'four-layer']):
            cleaned = line.rstrip()[:120].encode('ascii', errors='replace').decode('ascii')
            print(f"{i}: {cleaned}")
