with open('ARCHITECTURE.md', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if any(w in line.lower() for w in ['4-layer', 'four-layer', 'layer a', 'layer b', 'layer c', 'layer 1', 'layer 2', 'layer 3', 'layer 4', 'layer 5', 'defense-in-depth']):
            print(f"{i}: {line.rstrip()[:120]}")
