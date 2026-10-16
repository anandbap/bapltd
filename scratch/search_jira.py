with open('JIRA_STORIES.md', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if any(w in line.lower() for w in ['4-layer', 'four-layer', 'epic 30', 'bap-540', 'layer a', 'layer b', 'layer c', 'layer 1', 'layer 2', 'layer 3', 'layer 4', 'layer 5']):
            cleaned = line.rstrip()[:120].encode('ascii', errors='replace').decode('ascii')
            print(f"{i}: {cleaned}")
