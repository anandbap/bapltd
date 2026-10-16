with open('bap-controlplane/internal/dashboardui/web/index.html', 'r', encoding='utf-8') as f:
    for i, line in enumerate(f, 1):
        if 'layers' in line.lower() or 'l1' in line.lower() or 'four-layer' in line.lower() or '3-tier' in line.lower() or 'funnel' in line.lower():
            print(f"{i}: {line.rstrip()[:120]}")
