#!/bin/bash

set -e

trap 'echo "UPDATE FAILED at line $LINENO" >> /var/log/mihomo-generator.log' ERR

cd "$(dirname "$0")"

LOG=/var/log/mihomo-generator.log

echo "=== START UPDATE $(date) ===" >> "$LOG"

python3 -m src.providers.uploaded.provider >> "$LOG" 2>&1

python3 src/merge_providers.py >> "$LOG" 2>&1

python3 src/checker.py \
    cache/filtered/all.json \
    cache/filtered/available.json \
    cache/filtered/available.diagnostics.json >> "$LOG" 2>&1

cp cache/filtered/available.json cache/filtered/all.json

python3 src/merge_providers.py >> "$LOG" 2>&1

python3 src/generator.py \
    --proxies cache/filtered/all.json \
    --ru-direct domains:lists/ru_direct_domains.txt \
    --ru-direct ips:lists/ru_direct_ips.txt \
    --output publish/mihomo.yaml >> "$LOG" 2>&1

cp publish/mihomo.yaml publish/openclash.yaml

git add -f publish/mihomo.yaml publish/openclash.yaml

if git diff --cached --quiet; then
    echo "No changes" >> "$LOG"
else
    git commit -m "Auto-update Mihomo configs $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG" 2>&1
    git push >> "$LOG" 2>&1
fi

echo "=== UPDATE COMPLETE $(date) ===" >> "$LOG"

exit 0
