#!/bin/bash

set -e

trap 'echo "UPDATE FAILED at line $LINENO" >> /var/log/mihomo-generator.log' ERR

cd "$(dirname "$0")"

LOG=/var/log/mihomo-generator.log

echo "=== START UPDATE $(date) ===" >> "$LOG"

mkdir -p cache/imported

rm -f cache/imported/raw_proxies.txt
rm -f cache/imported/proxies.json

python3 src/importer.py \
    cache/imported/raw_proxies.txt >> "$LOG" 2>&1

python3 src/parser.py \
    cache/imported/raw_proxies.txt \
    cache/imported/proxies.json >> "$LOG" 2>&1

python3 -m src.providers.uploaded.provider >> "$LOG" 2>&1

python3 -m src.merge_providers >> "$LOG" 2>&1

python3 src/checker.py \
    cache/filtered/all.json \
    cache/filtered/available.json \
    cache/filtered/available.diagnostics.json >> "$LOG" 2>&1

# --- YouTube second stage: keep only nodes that can reach YouTube, sorted by ping ---
python3 src/checker_youtube.py \
    cache/filtered/available.json \
    cache/filtered/youtube.json \
    cache/filtered/youtube.diagnostics.json >> "$LOG" 2>&1

YT_COUNT=$(python3 -c "import json;print(len(json.load(open('cache/filtered/youtube.json', encoding='utf-8'))))")
echo "YouTube-passing nodes: $YT_COUNT" >> "$LOG"
if [ "$YT_COUNT" -lt 5 ]; then
    echo "ERROR: YouTube check produced only $YT_COUNT nodes - aborting to keep previous publish" | tee -a "$LOG"
    exit 1
fi

cp cache/filtered/youtube.json cache/filtered/all.json

python3 src/generator.py \
    --proxies cache/filtered/all.json \
    --output publish/mihomo.yaml >> "$LOG" 2>&1
python3 src/export_subscription.py publish/mihomo.yaml publish/subscription.txt >> "$LOG" 2>&1

echo "=== FINAL MIHOMO CONFIG VALIDATION ===" >> "$LOG"

if ! ./bin/mihomo -t -f publish/mihomo.yaml >> "$LOG" 2>&1; then
    echo "ERROR: Generated Mihomo config failed validation" | tee -a "$LOG"
    echo "ERROR: Git push aborted" | tee -a "$LOG"
    exit 1
fi

echo "=== MIHOMO CONFIG VALIDATION PASSED ===" >> "$LOG"

cp publish/mihomo.yaml publish/openclash.yaml

git add -f publish/mihomo.yaml publish/openclash.yaml publish/subscription.txt

if git diff --cached --quiet; then
    echo "No changes" >> "$LOG"
else
    git commit -m "Auto-update Mihomo configs $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG" 2>&1
    git push >> "$LOG" 2>&1
fi

echo "=== UPDATE COMPLETE $(date) ===" >> "$LOG"

exit 0
