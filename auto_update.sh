#!/bin/bash
set -e

export PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin

cd /root/Mihomo-SubPool

echo "========================================"
echo "MIHOMO AUTO UPDATE"
echo "========================================"
echo "Started: $(date)"

./update.sh

echo
echo "Checking generated YAML..."

test -s publish/mihomo.yaml
test -s publish/openclash.yaml

echo "YAML files OK"

mkdir -p site

cp publish/mihomo.yaml site/mihomo.yaml
cp publish/openclash.yaml site/openclash.yaml

echo "GitHub Pages files updated"

echo "Checking secrets..."

# WARP private-key is allowed inside generated mihomo/openclash configs.
# Block only accidental secret files and raw key dumps.

if find publish -type f \
    ! -name "mihomo.yaml" \
    ! -name "openclash.yaml" \
    -exec grep -l "private-key\\|private_key\\|secret" {} \; | grep .; then
    echo "ERROR: Secret data detected in unexpected publish file!"
    exit 1
fi

if find publish -type f \(     -name "*.json"     -o -name "*.txt"     -o -name "*.key" \) | grep .; then
    echo "ERROR: Suspicious secret file in publish!"
    exit 1
fi

echo "No unexpected secrets detected"

git add -f publish/mihomo.yaml publish/openclash.yaml

if git diff --cached --quiet; then
    echo "No changes to publish."
else
    git commit -m "Auto-update Mihomo configs: $(date '+%Y-%m-%d %H:%M:%S')"
    git push origin main
    echo "GitHub push completed."
fi

echo "Finished: $(date)"
echo "========================================"
