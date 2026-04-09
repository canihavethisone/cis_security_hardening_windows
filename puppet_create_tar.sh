#!/bin/bash

# 1. Validate JSON first
python3 -m json.tool metadata.json > /dev/null || { echo "Invalid metadata.json syntax"; exit 1; }

# 2. Distill name and version
RAW_NAME=$(grep '"name":' metadata.json | head -1 | cut -d'"' -f4 | tr '/' '-')
VERSION=$(grep '"version":' metadata.json | head -1 | cut -d'"' -f4)
RELEASE_NAME="${RAW_NAME}-${VERSION}"

echo "Building release: ${RELEASE_NAME}"

# 3. Create the "Native Style" tarball
mkdir -p ./pkg
tar -cvzf "./pkg/${RELEASE_NAME}.tar.gz" --format=ustar --owner=1000 --group=1000 --numeric-owner --transform "s|^|${RELEASE_NAME}/|" manifests/ files/ lib/ data/ hiera.yaml metadata.json

echo "Archive created: ./pkg/${RELEASE_NAME}.tar.gz"
