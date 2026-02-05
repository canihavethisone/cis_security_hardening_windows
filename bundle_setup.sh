#!/bin/bash
set -euo pipefail

echo "Working dir: $(pwd)"

# Ensure we're in a Bundler project
if [[ ! -f Gemfile ]]; then
  echo "Error: Gemfile not found in $(pwd)" >&2
  exit 1
fi

# Configure Bundler to install gems locally
bundle config set path 'vendor/bundle'

# Clean previous install
rm -rf vendor

# Install dependencies
bundle install
