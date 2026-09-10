#!/bin/sh
# Build the documentation site and publish it.
#
# Mirrors EasySYS-web/deploy.sh: build with mkdocs, replace what is served.
# Run it on the host that serves the site.
set -e

echo "Building the EasyWAF documentation site"
git pull
mkdocs build

TARGET=${1:-/var/www/easywaf}
rm -rf "$TARGET"
cp -r site "$TARGET"
echo "Deployed to $TARGET"
