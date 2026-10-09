#!/bin/sh
# Publishes both SDKs at the version in js/package.json, if not already out.
#   Go:  pushes the tag go/v<version>, then asks the Go proxy to fetch it.
#   npm: publishes @waka/client.
# Needs GITHUB_TOKEN (contents: write on this repo) and NPM_TOKEN.
set -eu
cd "$(dirname "$0")/.."

V=$(node -p "require('./js/package.json').version")
TAG="go/v$V"
REMOTE="https://x-access-token:${GITHUB_TOKEN}@github.com/azukaar/waka-sdk.git"

if git ls-remote --exit-code --tags "$REMOTE" "refs/tags/$TAG" >/dev/null 2>&1; then
  echo "go: $TAG already tagged"
else
  git tag "$TAG"
  git push "$REMOTE" "refs/tags/$TAG"
  curl -fsS "https://proxy.golang.org/github.com/azukaar/waka-sdk/go/@v/v$V.info" || echo "go: proxy not ready yet, it will fetch on first use"
  echo "go: published $TAG"
fi

if npm view "@waka/client@$V" version >/dev/null 2>&1; then
  echo "npm: @waka/client@$V already published"
else
  echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
  (cd js && npm publish --access public)
  echo "npm: published @waka/client@$V"
fi
