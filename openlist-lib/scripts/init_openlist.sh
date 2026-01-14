#!/bin/bash

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENLIST_LIB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Working in: $OPENLIST_LIB_DIR"

GIT_REPO="https://github.com/OpenListTeam/OpenList.git"
TAG_NAME=$(git -c 'versionsort.suffix=-' ls-remote --exit-code --refs --sort='version:refname' --tags $GIT_REPO | tail -n 1 | cut -d'/' -f3)

echo "OpenList - ${TAG_NAME}"

cd "$OPENLIST_LIB_DIR"

# Clean up any previous source
rm -rf ./src

unset GIT_WORK_TREE
git clone --branch "$TAG_NAME" https://github.com/OpenListTeam/OpenList.git ./src
rm -rf ./src/.git

echo "Checking cloned source structure:"
ls -la ./src/

# Copy go.mod and go.sum from OpenList source
if [ -f ./src/go.mod ]; then
    cp ./src/go.mod ./go.mod
    cp ./src/go.sum ./go.sum 2>/dev/null || true
    
    # Keep module name as OpenList but add our openlistlib as local package
    # The openlistlib directory already exists in this repo
    go mod edit -replace github.com/djherbis/times@v1.6.0=github.com/jing332/times@latest
    
    # Copy required internal packages from OpenList source
    echo "Copying required internal packages..."
    mkdir -p ./internal
    cp -r ./src/internal/* ./internal/ 2>/dev/null || true
    
    mkdir -p ./pkg
    cp -r ./src/pkg/* ./pkg/ 2>/dev/null || true
    
    # Also copy the cmd folder if needed for bootstrap
    mkdir -p ./cmd
    cp -r ./src/cmd/* ./cmd/ 2>/dev/null || true
    
    echo "OpenList source initialization completed"
    echo "go.mod location: $(pwd)/go.mod"
    
    # Show the module name
    echo "Module name:"
    head -1 ./go.mod
else
    echo "Error: go.mod not found in cloned source"
    exit 1
fi

# Download dependencies
echo "Downloading Go dependencies..."
go mod download
go mod tidy

echo "Initialization complete!"
echo ""
echo "Directory structure:"
ls -la
