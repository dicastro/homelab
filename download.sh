#!/bin/bash

# Configuration
REPO_NAME="homelab-ansible-playbooks"
BACKUP_PATHS=(".venv" "inventories/prod" "output" "playbooks/files/docker-config.json" ".vault-pass" "notes.md")
REPO_URL="https://github.com/dicastro/$REPO_NAME"
DEST_DIR="$(pwd)/$REPO_NAME"

# Create a temporary ZIP file using mktemp
TMP_TAR=$(mktemp --suffix=.tar.gz)
TMP_BACKUP=$(mktemp -d)

# Backup specified paths (files & folders)
for path in "${BACKUP_PATHS[@]}"; do
    full_path="$DEST_DIR/$path"
    
    if [[ -d "$full_path" ]]; then
        mkdir -p "$TMP_BACKUP/$path"  # Ensure full folder path exists
        cp -a "$full_path/." "$TMP_BACKUP/$path/"  # Copy folder contents recursively
    elif [[ -f "$full_path" ]]; then
        mkdir -p "$TMP_BACKUP/$(dirname "$path")"  # Ensure parent folder exists
        cp -a "$full_path" "$TMP_BACKUP/$path"  # Copy single file
    else
        echo "[WARNING] Skipping backup of missing path: $path"
    fi
done

# Ensure DEST_DIR exists and is empty
rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"

# Download the latest repository ZIP
curl -sL "${REPO_URL}/archive/refs/heads/main.tar.gz" -o "$TMP_TAR"

# Extract into DEST_DIR
tar -xzf "$TMP_TAR" -C "$DEST_DIR" --strip-components=1

# Restore backed-up paths
for path in "${BACKUP_PATHS[@]}"; do
    full_path="$DEST_DIR/$path"
    backup_path="$TMP_BACKUP/$path"

    if [[ -d "$backup_path" ]]; then
        mkdir -p "$full_path"
        cp -a "$backup_path/." "$full_path/"
    elif [[ -f "$backup_path" ]]; then
        mkdir -p "$(dirname "$full_path")"
        cp -a "$backup_path" "$full_path"
    else
        echo "[WARNING] Backup path does not exist: $path"
    fi
done

# Cleanup
rm -rf "$TMP_TAR" "$TMP_BACKUP"

echo "Repository downloaded and extracted to $DEST_DIR"
