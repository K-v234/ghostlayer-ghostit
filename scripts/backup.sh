
#!/bin/bash

# Ghost IT — automated data backup (R-01)

# Backs up the real Docker volume data (Parquet events + all DuckDB

# state files) to a timestamped, compressed archive outside the

# volume itself. Keeps the last 7 days, deletes older ones.

set -euo pipefail



BACKUP_DIR="/home/ubuntu/ghostit-backups"

SOURCE_DIR="/var/lib/docker/volumes/ghostlayer_ghostit-data/_data"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)

ARCHIVE="$BACKUP_DIR/ghostit-data-$TIMESTAMP.tar.gz"



echo "[$(date)] Starting backup..."

sudo tar -czf "$ARCHIVE" -C "$SOURCE_DIR" .

echo "[$(date)] Backup written: $ARCHIVE ($(du -h "$ARCHIVE" | cut -f1))"



# Rotate: keep only the last 7 days of backups

find "$BACKUP_DIR" -name "ghostit-data-*.tar.gz" -mtime +7 -delete

echo "[$(date)] Rotation complete. Current backups:"

ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -10

