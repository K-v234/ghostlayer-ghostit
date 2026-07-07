
# Disk check — alert if over 70%
DISK_PCT=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_PCT" -gt 70 ]; then
    echo "$DATE | ⚠️ DISK WARNING: ${DISK_PCT}% used" >> $LOG
fi
