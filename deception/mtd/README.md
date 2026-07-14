# C3: Moving Target Deception
Owner: Keerthivahanan

# STATUS: 100% — code complete, verified July 13, 2026
## Files:
- rotator.py — DeceptionAsset rotation scheduling (HMAC-jittered), confirmed working
- topology_decoys.py — TopologyDecoyManager (ARP/mDNS flooding), confirmed logic works, needs `subprocess`-level network testing
- wireguard_announce.py — MTDAnnouncement over WireGuard, needs WireGuard interface (wg-ghostit) set up before live testing

## Deployment note:
Added to docker/Dockerfile.canary build July 13, 2026 (was previously
never copied into the container despite files existing and being
code-complete).
