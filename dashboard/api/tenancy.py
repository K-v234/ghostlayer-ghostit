#!/usr/bin/env python3
"""
Ghost IT — V1.5: Multi-Tenant Access Model
Maps users to customers, and provides the filtering logic that scopes
every dashboard query to only the calling customer's data. Previously
the dashboard treated all data as one undifferentiated pool (single
hardcoded admin user, no customer_id anywhere in the actual alert/
incident/event data flow -- only in DPDP compliance endpoints).

Design: each customer is identified by their agents' machine identity
(source_ip, per the source_ip tagging built July 12) OR an explicit
per-agent customer_id tag (cleaner long-term, agent-side change).
For now, uses a simple IP-range-to-customer mapping as the pragmatic
V1.5 approach -- doesn't require touching agent code, works with what
already exists.
"""
import bcrypt
import json
import os
import logging

log = logging.getLogger(__name__)

TENANCY_CONFIG_PATH = os.environ.get("TENANCY_CONFIG_PATH",
    os.path.expanduser("~/ghostlayer/data/tenancy.json"))

# Structure:
# {
#   "users": {"username": {"password_hash": "...", "customer_id": "..."}},
#   "customers": {
#     "customer_id": {
#       "name": "Display Name",
#       "ip_ranges": ["10.0.0.0/24", "192.168.1.0/24"],  # which source_ips belong to this customer
#     }
#   }
# }

_DEFAULT_CONFIG = {
    "users": {
        "admin": {
            "password_hash": bcrypt.hashpw(b"ghostit-admin-2026", bcrypt.gensalt()).decode(),
            "customer_id": "_all_",  # special value: super-admin, sees everything
        }
    },
    "customers": {
        "_all_": {"name": "Ghost Layer Internal (all data)", "ip_ranges": []}
    }
}

def load_tenancy_config() -> dict:
    if not os.path.exists(TENANCY_CONFIG_PATH):
        os.makedirs(os.path.dirname(TENANCY_CONFIG_PATH), exist_ok=True)
        with open(TENANCY_CONFIG_PATH, "w") as f:
            json.dump(_DEFAULT_CONFIG, f, indent=2)
        return _DEFAULT_CONFIG
    with open(TENANCY_CONFIG_PATH) as f:
        return json.load(f)

def save_tenancy_config(config: dict):
    os.makedirs(os.path.dirname(TENANCY_CONFIG_PATH), exist_ok=True)
    with open(TENANCY_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def get_customer_id_for_user(username: str) -> str | None:
    config = load_tenancy_config()
    user = config["users"].get(username)
    return user["customer_id"] if user else None

def ip_in_range(ip: str, cidr: str) -> bool:
    """Simple IPv4 CIDR check without needing the ipaddress module's
    full complexity -- good enough for the common /24, /16 cases."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False

def filter_events_by_customer(events: list[dict], customer_id: str) -> list[dict]:
    """Scope a list of events/alerts to only those belonging to the
    given customer. customer_id='_all_' bypasses filtering entirely
    (super-admin/internal use)."""
    if customer_id == "_all_":
        return events
    config = load_tenancy_config()
    customer = config["customers"].get(customer_id)
    if not customer:
        return []  # unknown customer, no data
    ip_ranges = customer.get("ip_ranges", [])
    if not ip_ranges:
        return []  # customer configured but no IP ranges assigned yet
    filtered = []
    for e in events:
        src_ip = e.get("source_ip", "")
        if not src_ip:
            continue
        if any(ip_in_range(src_ip, cidr) for cidr in ip_ranges):
            filtered.append(e)
    return filtered

def add_customer(customer_id: str, name: str, ip_ranges: list[str]):
    config = load_tenancy_config()
    config["customers"][customer_id] = {"name": name, "ip_ranges": ip_ranges}
    save_tenancy_config(config)
    log.info(f"Added customer: {customer_id} ({name}), ranges: {ip_ranges}")

def add_user(username: str, password: str, customer_id: str):
    config = load_tenancy_config()
    config["users"][username] = {
        "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        "customer_id": customer_id,
    }
    save_tenancy_config(config)
    log.info(f"Added user: {username} -> customer {customer_id}")
