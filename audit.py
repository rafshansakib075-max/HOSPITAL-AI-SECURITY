import hashlib
from datetime import datetime

from extensions import db
from models import AuditLog

GENESIS_HASH = "0" * 64


def _get_last_hash():
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    return last.curr_hash if last else GENESIS_HASH


def log_action(user, action, resource=None, ip_address=None):
    """Append a tamper-evident audit log entry.

    The hash chain (prev_hash -> curr_hash) means every entry cryptographically
    depends on the one before it. Editing or deleting a past row in the
    database will not update later rows' hashes, so verify_chain() can detect
    exactly where the log was tampered with.
    """
    prev_hash = _get_last_hash()
    timestamp = datetime.utcnow()
    username = user.username if user else "anonymous"
    user_id = user.id if user else None

    payload = f"{prev_hash}|{user_id}|{action}|{resource}|{ip_address}|{timestamp.isoformat()}"
    curr_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    entry = AuditLog(
        user_id=user_id,
        username_snapshot=username,
        action=action,
        resource=resource,
        ip_address=ip_address,
        timestamp=timestamp,
        prev_hash=prev_hash,
        curr_hash=curr_hash,
    )
    db.session.add(entry)
    db.session.commit()
    return entry


def verify_chain():
    """Walk the entire audit log and recompute each hash to confirm no entry
    has been altered or removed. Returns (is_valid, first_broken_id_or_None).
    """
    entries = AuditLog.query.order_by(AuditLog.id.asc()).all()
    prev_hash = GENESIS_HASH
    for entry in entries:
        payload = (
            f"{prev_hash}|{entry.user_id}|{entry.action}|{entry.resource}|"
            f"{entry.ip_address}|{entry.timestamp.isoformat()}"
        )
        expected_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if entry.prev_hash != prev_hash or entry.curr_hash != expected_hash:
            return False, entry.id
        prev_hash = entry.curr_hash
    return True, None
