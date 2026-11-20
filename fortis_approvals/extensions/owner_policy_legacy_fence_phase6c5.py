"""Phase 6C.5 R7 fail-closed legacy startup guard (source-only).

Never delete/recreate/repair an existing Core DB. This guard only prevents a
*new* current R7 builder from ignoring local DENY tables by selecting plain
IncidentCore. It cannot stop already-running workers or old installed code.
"""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import stat

from ..core import Denied


def refuse_legacy_core_with_local_policy(root):
    """Read-only detect ANY local-policy schema before plain Core construction.

    Must run after the trusted private R7 state-root check and before any
    adapter or owner credential store construction. No SQLite schema writes,
    auto-migrations, backup restores, policy changes or network access.
    """
    path = Path(root) / 'approvals.sqlite'
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'existingCoreDb': False, 'legacyCoreAllowed': True}
    except (OSError, ValueError):
        raise Denied('R7_LOCAL_POLICY_DB_UNVERIFIABLE') from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            path.is_symlink()):
        raise Denied('R7_LOCAL_POLICY_DB_UNVERIFIABLE')
    try:
        # mode=ro cannot create a replacement database if backup/volume is
        # missing or permission denied. Query schema; NEVER infer no policies
        # from a failed read or malformed/torn DB.
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
            db.execute('PRAGMA query_only = ON')
            suspect = db.execute(
                "SELECT name FROM sqlite_master WHERE name GLOB 'owner_local_*' "
                "LIMIT 1").fetchone()
    except (sqlite3.Error, OSError, ValueError):
        raise Denied('R7_LOCAL_POLICY_DB_UNVERIFIABLE') from None
    if suspect is not None:
        raise Denied('R7_LEGACY_CORE_LOCAL_DENY_BYPASS_FORBIDDEN')
    return {'existingCoreDb': True, 'legacyCoreAllowed': True}
