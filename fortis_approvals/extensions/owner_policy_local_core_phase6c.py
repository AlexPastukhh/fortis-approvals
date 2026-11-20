"""Phase 6C local Core-SQLite deny-only admission candidate.

Not installed in production, not imported by default runtime, no owner/machine
policy edit route and no privilege-expanding ALLOW. Uses unmodified pinned Core:
existing signed fingerprint, version check and pre-dispatch SQLite lock all
apply to the exact local policy revision through a virtual policy_version.
"""
from ..core import Core, Denied


class LocalDenyCore(Core):
    """Explicit opt-in Core subclass, same request SQLite DB, DENY-only.

    No method to alter the active revision or deny rules is provided. A future
    owner-only WebAuthn/apply ceremony must commit local changes atomically in
    this database; test fixtures can simulate them with direct SQL OFFLINE.
    """

    def __init__(self, *args, **kwargs):
        self._local_policy_initialized = False
        super().__init__(*args, **kwargs)
        with self._db() as db:
            existing = {row['name'] for row in db.execute(
                """SELECT name FROM sqlite_master WHERE type='table'
                   AND name LIKE 'owner_local_%'""")}
            required = {'owner_local_policy_meta', 'owner_local_denials',
                        'owner_local_policy_events'}
            if existing and existing != required:
                raise Denied('OWNER_LOCAL_POLICY_SCHEMA_INCOMPLETE')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS owner_local_policy_meta(
                    id INTEGER PRIMARY KEY CHECK(id=1),
                    schema_version INTEGER NOT NULL CHECK(schema_version=1),
                    revision INTEGER NOT NULL CHECK(revision>=0),
                    gate TEXT NOT NULL CHECK(gate IN ('READY','PREPARED'))
                );
                CREATE TABLE IF NOT EXISTS owner_local_denials(
                    actor TEXT NOT NULL, service TEXT NOT NULL,
                    operation TEXT NOT NULL, target TEXT NOT NULL,
                    decision TEXT NOT NULL CHECK(decision='DENY'),
                    PRIMARY KEY(actor,service,operation,target)
                );
                CREATE TABLE IF NOT EXISTS owner_local_policy_events(
                    request_id TEXT PRIMARY KEY,
                    at INTEGER NOT NULL,
                    owner TEXT NOT NULL,
                    change TEXT NOT NULL,
                    expected_revision INTEGER NOT NULL CHECK(expected_revision>=0),
                    applied_revision INTEGER NOT NULL CHECK(applied_revision>0)
                );
            ''')
            if not existing:
                db.execute("INSERT INTO owner_local_policy_meta VALUES(1,1,0,'READY')")
            self._local_revision(db)
        self._local_policy_initialized = True

    @property
    def policy_version(self):
        if not self._local_policy_initialized:
            return self._baseline_policy_version
        # Core holds BEGIN IMMEDIATE around admission/dispatch. A concurrent
        # writer to the SAME SQLite file cannot commit a newer revision until
        # that transaction has serialized its decision/dispatch marker.
        with self._db() as db:
            rev = self._local_revision(db)
        return self._baseline_policy_version + '|owner-local-deny:' + str(rev)

    @policy_version.setter
    def policy_version(self, value):
        # Base Core validates this trusted constructor argument.
        self._baseline_policy_version = value

    @staticmethod
    def _local_revision(db):
        rows = db.execute('SELECT * FROM owner_local_policy_meta').fetchall()
        if (len(rows) != 1 or rows[0]['id'] != 1 or
                rows[0]['schema_version'] != 1 or
                type(rows[0]['revision']) is not int or rows[0]['revision'] < 0 or
                rows[0]['gate'] != 'READY'):
            raise Denied('OWNER_LOCAL_POLICY_NOT_READY')
        return rows[0]['revision']

    def _policy(self, actor, payload):
        configured = super()._policy(actor, payload)
        if not self._local_policy_initialized:
            return configured
        # The store only imposes an exact DENY; it cannot create rights and
        # cannot promote an existing ASK to unattended ALLOW.
        with self._db() as db:
            self._local_revision(db)
            denied = db.execute('''SELECT 1 FROM owner_local_denials
                    WHERE actor=? AND service=? AND operation=? AND target=?''',
                    (actor,payload['service'],payload['operation'],
                     payload['target'])).fetchone()
        return 'DENY' if denied is not None else configured
