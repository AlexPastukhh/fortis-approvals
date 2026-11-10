"""Gateway-owned durable artifact, task and worker job records."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import time
from .error_diagnostics import evidence
import uuid
from ..core import Conflict, Denied, canonical
from .common import secure_dir, require


class Store:
    def __init__(self, root):
        self.root=secure_dir(root);self.artifacts=secure_dir(self.root/'artifacts');self.visual_media=secure_dir(self.root/'visual-media')
        self.path=self.root/'workflow.sqlite'
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        require(not self.path.is_symlink() and self.path.stat().st_uid==os.geteuid() and
                self.path.stat().st_mode & 0o777==0o600,'WORKFLOW_STORE_PERMISSIONS')
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS artifacts(actor TEXT,digest TEXT,metadata TEXT,PRIMARY KEY(actor,digest));
                CREATE TABLE IF NOT EXISTS visual_media(request_id TEXT,actor TEXT,repo TEXT,run_id TEXT,idx INTEGER,sha TEXT,size INTEGER,name TEXT,PRIMARY KEY(request_id,idx));
                CREATE TABLE IF NOT EXISTS tasks(actor TEXT,repo TEXT,task TEXT,data TEXT,PRIMARY KEY(actor,repo,task));
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,actor TEXT,payload TEXT,state TEXT,claim TEXT,result TEXT,error TEXT);
            """)
            columns={r[1] for r in db.execute('PRAGMA table_info(jobs)')}
            for name,kind in (('claimed_at','INTEGER'),('heartbeat_at','INTEGER'),
                              ('diagnostic','TEXT')):
                if name not in columns:
                    db.execute('ALTER TABLE jobs ADD COLUMN '+name+' '+kind)

    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=10);db.row_factory=sqlite3.Row;db.execute('PRAGMA synchronous=FULL')
        try:
            with db:yield db
        finally:db.close()

    def task(self,actor,repo,task):
        with self.db() as db:row=db.execute('SELECT data FROM tasks WHERE actor=? AND repo=? AND task=?',(actor,repo,task)).fetchone()
        require(row is not None,'WORKFLOW_TASK_NOT_REGISTERED');return json.loads(row[0])

    def register(self,actor,repo,task,value):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT data FROM tasks WHERE actor=? AND repo=? AND task=?',(actor,repo,task)).fetchone()
            if row:
                previous=json.loads(row[0]);previous.pop('closed',None)
                if canonical(previous)!=canonical(value):raise Conflict('WORKFLOW_TASK_CONFLICT')
            else:db.execute('INSERT INTO tasks VALUES(?,?,?,?)',(actor,repo,task,canonical(value)))

    def close_task(self,actor,repo,task):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT data FROM tasks WHERE actor=? AND repo=? AND task=?',(actor,repo,task)).fetchone()
            require(row is not None,'WORKFLOW_TASK_NOT_REGISTERED')
            value=json.loads(row[0]);value['closed']=True
            db.execute('UPDATE tasks SET data=? WHERE actor=? AND repo=? AND task=?',(canonical(value),actor,repo,task))

    def stage_visual_png(self,actor,request_id,repo,run_id,index,name,digest,data):
        import hashlib
        import re
        from ..core import Denied
        require(repo=='visual-workspace' and type(run_id) is str and
                re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}',run_id) and
                type(request_id) is str and str(uuid.UUID(request_id))==request_id and
                type(index) is int and 0<=index<5 and
                type(name) is str and 1<=len(name)<=120 and
                type(digest) is str and re.fullmatch(r'[0-9a-f]{64}',digest) and
                type(data) is bytes and 24<=len(data)<=10*1024*1024 and
                data.startswith(b'\x89PNG\r\n\x1a\n') and data[12:16]==b'IHDR' and
                hashlib.sha256(data).hexdigest()==digest,'VISUAL_MEDIA_INVALID')
        file=self.visual_media/(request_id+'-'+str(index)+'-'+digest+'.png')
        meta=(request_id,actor,repo,run_id,index,digest,len(data),name)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT request_id,actor,repo,run_id,idx,sha,size,name FROM visual_media WHERE request_id=? AND idx=?',(request_id,index)).fetchone()
            require(row is None or tuple(row)==meta,'VISUAL_MEDIA_CONFLICT')
            if file.exists():
                require(not file.is_symlink() and hashlib.sha256(file.read_bytes()).hexdigest()==digest,'VISUAL_MEDIA_CHANGED')
            else:
                fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
            db.execute('INSERT OR IGNORE INTO visual_media VALUES(?,?,?,?,?,?,?,?)',meta)
        return dict(index=index,sha256=digest,size=len(data),name=name)

    def visual_png(self,actor,request_id,repo,run_id,item):
        import hashlib
        with self.db() as db:
            row=db.execute('SELECT actor,repo,run_id,sha,size,name FROM visual_media WHERE request_id=? AND idx=?',
                           (request_id,item['index'])).fetchone()
        require(row is not None and tuple(row)==(actor,repo,run_id,item['sha256'],item['size'],item['name']),
                'VISUAL_MEDIA_BINDING_INVALID')
        file=self.visual_media/(request_id+'-'+str(item['index'])+'-'+item['sha256']+'.png')
        require(file.is_file() and not file.is_symlink() and file.stat().st_size==item['size'],
                'VISUAL_MEDIA_MISSING')
        data=file.read_bytes()
        require(hashlib.sha256(data).hexdigest()==item['sha256'],'VISUAL_MEDIA_CHANGED')
        return data

    def artifact(self,actor,ident):
        with self.db() as db:row=db.execute('SELECT metadata FROM artifacts WHERE actor=? AND digest=?',(actor,ident)).fetchone()
        require(row is not None,'WORKFLOW_ARTIFACT_UNAVAILABLE')
        return json.loads(row[0])

    def save_artifact(self,actor,ident,metadata):
        with self.db() as db:
            row=db.execute('SELECT metadata FROM artifacts WHERE actor=? AND digest=?',(actor,ident)).fetchone()
            if row and row[0]!=canonical(metadata):raise Conflict('WORKFLOW_ARTIFACT_CONFLICT')
            db.execute('INSERT OR IGNORE INTO artifacts VALUES(?,?,?)',(actor,ident,canonical(metadata)))

    def enqueue(self,actor,payload):
        with self.db() as db:
            row=db.execute('SELECT actor,payload FROM jobs WHERE id=?',(payload['requestId'],)).fetchone()
            if row and tuple(row)!=(actor,canonical(payload)):raise Conflict('WORKFLOW_JOB_CONFLICT')
            db.execute("INSERT OR IGNORE INTO jobs(id,actor,payload,state,claim,result,error) "
                       "VALUES(?,?,?,'QUEUED',NULL,NULL,NULL)",
                       (payload['requestId'],actor,canonical(payload)))

    def claim(self,actor,ident):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM jobs WHERE id=? AND actor=?',(ident,actor)).fetchone()
            if row is None:return None
            # An existing claim is owned by its original executor. Re-delivery
            # of its token/payload could replay an unjournaled partial effect.
            if row['state']=='CLAIMED':return dict(state='CLAIMED')
            if row['state']!='QUEUED':return dict(state=row['state'])
            claim=str(uuid.uuid4())
            db.execute("UPDATE jobs SET state='CLAIMED',claim=?,claimed_at=? WHERE id=?",
                       (claim,int(time.time()),ident))
            return dict(state='CLAIMED',claim=claim,payload=json.loads(row['payload']))

    def heartbeat(self,actor,ident,claim):
        """Best-effort claim-token-bound observation, never a claim renewal.

        Does not authorize a replay, release, cancellation or new executor.
        """
        require(type(claim) is str and len(claim)==36,'WORKFLOW_CLAIM_INVALID')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            updated=db.execute("UPDATE jobs SET heartbeat_at=? WHERE id=? AND actor=? "
                               "AND claim=? AND state='CLAIMED'",
                               (int(time.time()),ident,actor,claim)).rowcount
            require(updated==1,'WORKFLOW_HEARTBEAT_CLAIM_INVALID')

    def activity(self,actor,*,offset=0,limit=100):
        """Actor-only snapshot. Stale/missing heartbeat is not quiescence proof."""
        require(type(offset) is int and 0<=offset<=1000000 and
                type(limit) is int and 1<=limit<=100,'WORKFLOW_ACTIVITY_PAGINATION_INVALID')
        now=int(time.time())
        with self.db() as db:
            db.execute('BEGIN')
            counts=dict(db.execute("SELECT state,COUNT(*) FROM jobs WHERE actor=? "
                                   "AND state IN ('QUEUED','CLAIMED') GROUP BY state",(actor,)))
            rows=db.execute("SELECT id,state,claimed_at,heartbeat_at FROM jobs "
                            "WHERE actor=? AND state IN ('QUEUED','CLAIMED') "
                            "ORDER BY id DESC LIMIT ? OFFSET ?",(actor,limit,offset)).fetchall()
        items=[]
        for r in rows:
            at=r['heartbeat_at']
            if r['state']=='QUEUED':signal='NOT_CLAIMED'
            elif at is None:signal='NO_HEARTBEAT_UNCONFIRMED'
            elif 0<=now-at<=30:signal='RECENT_HEARTBEAT_UNCONFIRMED'
            else:signal='STALE_HEARTBEAT_UNCONFIRMED'
            items.append(dict(requestId=r['id'],jobState=r['state'],
                              claimedAt=r['claimed_at'],lastHeartbeatAt=at,
                              signal=signal))
        total=sum(counts.values())
        next_offset=offset+len(items) if offset+len(items)<total else None
        return dict(schemaVersion=1,observedAt=now,total=total,
                    queued=counts.get('QUEUED',0),claimed=counts.get('CLAIMED',0),
                    offset=offset,limit=limit,items=items,
                    truncated=next_offset is not None,nextOffset=next_offset,
                    quiescenceProven=False)

    def finish(self,actor,ident,claim,result,error,diagnostic=None):
        require(error in (None,'STALE','UNCERTAIN') and (error is not None or type(result) is dict),'WORKFLOW_COMPLETION_INVALID')
        require(diagnostic is None or (error=='UNCERTAIN' and type(diagnostic) is dict and
                set(diagnostic)=={'stage','code'} and evidence(diagnostic['stage'],diagnostic['code'])==diagnostic),
                'WORKFLOW_DIAGNOSTIC_INVALID')
        encoded_diagnostic=canonical(diagnostic) if diagnostic is not None else None
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM jobs WHERE id=? AND actor=?',(ident,actor)).fetchone()
            require(row and row['claim']==claim and row['state'] in ('CLAIMED','DONE','FAILED'),'WORKFLOW_CLAIM_INVALID')
            encoded=canonical(result)
            if row['state'] in ('DONE','FAILED'):
                if row['result']!=encoded or row['error']!=error or row['diagnostic']!=encoded_diagnostic:
                    raise Conflict('WORKFLOW_COMPLETION_CONFLICT')
                return
            db.execute('UPDATE jobs SET state=?,result=?,error=?,diagnostic=? WHERE id=?',
                       ('FAILED' if error else 'DONE',encoded,error,encoded_diagnostic,ident))

    def job(self,ident):
        with self.db() as db:row=db.execute('SELECT * FROM jobs WHERE id=?',(ident,)).fetchone()
        return dict(row) if row else None
