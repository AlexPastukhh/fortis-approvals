"""Gateway-owned durable artifact, task and worker job records."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid
from ..core import Conflict, Denied, canonical
from .common import secure_dir, require


class Store:
    def __init__(self, root):
        self.root=secure_dir(root);self.artifacts=secure_dir(self.root/'artifacts')
        self.path=self.root/'workflow.sqlite'
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        require(not self.path.is_symlink() and self.path.stat().st_uid==os.geteuid() and
                self.path.stat().st_mode & 0o777==0o600,'WORKFLOW_STORE_PERMISSIONS')
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS artifacts(actor TEXT,digest TEXT,metadata TEXT,PRIMARY KEY(actor,digest));
                CREATE TABLE IF NOT EXISTS tasks(actor TEXT,repo TEXT,task TEXT,data TEXT,PRIMARY KEY(actor,repo,task));
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,actor TEXT,payload TEXT,state TEXT,claim TEXT,result TEXT,error TEXT);
            """)

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
            db.execute("INSERT OR IGNORE INTO jobs VALUES(?,?,?,'QUEUED',NULL,NULL,NULL)",
                       (payload['requestId'],actor,canonical(payload)))

    def claim(self,actor,ident):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM jobs WHERE id=? AND actor=?',(ident,actor)).fetchone()
            if row is None:return None
            if row['state']=='CLAIMED':return dict(state='CLAIMED',claim=row['claim'],payload=json.loads(row['payload']))
            if row['state']!='QUEUED':return dict(state=row['state'])
            claim=str(uuid.uuid4())
            db.execute("UPDATE jobs SET state='CLAIMED',claim=? WHERE id=?",(claim,ident))
            return dict(state='CLAIMED',claim=claim,payload=json.loads(row['payload']))

    def finish(self,actor,ident,claim,result,error):
        require(error in (None,'STALE','UNCERTAIN') and (error is not None or type(result) is dict),'WORKFLOW_COMPLETION_INVALID')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM jobs WHERE id=? AND actor=?',(ident,actor)).fetchone()
            require(row and row['claim']==claim and row['state'] in ('CLAIMED','DONE','FAILED'),'WORKFLOW_CLAIM_INVALID')
            encoded=canonical(result)
            if row['state'] in ('DONE','FAILED'):
                if row['result']!=encoded or row['error']!=error:raise Conflict('WORKFLOW_COMPLETION_CONFLICT')
                return
            db.execute('UPDATE jobs SET state=?,result=?,error=? WHERE id=?',('FAILED' if error else 'DONE',encoded,error,ident))

    def job(self,ident):
        with self.db() as db:row=db.execute('SELECT * FROM jobs WHERE id=?',(ident,)).fetchone()
        return dict(row) if row else None
