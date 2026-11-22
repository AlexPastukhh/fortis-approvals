"""Confined, recoverable source-only updates for generated provider packages.

A linked task worktree is validated by the caller. No live Gateway or network
operations. A staged full directory swap preserves ALL human-owned files and
has a durable recovery marker for interruptions between renames.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile
from uuid import uuid4

from ..core import Denied, canonical, loads_strict
from .model import check, ident

_MANIFEST = 'generated-inventory.json'
_SHA = re.compile('[0-9a-f]{64}\\Z')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _safe(path, *, directory=None):
    """Check existing entries without following symlinks, including parents."""
    path=Path(path)
    check(not path.is_symlink(), 'SOURCE_SYMLINK_DENIED')
    if directory is True:
        check(path.is_dir(), 'SOURCE_DIRECTORY_REQUIRED')
    elif directory is False:
        check(path.is_file(), 'SOURCE_FILE_REQUIRED')
    return path


def _safe_package(folder):
    """Reject links/special entries throughout an existing provider package."""
    _safe(folder,directory=True)
    for current,dirs,files in os.walk(folder,followlinks=False):
        for name in dirs:
            _safe(Path(current)/name,directory=True)
        for name in files:
            _safe(Path(current)/name,directory=False)


def _base(root):
    root=Path(root).absolute()
    _safe(root,directory=True)
    _safe(root/'fortis_approvals',directory=True)
    _safe(root/'fortis_approvals'/'extensions',directory=True)
    _safe(root/'fortis_approvals'/'extensions'/'model.py',directory=False)
    return _safe(root/'fortis_approvals'/'integrations',directory=True)


def _manifest(generated):
    return canonical({k:_sha(v.encode('utf-8')) for k,v in generated.items()})


def _verify_manifest_files(folder):
    """Never prune a recovery backup until every declared file is intact."""
    manifest=_safe(folder/_MANIFEST,directory=False)
    try:
        current=loads_strict(manifest.read_text(encoding='utf-8'))
    except (OSError,UnicodeError,ValueError):
        raise Denied('SOURCE_MANIFEST_INVALID') from None
    check(type(current) is dict and current and
          all(type(k) is str and type(v) is str and _SHA.fullmatch(v)
              for k,v in current.items()), 'SOURCE_MANIFEST_INVALID')
    for rel,oldsha in current.items():
        # Manifest is source-owned today, but recovery must not trust a changed
        # path to point outside its package before deciding to prune a backup.
        pathparts=Path(rel)
        check(not pathparts.is_absolute() and len(pathparts.parts)<=3 and
              all(part not in ('','.', '..') for part in pathparts.parts),
              'SOURCE_MANIFEST_INVALID')
        path=_safe(folder/rel,directory=False)
        check(_sha(path.read_bytes())==oldsha, 'SOURCE_GENERATED_FILE_EDITED_STOP')
    for rel in ('manual.py','tests/test_manual.py'):
        _safe(folder/rel,directory=False)
    return current


def _inventory_valid(folder,generated):
    current=_verify_manifest_files(folder)
    check(set(current)==set(generated), 'SOURCE_MANIFEST_INVALID')
    return _sha((folder/_MANIFEST).read_bytes())


def _preflight(root,name,generated,*,allow_pending=False):
    ident(name)
    base=_base(root)
    folder=base/name
    check(not folder.is_symlink(),'SOURCE_PACKAGE_SYMLINK_DENIED')
    if not allow_pending:
        check(not _pending(base,name),'SOURCE_PENDING_TRANSACTION_REQUIRES_APPLY')
    exists=folder.exists()
    if exists:
        _safe_package(folder)
        check((folder/_MANIFEST).exists(),'SOURCE_UNMANAGED_PROVIDER_DENIED')
        _inventory_valid(folder,generated)
    return base,folder,exists


def _plan(folder,name,generated,is_update):
    changes=[]
    for rel,body in generated.items():
        path=folder/rel
        old=_sha(path.read_bytes()) if is_update else None
        new=_sha(body.encode('utf-8'))
        if old != new:changes.append(dict(path=rel,sha256=new,was=old))
    return dict(provider=name,package=str(folder),
                action='update' if is_update else 'create',
                changes=changes,manuallyOwnedFiles=['manual.py','tests/test_manual.py'],
                requiresOwnerRelease=True)


def preview(root,name,generated):
    _,folder,exists=_preflight(root,name,generated)
    return _plan(folder,name,generated,exists)


def _pending(base,name):
    return sorted(base.glob('_'+name+'_source_txn_*'))


def _record(txn):
    _safe(txn,directory=True)
    _safe_package(txn)
    marker=_safe(txn/'transaction.json',directory=False)
    try:row=loads_strict(marker.read_text(encoding='utf-8'))
    except (OSError,UnicodeError,ValueError):
        raise Denied('SOURCE_TRANSACTION_INVALID') from None
    check(type(row) is dict and set(row)=={'provider','oldManifest','newManifest'} and
          type(row['provider']) is str and
          (row['oldManifest'] is None or
             type(row['oldManifest']) is str and _SHA.fullmatch(row['oldManifest'])) and
          type(row['newManifest']) is str and _SHA.fullmatch(row['newManifest']),
          'SOURCE_TRANSACTION_INVALID')
    return row


def _manifest_sha(folder):
    if not folder.exists():return None
    _safe_package(folder)
    path=_safe(folder/_MANIFEST,directory=False)
    return _sha(path.read_bytes())


def _recover(base,name):
    """Resume known interrupted swap without overwriting unrelated edits.

    If original was moved aside but replacement not installed, roll it back.
    If replacement is already installed, finalize the recorded transaction.
    An unknown state/changed inventory always STOPs for human inspection.
    """
    pending=_pending(base,name)
    check(len(pending)<=1, 'SOURCE_MULTIPLE_PENDING_TRANSACTIONS')
    if not pending:return None
    txn=pending[0]
    check(not txn.is_symlink(), 'SOURCE_TRANSACTION_INVALID')
    row=_record(txn)
    check(row['provider']==name,'SOURCE_TRANSACTION_INVALID')
    original=base/name
    backup=txn/'previous'
    staged=txn/'staged'
    current_sha=_manifest_sha(original)
    old_sha=row['oldManifest'];new_sha=row['newManifest']
    previous_sha=_manifest_sha(backup)
    if current_sha is None and previous_sha==old_sha and old_sha is not None:
        # Verify the exact original bytes before restoring its directory.
        try:_verify_manifest_files(backup)
        except Denied:
            raise Denied('SOURCE_TRANSACTION_RECOVERY_REVIEW_REQUIRED') from None
        os.replace(backup,original)
        shutil.rmtree(txn)
        return 'rolled_back'
    if current_sha==new_sha and (previous_sha==old_sha or previous_sha is None):
        # A modified package may retain the SAME manifest hash. Do not silently
        # delete the only old source snapshot before validating all its files.
        try:
            _verify_manifest_files(original)
            if previous_sha is not None:_verify_manifest_files(backup)
        except Denied:
            raise Denied('SOURCE_TRANSACTION_RECOVERY_REVIEW_REQUIRED') from None
        shutil.rmtree(txn)
        return 'committed'
    if current_sha==old_sha and previous_sha is None:
        try:_verify_manifest_files(original)
        except Denied:
            raise Denied('SOURCE_TRANSACTION_RECOVERY_REVIEW_REQUIRED') from None
        shutil.rmtree(txn)
        return 'staged_not_applied'
    if old_sha is None and current_sha is None and previous_sha is None:
        shutil.rmtree(txn)
        return 'staged_not_applied'
    raise Denied('SOURCE_TRANSACTION_RECOVERY_REVIEW_REQUIRED')


@contextmanager
def _locked(base,name):
    # Lock outside source tree, so no undeclared untracked file leaks into Git.
    lockname='_fortis_source_'+_sha((str(base.resolve())+'|'+name).encode())+'.lock'
    flags=os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(Path(tempfile.gettempdir())/lockname,flags,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def apply(root,name,generated,manual_files):
    """Save a complete generated package and preserve all human-owned bytes.

    Does not install/release provider or grant any credentials/policies. Single
    provider operations are serialized. New/old manifest pins entire swap.
    """
    base=_base(root)
    with _locked(base,name):
        recovered=_recover(base,name)
        _,folder,is_update=_preflight(root,name,generated)
        before=_plan(folder,name,generated,is_update)
        if is_update and not before['changes']:
            return {**before,'appliedFiles':[],'recovery':recovered}
        txn=base/('_'+name+'_source_txn_'+uuid4().hex)
        check(not txn.exists() and not txn.is_symlink(),'SOURCE_TRANSACTION_EXISTS')
        txn.mkdir(mode=0o700)
        try:
            staged=txn/'staged'
            if is_update:
                shutil.copytree(folder,staged,symlinks=True)
            else:
                staged.mkdir(mode=0o700)
            for rel,body in generated.items():
                target=staged/rel
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text(body,encoding='utf-8')
            if not is_update:
                for rel,body in manual_files.items():
                    target=staged/rel
                    target.parent.mkdir(parents=True,exist_ok=True)
                    target.write_text(body,encoding='utf-8')
            next_manifest=_manifest(generated)
            (staged/_MANIFEST).write_text(next_manifest,encoding='utf-8')
            _safe_package(staged)
            check(_manifest_sha(staged)==_sha(next_manifest.encode()),
                  'SOURCE_STAGING_INVALID')
            old_manifest=_manifest_sha(folder) if is_update else None
            (txn/'transaction.json').write_text(canonical(dict(
                provider=name,oldManifest=old_manifest,
                newManifest=_sha(next_manifest.encode()))),encoding='utf-8')
            # The only directory-level visibility window is between these two
            # same-filesystem renames; a crash is restored by _recover on retry.
            if is_update:os.replace(folder,txn/'previous')
            try:
                os.replace(staged,folder)
            except BaseException:
                # If the process remains alive, rollback immediately.
                if is_update and (txn/'previous').exists() and not folder.exists():
                    os.replace(txn/'previous',folder)
                raise
            shutil.rmtree(txn)
        except BaseException:
            # Keep any unrecognized transaction for safe recovery on next apply.
            # Do not delete backups if an exception occurs after first rename.
            if txn.exists() and (txn/'previous').exists():
                pass
            elif txn.exists():
                shutil.rmtree(txn)
            raise
        return {**before, 'appliedFiles':[c['path'] for c in before['changes']],
                'recovery':recovered}
