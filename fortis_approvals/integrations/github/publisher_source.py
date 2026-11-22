"""Fresh private data views from exact-SHA Gateway bundles. Never check out PR code."""
import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import tempfile

from ...core import Denied
from ...workflow.common import Git, MAX_BUNDLE, branch, file_path, secure_dir, sha
from .publisher_profile import REPOSITORY, require

MAX_FILES = 5000
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_VIEW_BYTES = 48 * 1024 * 1024


def private_path(value):
    require(isinstance(value, (str, Path)), 'PUBLISHER_PRIVATE_PATH_REQUIRED')
    path = Path(value)
    require(path.is_absolute() and path != Path('/') and path.resolve() == path,
            'PUBLISHER_PRIVATE_PATH_REQUIRED')
    return path


def materialize(git, repository, revision, destination):
    """Read raw regular Git blobs; no archive attributes, filters, hooks or links."""
    sha(revision)
    destination = secure_dir(destination)
    require(not list(destination.iterdir()), 'PUBLISHER_VIEW_NOT_EMPTY')
    raw = git.run(['--no-replace-objects', 'ls-tree', '-rlz', '--full-tree', revision],
                  cwd=repository)[1]
    require(not raw or raw.endswith(b'\0'), 'PUBLISHER_TREE_INVALID')
    entries = [x for x in raw.split(b'\0') if x]
    require(0 < len(entries) <= MAX_FILES, 'PUBLISHER_TREE_LIMIT')
    total, names, folded, records = 0, set(), set(), []
    for entry in entries:
        try:
            metadata, encoded = entry.split(b'\t', 1)
            mode, kind, ident, size = metadata.split()
            name = file_path(encoded.decode('utf-8', 'strict'))
            length = int(size)
        except (ValueError, UnicodeError):
            raise Denied('PUBLISHER_TREE_INVALID') from None
        require(mode in (b'100644', b'100755') and kind == b'blob' and
                re.fullmatch(b'[0-9a-f]{40}', ident) and 0 <= length <= MAX_FILE_BYTES,
                'PUBLISHER_UNSAFE_TREE_ENTRY')
        require(name not in names and name.casefold() not in folded,
                'PUBLISHER_TREE_ALIAS')
        names.add(name); folded.add(name.casefold())
        total += length
        require(total <= MAX_VIEW_BYTES, 'PUBLISHER_TREE_LIMIT')
        records.append((name, ident, length))
    # One bounded raw-object read avoids a process for every repository file.
    blobs = git.run(['--no-replace-objects','cat-file','--batch'],
                    data=b''.join(ident+b'\n' for _,ident,_ in records), cwd=repository)[1]
    offset = 0
    for name, ident, length in records:
        end = blobs.find(b'\n',offset)
        require(end >= 0 and blobs[offset:end] ==
                ident+b' blob '+str(length).encode(), 'PUBLISHER_BLOB_INVALID')
        offset = end+1
        data = blobs[offset:offset+length]
        offset += length
        require(len(data) == length and blobs[offset:offset+1] == b'\n' and hashlib.sha1(
            b'blob '+str(length).encode()+b'\0'+data).hexdigest() == ident.decode(),
            'PUBLISHER_BLOB_INVALID')
        offset += 1
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
    require(offset == len(blobs), 'PUBLISHER_BLOB_INVALID')
    return dict(files=len(entries), bytes=total)


class SourceView:
    def __init__(self, gateway, folder):
        self.gateway = gateway
        self.folder = secure_dir(folder)
        self.git = Git(self.folder / 'git-state', protocols='file')
        self.repository = secure_dir(self.folder / 'objects')
        self.data = self.folder / 'data'
        self.git.run(['init', '--quiet', '--template=', self.repository])

    def _bundle(self, ref, expected, target):
        response = self.gateway.post('/v1/git/fetch', dict(
            repository=REPOSITORY, ref=ref, expectedSha=expected))
        require(type(response) is dict and set(response) == {
            'repository','ref','sha','bundleSha256','bundle'} and
            response['repository'] == REPOSITORY and response['ref'] == ref and
            response['sha'] == expected and type(response['bundleSha256']) is str and
            re.fullmatch('[0-9a-f]{64}', response['bundleSha256']) and
            type(response['bundle']) is str and
            0 < len(response['bundle']) <= (MAX_BUNDLE+2)//3*4,
            'PUBLISHER_BUNDLE_RESPONSE_INVALID')
        try:
            data = base64.b64decode(response['bundle'], validate=True)
        except (ValueError, UnicodeError):
            raise Denied('PUBLISHER_BUNDLE_INVALID') from None
        require(0 < len(data) <= MAX_BUNDLE and hashlib.sha256(data).hexdigest() ==
                response['bundleSha256'], 'PUBLISHER_BUNDLE_DIGEST_INVALID')
        path = self.folder / (target + '.bundle')
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(data)
        heads = self.git.text(['bundle','list-heads',path], cwd=self.repository)
        require(heads == expected+' refs/heads/transfer', 'PUBLISHER_BUNDLE_REF_INVALID')
        self.git.run(['bundle','verify',path], cwd=self.repository)
        self.git.run(['fetch','--no-tags','--no-write-fetch-head',path,
            'refs/heads/transfer:refs/heads/'+target], cwd=self.repository, protocols='file')
        require(self.git.text(['rev-parse','refs/heads/'+target], cwd=self.repository) ==
                expected, 'PUBLISHER_SOURCE_SHA_CHANGED')
        return response['bundleSha256']

    def acquire(self, *, main_sha, head_sha, base_sha, task_branch):
        for value in (main_sha, head_sha, base_sha):
            sha(value)
        branch(task_branch)
        main_digest = self._bundle('main', main_sha, 'verified-main')
        head_digest = self._bundle(task_branch, head_sha, 'verified-head')
        require(not (self.repository/'.git/shallow').exists() and
                not (self.repository/'.git/objects/info/alternates').exists() and
                not self.git.text(['for-each-ref','refs/replace'], cwd=self.repository),
                'PUBLISHER_INCOMPLETE_HISTORY')
        # The freshly initialized private repository otherwise has an unborn
        # HEAD despite its two fetched, exact-SHA verified refs. Point HEAD at
        # a distinct verified-view ref before strict refs/object fsck; do not
        # mutate verified-main when HEAD is later advanced to the PR head.
        self.git.run(['symbolic-ref','HEAD','refs/heads/verified-view'],cwd=self.repository)
        self.git.run(['update-ref','refs/heads/verified-view',main_sha],cwd=self.repository)
        require(self.git.text(['--no-replace-objects','rev-parse','HEAD'],
                              cwd=self.repository) == main_sha,
                'PUBLISHER_SOURCE_SHA_CHANGED')
        self.git.run(['--no-replace-objects','fsck','--strict','--full','--no-reflogs'],
                     cwd=self.repository)
        objects = self.git.text(['--no-replace-objects','cat-file',
            '--batch-check','--batch-all-objects'], cwd=self.repository).splitlines()
        require(len(objects) <= 100000 and
                sum(int(x.rsplit(' ',1)[1]) for x in objects) <= 256*1024*1024,
                'PUBLISHER_OBJECT_LIMIT')
        for value in (main_sha, head_sha, base_sha):
            require(self.git.text(['--no-replace-objects','cat-file','-t',value],
                    cwd=self.repository) == 'commit', 'PUBLISHER_COMMIT_REQUIRED')
        code, _ = self.git.run(['--no-replace-objects','merge-base','--is-ancestor',
            base_sha, main_sha], cwd=self.repository, ok=(0,1))
        require(code == 0, 'PUBLISHER_BASE_NOT_IN_MAIN')
        merge_base = sha(self.git.text(['--no-replace-objects','merge-base',base_sha,head_sha],
                                       cwd=self.repository))
        tree = materialize(self.git, self.repository, head_sha, self.data)
        # The validator needs verified Git objects at its data-only repo root.
        # Move only our own fresh metadata, never a PR-provided .git directory.
        (self.repository/'.git').rename(self.data/'.git')
        self.repository.rmdir()
        self.git.run(['--no-replace-objects','update-ref','HEAD',head_sha], cwd=self.data)
        require(self.git.text(['rev-parse','HEAD'], cwd=self.data) == head_sha,
                'PUBLISHER_SOURCE_SHA_CHANGED')
        return dict(mainSha=main_sha, headSha=head_sha, baseSha=base_sha,
                    mergeBaseSha=merge_base, mainBundleSha256=main_digest,
                    headBundleSha256=head_digest, **tree)


@contextmanager
def source_view(gateway, cache_root, **identity):
    root = secure_dir(private_path(cache_root))
    with tempfile.TemporaryDirectory(prefix='source-', dir=root) as folder:
        view = SourceView(gateway, Path(folder))
        evidence = view.acquire(**identity)
        yield view, evidence
