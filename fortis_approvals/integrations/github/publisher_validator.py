"""Execute only the separately pinned public validator, never code from a PR."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

from ...core import Denied, loads_strict
from ...workflow.common import sha, secure_dir
from .publisher_profile import require
from .publisher_source import materialize, private_path
from .release_label_contract import checked_names

# This shim imports only the configured owner code root, checked against raw
# Git blobs at the trusted pin. Cache and PR data never enter sys.path.
_SHIM = """
import json,resource,sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS,(536870912,536870912))
resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576))
resource.setrlimit(resource.RLIMIT_CPU,(30,30))
sys.path.insert(0,sys.argv[1])
from ci_entry import run
from label_admission_v1 import plan_labels
value=json.load(sys.stdin)
checked=run(Path(sys.argv[2]),repository=value['repository'],
            event_name='pull_request',repo_root=Path(value['repoRoot']))
pr=value['currentPr']
admission=dict(repository=value['repository'],pullRequest=pr['number'],
               headSha=pr['head']['sha'],baseSha=pr['base']['sha'],body=pr['body'])
plan=plan_labels(admission,checked,pr,value['existingLabels'],value['availableLabels'])
print(json.dumps(dict(plan,classification=checked['classification'],
                      affectedTargets=checked['affectedTargets'])))
"""


class PinnedValidator:
    def __init__(self, root, revision, *, git, folder):
        self.root = private_path(root)
        self.revision = sha(revision)
        self.git = git
        self.folder = secure_dir(folder)
        require(self.root.is_dir(), 'PUBLISHER_VALIDATOR_ROOT_REQUIRED')
        require(git.text(['--no-replace-objects','rev-parse','HEAD'], cwd=self.root) ==
                revision, 'PUBLISHER_VALIDATOR_PIN_CHANGED')
        git.run(['--no-replace-objects','fsck','--strict','--full','--no-reflogs'],
                cwd=self.root)
        self.reference = self.folder / 'code-reference'
        materialize(git, self.root, revision, self.reference)
        require((self.reference/'tools/release/ci_entry.py').is_file() and
                (self.reference/'tools/release/label_admission_v1.py').is_file(),
                'PUBLISHER_VALIDATOR_CODE_REQUIRED')
        self._verify_code_root()

    def _verify_code_root(self):
        # Physical read-only ownership is a P3.4 activation gate. This source
        # check additionally rejects modified, untracked and ignored code.
        expected = {p.relative_to(self.reference) for p in self.reference.rglob('*') if p.is_file()}
        actual = set()
        expected_directories = {parent for relative in expected for parent in relative.parents
                                if parent != Path('.')}
        for current, directories, files in os.walk(self.root, followlinks=False):
            current = Path(current)
            if current == self.root:
                directories[:] = [d for d in directories if d != '.git']
                files = [f for f in files if f != '.git']
            require(all(not (current/d).is_symlink() and
                        (current/d).relative_to(self.root) in expected_directories for d in directories),
                    'PUBLISHER_VALIDATOR_WORKTREE_CHANGED')
            for name in files:
                path = current/name
                require(not path.is_symlink() and path.is_file(), 'PUBLISHER_VALIDATOR_WORKTREE_CHANGED')
                relative = path.relative_to(self.root)
                require(relative in expected, 'PUBLISHER_VALIDATOR_WORKTREE_CHANGED')
                actual.add(relative)
        require(actual == expected, 'PUBLISHER_VALIDATOR_WORKTREE_CHANGED')
        for relative in expected:
            require((self.root/relative).read_bytes() == (self.reference/relative).read_bytes(),
                    'PUBLISHER_VALIDATOR_WORKTREE_CHANGED')

    def plan(self, *, view, current_pr, existing_labels, available_labels, repository):
        self._verify_code_root()
        event = dict(action='opened', repository=dict(full_name=repository),
                     pull_request=current_pr)
        event_file = self.folder / 'event.json'
        event_file.write_text(json.dumps(event)); event_file.chmod(0o600)
        value = dict(repository=repository, repoRoot=str(view.data), currentPr=current_pr,
                     existingLabels=existing_labels, availableLabels=available_labels)
        data = json.dumps(value).encode()
        require(len(data) <= 131072, 'PUBLISHER_VALIDATOR_INPUT_LIMIT')
        # No inherited Python/Git config, credential helper, replace refs or network protocols.
        env = dict(PATH=os.defpath, HOME=str(self.git.home), LANG='C.UTF-8', LC_ALL='C.UTF-8',
                   GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(self.git.config),
                   GIT_TERMINAL_PROMPT='0', GIT_OPTIONAL_LOCKS='0', GIT_ALLOW_PROTOCOL='',
                   GIT_NO_REPLACE_OBJECTS='1', GIT_PAGER='cat')
        settings = [('core.hooksPath',str(self.git.hooks)),('core.fsmonitor','false'),
                    ('credential.helper',''),('diff.external',''),('submodule.recurse','false')]
        env['GIT_CONFIG_COUNT'] = str(len(settings))
        for i, (key, value) in enumerate(settings):
            env['GIT_CONFIG_KEY_'+str(i)] = key
            env['GIT_CONFIG_VALUE_'+str(i)] = value
        cache = secure_dir(self.folder/'bytecode')
        with tempfile.TemporaryFile(dir=self.folder) as output, tempfile.TemporaryFile(dir=self.folder) as error:
            process = subprocess.Popen([sys.executable,'-I','-B','-X','pycache_prefix='+str(cache),
                '-c',_SHIM,str(self.root/'tools/release'),str(event_file)],
                cwd=self.folder, env=env, stdin=subprocess.PIPE, stdout=output,
                stderr=error, start_new_session=True)
            try:
                process.communicate(data, timeout=40)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL); process.wait()
                raise Denied('PUBLISHER_VALIDATOR_TIMEOUT') from None
            require(process.returncode == 0, 'PUBLISHER_SOURCE_VALIDATION_FAILED')
            require(0 < output.tell() <= 65536, 'PUBLISHER_VALIDATOR_OUTPUT_LIMIT')
            output.seek(0)
            try:
                plan = loads_strict(output.read())
            except (ValueError, UnicodeError):
                raise Denied('PUBLISHER_VALIDATOR_OUTPUT_INVALID') from None
        fields = {'status','repository','pullRequest','headSha','suggestedLabels','add','remove',
                  'missingDefinitions','preservedHumanLabels','preservedReviewFlag','classification','affectedTargets'}
        require(type(plan) is dict and set(plan) == fields and plan.get('repository') == repository and
                plan.get('pullRequest') == current_pr['number'] and
                plan.get('headSha') == current_pr['head']['sha'] and
                plan.get('status') in ('PREVIEW_ONLY','BLOCKED_MISSING_LABELS'),
                'PUBLISHER_VALIDATOR_OUTPUT_INVALID')
        for key in ('suggestedLabels','add','remove','missingDefinitions','preservedHumanLabels'):
            checked_names(plan[key])
        require(type(plan['preservedReviewFlag']) is bool and
                plan['classification'] in ('deployment','no-deployment') and
                type(plan['affectedTargets']) is list and len(plan['affectedTargets']) <= 200 and
                all(type(x) is str and 0 < len(x) <= 100 for x in plan['affectedTargets']),
                'PUBLISHER_VALIDATOR_OUTPUT_INVALID')
        self._verify_code_root()
        return plan
