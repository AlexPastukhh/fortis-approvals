"""Offline negative owner-storage access probe for real Linux Registry/Repo UIDs.

Run ONLY under an independently provisioned Registry or Repo process.
Uses real kernel credentials and read-only/open-without-write attempts.
Never changes SQLite, creates files, impersonates the owner, or grants
Protected Enrollment. An untrusted caller may fabricate any JSON result:
a protected host must attest the original process and its observations.
"""
import errno
import os

from ..core import Denied, Stale
from .owner_peer_boundary import _profile
from .owner_runtime_isolation import (_boot_id, _layout, _read_process, _full_path)
from .state_journal import _hash, _need, _hex

_ROLE_KEYS={'registry','repo'}
_ATTEMPT_NAMES=('ownerParentRead','ownerDbRead','ownerDbReadWrite')
_REQUIRED_FALSE=('protectedAnchorVerified','hostIdentityVerified',
                 'ownerAcceptanceVerified','enrollmentVerified','admissionAllowed')


def _role_identity(role,layout,peer):
    _need(type(role) is str and role in _ROLE_KEYS,'REGISTRY_DENIAL_ROLE_INVALID')
    return ((peer['registryUid'],peer['registryGid']) if role=='registry' else
            (layout['repoUid'],layout['repoGid']))


def _valid_process(role,layout,peer,row):
    uid,gid=_role_identity(role,layout,peer)
    _need(type(row) is dict and row.get('pid')==layout[role+'Pid']
          and type(row.get('startTicks')) is int and row['startTicks']>0
          and row.get('uids')==[uid]*4 and row.get('gids')==[gid]*4
          and type(row.get('groups')) is list
          and len(row['groups'])<=64
          and all(type(n) is int and n>0 for n in row['groups'])
          and len(set(row['groups']))==len(row['groups'])
          and peer['authorityGid'] not in row['groups']
          and all(type(row.get(name)) is int and row[name]==0 for name in
                  ('capInh','capPrm','capEff','capBnd','capAmb','tracerPid'))
          and type(row.get('noNewPrivs')) is int and row['noNewPrivs']==1
          and type(row.get('seccomp')) is int and row['seccomp']==2
          and type(row.get('mountNamespace')) is str
          and row['mountNamespace'].startswith('mnt:[')
          and type(row.get('cgroup')) is str and row['cgroup'].strip(),
          'REGISTRY_DENIAL_PROCESS_IDENTITY')
    return row


def _denied_open(path,flags):
    """Attempt an OS open, close successful FDs; never read/write content.

    EACCES/EPERM are the ONLY valid negative observations.
    ENOENT, ENOTDIR, ELOOP, EISDIR, EROFS and all other errors are STOP,
    not proof of an inaccessible but existing protected owner state.
    """
    try:
        fd=os.open(path,flags|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    except OSError as exc:
        if exc.errno==errno.EACCES:return 'EACCES'
        if exc.errno==errno.EPERM:return 'EPERM'
        raise Denied('REGISTRY_DENIAL_NOT_PROVEN') from None
    else:
        os.close(fd)
        raise Denied('REGISTRY_DENIAL_STORAGE_ACCESSIBLE')


def _attempts(path):
    return {
        'ownerParentRead':_denied_open(str(path.parent),os.O_RDONLY|os.O_DIRECTORY),
        'ownerDbRead':_denied_open(str(path),os.O_RDONLY),
        # Request write-capable descriptor only, NEVER perform a write or
        # create/truncate. Opening must be denied to the unprivileged peer.
        'ownerDbReadWrite':_denied_open(str(path),os.O_RDWR),
    }


def observe_storage_denial(*,role,peer_profile_reader,expected_peer_profile_digest,
                           layout_reader,expected_layout_digest):
    """Read only; the caller must be the actual pre-registered Linux PID/UID.

    This is NOT an owner-host attestation. It cannot alone prove storage
    separation, absence of another capability or a monotonic owner anchor.
    """
    _need(callable(peer_profile_reader) and callable(layout_reader),
          'REGISTRY_DENIAL_READERS_REQUIRED')
    peer=_profile(peer_profile_reader(),expected_peer_profile_digest)
    layout=_layout(layout_reader(),expected_layout_digest,peer)
    uid,gid=_role_identity(role,layout,peer)
    _need(os.getpid()==layout[role+'Pid']
          and os.geteuid()==uid and os.getegid()==gid
          and os.getuid()==uid and os.getgid()==gid,
          'REGISTRY_DENIAL_ACTOR_IDENTITY')
    boot=_boot_id()
    _need(boot==layout['bootId'],'REGISTRY_DENIAL_BOOT_MISMATCH')
    before=_valid_process(role,layout,peer,_read_process(os.getpid()))
    path=_full_path(layout['ownerStatePath'])
    observed=_attempts(path)
    after=_valid_process(role,layout,peer,_read_process(os.getpid()))
    _need(_boot_id()==boot
          and _profile(peer_profile_reader(),expected_peer_profile_digest)==peer
          and _layout(layout_reader(),expected_layout_digest,peer)==layout,
          'REGISTRY_DENIAL_PROFILE_CHANGED')
    if after!=before:raise Stale('REGISTRY_DENIAL_PROCESS_CHANGED')
    evidence={'schemaVersion':1,'format':'registry-owner-storage-denial-v1',
              'role':role,'instanceId':peer['instanceId'],
              'scopeDigest':peer['scopeDigest'],
              'enrollmentReceiptDigest':peer['enrollmentReceiptDigest'],
              'peerProfileDigest':_hash(peer),'layoutDigest':_hash(layout),
              'bootId':boot,'ownerStatePath':str(path),
              'process':before,'attempts':observed}
    return {'result':'OWNER_STORAGE_DENIAL_OBSERVATION_CANDIDATE',
            'evidence':evidence,'evidenceDigest':_hash(evidence),
            'protectedAnchorVerified':False,'hostIdentityVerified':False,
            'ownerAcceptanceVerified':False,'enrollmentVerified':False,
            'admissionAllowed':False}


def _checked_observation(value,role,layout,peer):
    _need(type(value) is dict and set(value)=={'result','evidence','evidenceDigest'}|set(_REQUIRED_FALSE)
          and value['result']=='OWNER_STORAGE_DENIAL_OBSERVATION_CANDIDATE'
          and all(value[f] is False for f in _REQUIRED_FALSE)
          and type(value['evidence']) is dict
          and _hex(value['evidenceDigest'],64)
          and _hash(value['evidence'])==value['evidenceDigest'],
          'REGISTRY_DENIAL_EVIDENCE_INVALID')
    evidence=value['evidence']
    _need(set(evidence)=={'schemaVersion','format','role','instanceId','scopeDigest',
                 'enrollmentReceiptDigest','peerProfileDigest','layoutDigest',
                 'bootId','ownerStatePath','process','attempts'}
          and type(evidence['schemaVersion']) is int and evidence['schemaVersion']==1
          and evidence['format']=='registry-owner-storage-denial-v1'
          and evidence['role']==role
          and evidence['instanceId']==peer['instanceId']
          and evidence['scopeDigest']==peer['scopeDigest']
          and evidence['enrollmentReceiptDigest']==peer['enrollmentReceiptDigest']
          and evidence['peerProfileDigest']==_hash(peer)
          and evidence['layoutDigest']==_hash(layout)
          and evidence['bootId']==layout['bootId']
          and evidence['ownerStatePath']==layout['ownerStatePath']
          and type(evidence['attempts']) is dict
          and set(evidence['attempts'])==set(_ATTEMPT_NAMES)
          and all(evidence['attempts'][k] in ('EACCES','EPERM') for k in _ATTEMPT_NAMES),
          'REGISTRY_DENIAL_EVIDENCE_INVALID')
    _valid_process(role,layout,peer,evidence['process'])
    return evidence


def compose_storage_denial_review(*,registry_observation,repo_observation,
                                  peer_profile_reader,expected_peer_profile_digest,
                                  layout_reader,expected_layout_digest):
    """Structural two-principal review package: still NOT signed/owner-accepted.

    Neither caller-supplied observations nor source-only digests constitute
    independently authenticated kernel results. Operator must obtain
    protected original host evidence before accepting an enrollment.
    """
    _need(callable(peer_profile_reader) and callable(layout_reader),
          'REGISTRY_DENIAL_READERS_REQUIRED')
    peer=_profile(peer_profile_reader(),expected_peer_profile_digest)
    layout=_layout(layout_reader(),expected_layout_digest,peer)
    values={'registry':_checked_observation(registry_observation,'registry',layout,peer),
            'repo':_checked_observation(repo_observation,'repo',layout,peer)}
    _need(values['registry']['process']['pid']!=values['repo']['process']['pid']
          and values['registry']['process']['mountNamespace']!=
              values['repo']['process']['mountNamespace']
          and values['registry']['process']['cgroup']!=values['repo']['process']['cgroup'],
          'REGISTRY_DENIAL_ROLE_NOT_SEPARATED')
    if (_profile(peer_profile_reader(),expected_peer_profile_digest)!=peer
            or _layout(layout_reader(),expected_layout_digest,peer)!=layout):
        raise Stale('REGISTRY_DENIAL_PROFILE_CHANGED')
    observation={'schemaVersion':1,'format':'registry-owner-storage-denial-review-v1',
                 'instanceId':peer['instanceId'],'scopeDigest':peer['scopeDigest'],
                 'peerProfileDigest':_hash(peer),'layoutDigest':_hash(layout),
                 'bootId':layout['bootId'],'registryDigest':_hash(values['registry']),
                 'repoDigest':_hash(values['repo'])}
    return {'result':'OWNER_STORAGE_DENIAL_REVIEW_CANDIDATE',
            'observation':observation,'observationDigest':_hash(observation),
            'protectedAnchorVerified':False,'hostIdentityVerified':False,
            'ownerAcceptanceVerified':False,'enrollmentVerified':False,
            'admissionAllowed':False}
