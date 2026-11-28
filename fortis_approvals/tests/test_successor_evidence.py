"""Successor evidence tests: isolated Git objects and reviewed validator fixture.

The optional cross-repo fixture copies only the validator/schema files into
a temporary local Git repo; it does not publish or select live authority.
"""
import copy
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch

from fortis_approvals.core import Denied, Stale
from fortis_approvals.workflow.common import Git
from fortis_approvals.extensions.successor_impact import SuccessorImpact
from fortis_approvals.extensions.successor_ci import SuccessorCI
from fortis_approvals.extensions.successor_projector import SuccessorProjector
from fortis_approvals.integrations.github.gateway.adapter import GitHubAdapter
from fortis_approvals.integrations.github.gateway.analysis_adapter import AnalysisGitHubAdapter
from fortis_approvals.integrations.github.tests import test_path_ci_observation as ci_fixture
from fortis_approvals.integrations.github.tests import publisher_fixture as pub_fixture
from fortis_approvals.integrations.github.release_label_ci import WORKFLOWS
from fortis_approvals.extensions.native_merge_receipt import NativeMergeReceiptReader
from fortis_approvals.extensions.native_merge_discovery import NativeMergeDiscovery
from fortis_approvals.extensions.composite_executor import StepContext
from fortis_approvals.integrations.registry_contracts import source_lineage_contract as lc
import uuid
from fortis_approvals.integrations.github.gateway.component_bindings import _resolved
from fortis_approvals.integrations.github.post_merge_proof_bindings import _impact_yaml
from fortis_approvals.integrations.registry_contracts.release_profile import from_resolved_catalog
from fortis_approvals.integrations.registry_contracts import semantic_contract as sc


def sha(raw):return hashlib.sha256(raw).hexdigest()


class ImpactTests(unittest.TestCase):
    def setUp(self):
        validator=os.getenv('FORTIS_SUCCESSOR_VALIDATOR_FIXTURE')
        if not validator:self.skipTest('explicit cross-repo validator fixture not supplied')
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.git=Git(self.root/'git')
        self.code=self.root/'validator';self.source=self.root/'source';self.state=self.root/'state'
        for p in (self.code,self.source,self.state):p.mkdir(mode=0o700)
        for repo in (self.code,self.source):
            self.git.run(['init','-q'],cwd=repo)
        for name in ('tools/release/validate.py','docs/schemas/build-target-catalog-v1.schema.json',
                     'docs/schemas/build-target-catalog-v2.schema.json','docs/schemas/release-impact-v1.schema.json'):
            dest=self.code/name;dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(Path(validator)/name,dest)
        self.pin=self.commit(self.code)
        self.repo='Owner/fortis-approvals'
        self.catalog={'schemaVersion':2,'repository':'fortis-approvals','buildUnits':[],
            'targets':[{'id':'app','inputs':['src.py'],'deployment':{'kind':'owner-controlled',
             'procedure':'README.md','environments':['test']},'verification':['health'],
             'maintenance':{'beginRequired':False,'stateFreeze':False,'blockedOperations':[],'notes':[]}}],
            'noDeploymentPaths':['README.md']}
        self.binding={'bindings':[{'targetId':'app','environment':'test','componentId':'app'}],
                      'components':[{'id':'app','resources':['app-state'],'requires':[]}]}
        (self.source/'release').mkdir()
        self.catalog_text=json.dumps(self.catalog)
        (self.source/'release/targets.yaml').write_text(self.catalog_text)
        (self.source/'src.py').write_text('pass\n')
        (self.source/'README.md').write_text('UC\n')
        # Exact reviewed workflow bytes in the fixture source tree.
        for w in WORKFLOWS:
            path=self.source/w.path;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((pub_fixture.ROOT/w.path).read_bytes())

        self.base=self.commit(self.source)
        (self.source/'src.py').write_text('raise RuntimeError("PR code must not execute")\n')
        self.head=self.commit(self.source)
        self.profile=from_resolved_catalog(self.catalog,_resolved(self.binding,self.catalog),
            repository=self.repo,catalog_sha256=sha(self.catalog_text.encode()),build_pins={})
        self.verifier=SuccessorImpact(validator_repository=self.code,validator_revision=self.pin,
            source_repository=self.source,state_root=self.state,repository=self.repo,
            binding=self.binding,build_pins={},profile_digest=sc.digest(self.profile))
        self.impact={'releaseImpact':{'schemaVersion':1,'classification':'deployment',
             'reason':'Changed source file','targets':[{'id':'app','actions':['config-deploy']}],
             'dependencies':{'pullRequests':[],'targets':[]},'verification':['tests']}}
        self.observed=self.observation()

    def commit(self,repo):
        self.git.run(['add','.'],cwd=repo)
        self.git.run(['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                      'commit','-qm','fixture'],cwd=repo)
        return self.git.text(['rev-parse','HEAD'],cwd=repo)

    def observation(self):
        # JSON is a valid YAML document. Existing delimiter contract unchanged.
        body='<!-- fortis-release-impact:start -->\n```yaml\n'+json.dumps(self.impact)+'\n```\n<!-- fortis-release-impact:end -->'
        paths=[{'path':'src.py','status':'modified','previousPath':None}]
        raw=self.catalog_text.encode()
        return {'repository':self.repo,'number':12,'baseSha':self.base,'headSha':self.head,
                'treeSha':self.git.text(['rev-parse',self.head+'^{tree}'],cwd=self.source),
                'headBranch':'fixture','body':body,'bodyDigest':sha(body.encode()),
                'impactDigest':sha(_impact_yaml(body).encode()),'catalog':self.catalog_text,
                'catalogSha256':sha(raw),'catalogBlobSha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                'paths':paths,'pathsDigest':sc.digest(paths)}

    def test_exact_v2_impact_profile_and_no_pr_execution(self):
        out=self.verifier.verify(self.observed)
        self.assertEqual(out['validatorRevision'],self.pin)
        self.assertEqual(out['targets'][0]['actions'],['config-deploy'])
        self.assertEqual(out['profileDigest'],sc.digest(self.profile))

    def test_false_no_deployment_or_unresolved_pr_refused(self):
        self.impact['releaseImpact'].update(classification='no-deployment',targets=[])
        with self.assertRaises(Denied):self.verifier.verify(self.observation())
        self.impact['releaseImpact'].update(classification='deployment',targets=[{'id':'app','actions':['config-deploy']}])
        self.impact['releaseImpact']['dependencies']['pullRequests']=[{'repository':'fortis-approvals','number':11}]
        with self.assertRaises(Denied):self.verifier.verify(self.observation())

    def test_tree_and_path_drift(self):
        with self.assertRaises(Denied):self.verifier.verify({**self.observed,'treeSha':'f'*40})
        paths=[{'path':'README.md','status':'modified','previousPath':None}]
        with self.assertRaises(Denied):self.verifier.verify({**self.observed,'paths':paths,'pathsDigest':sc.digest(paths)})

    def test_real_projector_and_original_upstream_receipt(self):
        api=CheckProvider()
        api.head=self.head;api.base=self.base;api.ci_head=self.head
        # The existing REST fixture's repo and PR number are fixed.
        # This test uses the same actual source/profile under that scope.
        repo=pub_fixture.OWNER+'/fortis-approvals'
        self.verifier.repository=repo
        profile=from_resolved_catalog(self.catalog,_resolved(self.binding,self.catalog),
            repository=repo,catalog_sha256=sha(self.catalog_text.encode()),build_pins={})
        self.verifier.profile_digest=sc.digest(profile)
        observed={**self.observed,'repository':repo,'number':7,'headBranch':api.branch}
        ci=make_ci(api,self.root/'ci.sqlite')
        pin=sc.digest({'repository':repo,'validatorRevision':self.pin,
                       'ciPolicyDigest':ci.pin,'profileDigest':self.verifier.profile_digest})
        with self.assertRaises(Denied):
            SuccessorProjector(self.verifier,ci,source_revision=lambda:1,expected_composition_digest='f'*64)
        projector=SuccessorProjector(self.verifier,ci,source_revision=lambda:1,expected_composition_digest=pin)
        api.body=observed['body']
        class PreAPI:
            def request(self,method,path,**kw):
                assert method=='GET'
                if path.endswith('/pulls'):return [{**api.pr(),'changed_files':1}]
                if path.endswith('/pulls/7'):return {**api.pr(),'changed_files':1}
                if path.endswith('/branches/main'):return {'name':'main','commit':{'sha':api.base}}
                if path.endswith('/git/commits/'+api.head):return {'sha':api.head,'tree':{'sha':observed['treeSha']}}
                if '/compare/' in path:return {'status':'ahead','ahead_by':1,'base_commit':{'sha':api.base},
                    'merge_base_commit':{'sha':api.base},'files':[{'filename':'src.py','status':'modified'}]}
                if path.endswith('/contents/release/targets.yaml'):
                    raw=observed['catalog'].encode()
                    return {'type':'file','path':'release/targets.yaml','encoding':'base64','size':len(raw),
                            'content':base64.b64encode(raw).decode(),'sha':observed['catalogBlobSha']}
                raise AssertionError(path)
        pre=GitHubAdapter(PreAPI(),owner=pub_fixture.OWNER,repositories=['fortis-approvals'],
                            receipt_store=self.root/'pre.sqlite')
        discovery=NativeMergeDiscovery(pre,repository=repo,read_guard=lambda *_:True,
                        branch_guard=lambda *_:True,project=projector)
        p=discovery('agent',repo)[0]
        same,material=discovery.review('agent',p)
        self.assertEqual(p,same)
        with self.assertRaises(Stale):
            discovery.review('agent',{**p,'bodyDigest':'f'*64})
        self.assertEqual(p['ciDigest'],sc.digest(material['ci']))
        self.assertEqual(p['targets'][0]['subject']['repository'],repo)
        self.assertEqual(p['expectedSourceRevision'],1)
        self.assertEqual(material['ci']['validatorRevision'],self.pin)
        self.assertEqual(len(material['ci']['checks']),3)
        parent=str(uuid.uuid4());exp=lc.merge_expansion(parent,p);step=exp['steps'][0]
        ctx=StepContext('agent',parent,'a'*64,'v1','owner','scope',exp['definitionDigest'],
                        'b'*64,step['stepId'],0,step['operation'],sc.canonical(step['params']))
        retained={'stepId':ctx.step_id,'material':material,'materialDigest':sc.digest(material)}
        merge=self.git.text(['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
              'commit-tree',p['treeSha'],'-p',self.base,'-p',self.head,'-m','Fixture merge'],cwd=self.source)
        class PostAPI:
            def __init__(self):self.body=observed['body'];self.parents=[p['baseSha'],p['headSha']];self.main=merge;self.calls=0
            def request(self,method,path,**kw):
                assert method=='GET';self.calls+=1
                if path.endswith('/pulls/7'):
                    return {**api.pr(),'state':'closed','merged':True,'merge_commit_sha':merge,'body':self.body}
                if path.endswith('/branches/main'):
                    return {'name':'main','commit':{'sha':self.main}}
                if path.endswith('/git/commits/'+merge):
                    return {'sha':merge,'tree':{'sha':p['treeSha']},'parents':[{'sha':v} for v in self.parents]}
                raise AssertionError(path)
        post=PostAPI()
        native=GitHubAdapter(post,owner=pub_fixture.OWNER,repositories=['fortis-approvals'],
                            receipt_store=self.root/'merge.sqlite')
        reader=NativeMergeReceiptReader(native,source_repository=self.source,state_root=self.state,
                                        read_guard=lambda *_:True)
        self.assertIsNone(reader.lookup(ctx,retained))
        self.assertEqual(post.calls,0)
        # Fixture only: simulate the original provider acknowledgement,
        # not a new receipt reconstructed from the visible merged PR.
        native._save_receipt(ctx.step_id,{'requestId':ctx.step_id,'operation':'merge_pull_request',
                  'repository':'fortis-approvals','number':7,'merged':True,'sha':merge})
        receipt=reader.lookup(ctx,retained)
        self.assertEqual(receipt['observation']['parents'],[self.base,self.head])
        self.assertEqual(receipt['observation']['mergeSha'],merge)
        self.assertEqual(reader.lookup(ctx,retained),receipt)
        post.main='f'*40
        with self.assertRaises(Denied):reader.lookup(ctx,retained)
        post.main=merge;post.parents=[self.head,self.base]
        with self.assertRaises(Denied):reader.lookup(ctx,retained)

    def test_prepared_transition_replays_real_bundle_and_commits_once(self):
        from contextlib import ExitStack
        from unittest.mock import patch
        from fortis_approvals.registry import owner_functional_v1_bootstrap as boot
        from fortis_approvals.registry import local_candidate_read_service as entry
        from fortis_approvals.registry import protected_transition as protected
        from fortis_approvals.registry.transition_preservation import legacy_prefix_witness
        from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
        from fortis_approvals.integrations.registry_contracts import transition_contract as tc
        from fortis_approvals.integrations.registry_contracts import source_lineage_contract as lc
        from fortis_approvals.tests.test_registry_transition_contract import manifest as fixture_manifest

        baseline = self.base
        base_tree = self.git.text(['rev-parse', baseline+'^{tree}'], cwd=self.source)
        head_tree = self.observed['treeSha']

        def commit(tree, parents, label):
            args = ['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
                    'commit-tree',tree]
            for parent in parents:
                args += ['-p',parent]
            return self.git.text([*args,'-m',label],cwd=self.source)

        merges, base = [], baseline
        for number in range(256,287):
            task = commit(base_tree,[base],f'task {number}')
            base = commit(base_tree,[base,task],f'merge {number}')
            merges.append({'number':number,'headSha':task,'mergeSha':base,'impact':{}})
        head = commit(head_tree,[base],'successor')
        merge = commit(head_tree,[base,head],'deliver successor')
        self.git.run(['branch','transfer',merge],cwd=self.source)
        bundle_path=self.root/'transition.bundle'
        self.git.run(['bundle','create',bundle_path,'refs/heads/transfer'],cwd=self.source)
        bundle=bundle_path.read_bytes()
        gap={'disposition':'OWNER_REVIEWED_POST_285_CAPTURE_GAP','merges':merges}
        catalog_sha=self.observed['catalogSha256']
        authority='d'*64
        config_root=self.root/'owner-config'
        config_root.mkdir(mode=0o700)
        validator_mount=self.root/'validator-mount'
        validator_mount.mkdir(mode=0o700)
        self.git.run(['clone','--bare',self.code,validator_mount/'validator.git'],cwd=self.root,protocols='file')
        self.verifier.repository=tc.REPOSITORY
        profile=from_resolved_catalog(self.catalog,_resolved(self.binding,self.catalog),
            repository=tc.REPOSITORY,catalog_sha256=catalog_sha,build_pins={})
        profile_pin=sc.digest(profile)
        self.verifier.profile_digest=profile_pin
        observed={**self.observed,'repository':tc.REPOSITORY,'number':287,'baseSha':base,'headSha':head}
        impact=self.verifier.verify(observed)
        ci={k:observed[k] for k in ('repository','number','baseSha','headSha')}
        runs, checks = [], []
        for workflow in WORKFLOWS:
            run_id = len(runs)+1
            jobs = []
            for name in workflow.jobs:
                ident=len(checks)+1
                jobs.append({'id':ident,'name':name,'status':'completed','conclusion':'success'})
                checks.append({'name':name,'checkRunId':ident,'runId':run_id,'attempt':1,
                               'workflowId':workflow.ident,'headSha':head,'conclusion':'success'})
            runs.append({'workflowPath':workflow.path,'workflowSha256':workflow.sha256,
                         'runId':run_id,'attempt':1,'workflowId':workflow.ident,'jobs':jobs})
        ci.update(schemaVersion=1,policyDigest='a'*64,rulesDigest='b'*64,compositionDigest='c'*64,
                  runs=runs,checks=checks,validatorRevision=self.pin,validatedImpactDigest=sc.digest(impact))
        proposal={k:observed[k] for k in ('repository','number','baseSha','headSha','treeSha',
                  'catalogSha256','bodyDigest','impactDigest','pathsDigest')}
        proposal.update({k:impact[k] for k in ('profileDigest','classification','targets','dependencies')},
                        expectedSourceRevision=0,ciDigest=sc.digest(ci),dependencyDigest=sc.digest([]))

        with ExitStack() as contexts:
            def fixture(module,attr,value):
                contexts.enter_context(patch.object(module,attr,value))
            for module,attr,value in ((lc,'BASELINE',baseline),(lc,'FINAL_GAP',merges[-1]),
                (tc,'BASE_SHA',base),(tc,'BASE_CATALOG',catalog_sha),(tc,'GAP_PREFIX',sc.digest(merges[:-1])),
                (protected,'VALIDATOR_MOUNT',validator_mount),(protected,'_check_owner_readonly_mount',lambda _:None),
                (boot,'_runtime_confinement',lambda:None),(entry,'_readonly_owner_runtime',lambda _:config_root),
                (boot.os,'getgroups',lambda:[])):
                fixture(module,attr,value)
            manifest=fixture_manifest()
            manifest['old']['historicalGapDigest']=sc.digest(gap)
            manifest['pr'].update({k:proposal[k] for k in ('number','baseSha','headSha','treeSha',
                                   'bodyDigest','impactDigest','pathsDigest','ciDigest')})
            manifest['successor'].update(catalogSha256=catalog_sha,validatorRevision=self.pin,
                                         actionRevision='8b82564728c55807c57d1c9e1f0f974ea14fd6d6')
            scope={'repository':tc.REPOSITORY,'enrollmentId':manifest['transitionId'],
                   'baselineSha':baseline,'baselineDigest':'a'*64,'catalogSha256':catalog_sha,
                   'bindingDigest':'b'*64,'policyReferenceDigest':'c'*64}
            state_path=self.state/'registry.sqlite'
            config_path=config_root/'profile.json'
            socket_path=self.root/'socket'/'reader.sock'
            for attr,value in (('STATE_PATH',state_path),('CONFIG_PATH',config_path),('SOCKET_PATH',socket_path)):
                fixture(boot,attr,value)
            instance=manifest['old']['registry']['instanceId']
            original=boot.FunctionalV1CandidateJournal.initialize(self.root/'original.sqlite',
                instance_id=instance,scope=scope,plan_reader=boot._disabled)
            shutil.copy2(original.path,state_path)
            before=original.path.read_bytes()
            witness=legacy_prefix_witness(original)
            manifest['old']['registry']=witness
            manifest_pin=sc.digest(manifest)
            post={k:proposal[k] for k in ('repository','number','headSha','treeSha','catalogSha256',
                                         'bodyDigest','impactDigest','pathsDigest','ciDigest')}
            post.update(mergeSha=merge,mainSha=merge,parents=[base,head])
            envelope={'manifest':manifest,'oldState':manifest['old'],'gap':gap,
                      'gapObservation':{'baseSha':baseline,'endSha':base,'gapDigest':sc.digest(gap)},
                      'proposal':proposal,'observation':post,'ci':ci,'body':observed['body'],
                      'bundleSha256':sha(bundle)}
            pins={'legacyWitness':witness,'transitionDigest':manifest_pin,
                  'legacyProfileDigest':profile_pin,'successorProfileDigest':profile_pin,
                  'generation':'a'*64,'internalActor':'internal','peerKeyDigest':sha(b'p'*32),
                  'frameKeyDigest':sha(b'f'*32),'readGrants':[{'actor':'agent-1',
                  'operation':'get_component','subject':profile['subjects'][0]['subject']}]}
            cfg={'schemaVersion':3,'instanceId':instance,'scope':scope,'registryStatePath':str(state_path),
                 'socketPath':str(socket_path),'readerUid':10001,'readerGid':10001,'semantic':pins,
                 'sourceWrite':{'policyAuthorityDigest':authority,'validatorRevision':self.pin,
                                'impactBinding':self.binding,'buildPins':{},'ownerActor':'owner',
                                'ownerName':'owner','target':'app','interlockDigest':'b'*64}}

            def write(name, data):
                target=config_root/name
                target.write_bytes(data if isinstance(data,bytes) else sc.canonical(data).encode())
                target.chmod(0o600)
                return sha(target.read_bytes())

            profile_file_sha=write('profile.json',cfg)
            evidence_sha=write('transition-evidence.json',envelope)
            write('transition-main.bundle',bundle)
            write('successor-release-profile.json',profile)
            write('semantic-peer.key',b'p'*32)
            write('semantic-frame.key',b'f'*32)

            def prepare(evidence=evidence_sha):
                return boot.prepare_successor(profile_file_sha,transition_evidence_sha256=evidence,
                                              source_sha=merge)

            with self.assertRaisesRegex(Denied,'SOURCE_TRANSITION_EVIDENCE_PIN_CHANGED'):
                prepare('0'*64)
            alternate=sc.loads_strict(sc.canonical(profile))
            alternate['subjects'][0]['resources']=['remapped-state']
            pins['legacyProfileDigest']=write('legacy-release-profile.json',alternate)
            profile_file_sha=write('profile.json',cfg)
            with self.assertRaisesRegex(Denied,'SOURCE_PROFILE_REMAP_REQUIRED'):
                prepare()
            self.assertEqual(state_path.read_bytes(),before)
            pins['legacyProfileDigest']=write('legacy-release-profile.json',profile)
            profile_file_sha=write('profile.json',cfg)

            receipt=prepare()
            self.assertFalse(receipt['sourceTransitionPending'])
            accepted=receipt['sourceTransitionReceipt']
            self.assertEqual(accepted['operationId'],manifest['transitionId'])
            self.assertEqual(accepted['sourceCursor'],merge)
            self.assertFalse(accepted['deploymentAuthorized'])
            self.assertEqual(original.path.read_bytes(),before)
            store=ReleaseEventJournal(state_path,instance_id=instance,scope=scope,
                expected_legacy=witness,transition_digest=manifest_pin)
            domain=protected.staged_domain(store,config_root,pins)
            self.assertEqual(domain.source_operation(manifest['transitionId']),accepted)
            state=next(iter(domain.snapshot()['states'].values()))
            self.assertEqual(state['desired']['provenance'],'REVIEWED_TRANSITION')
            self.assertIsNone(state['installed'])

            # The normal writer entry point opens that exact migrated DB.
            from fortis_approvals.tests.test_semantic_wire import read_service_via_entrypoint
            from fortis_approvals.registry import protected_source_write as writer
            fixture(writer.ProtectedSourceWrite,'_check_source',lambda *_:None)
            fixture(writer,'read_owner_interlock',lambda **_:{'phase':'NORMAL'})
            fixture(writer,'InterlockReservations',Mock)
            selected=read_service_via_entrypoint(config_path,readonly=False,expected_profile=profile_file_sha)
            self.assertEqual(selected.frames.service.domain.source_operation(manifest['transitionId']),accepted)
            self.assertEqual(selected.frames.service.domain.snapshot()['sourceCursor'],merge)
            with self.assertRaises(Denied):
                prepare()
            self.assertEqual(domain.source_operation(manifest['transitionId']),accepted)

            # The repair uses a new real Git merge with the exact staged
            # transition as first parent. The retained source event stays intact.
            from copy import deepcopy
            from fortis_approvals.registry import source_event_journal as source_events
            fixture(source_events, '_DELIVERY_287', merge)
            (self.source/'src.py').write_text('raise RuntimeError("repair code must not execute")\n')
            self.git.run(['add','src.py'], cwd=self.source)
            repair_tree = self.git.text(['write-tree'], cwd=self.source)
            repair_head = commit(repair_tree, [merge], 'repair head')
            repair_merge = commit(repair_tree, [merge,repair_head], 'repair merge')
            observed_repair = {**observed,'number':288,'baseSha':merge,'headSha':repair_head,
                               'treeSha':repair_tree}
            repair_impact = self.verifier.verify(observed_repair)
            repair_ci = {**deepcopy(ci),'number':288,'baseSha':merge,'headSha':repair_head,
                         'validatedImpactDigest':sc.digest(repair_impact)}
            for check in repair_ci['checks']:
                check.update(headSha=repair_head,appId=15368,appSlug='github-actions')
            repair_proposal = {**proposal,'number':288,'baseSha':merge,'headSha':repair_head,
                               'treeSha':repair_tree,'expectedSourceRevision':1,
                               'ciDigest':sc.digest(repair_ci)}
            repair_post = {**post,'number':288,'headSha':repair_head,'treeSha':repair_tree,
                           'mergeSha':repair_merge,'mainSha':repair_merge,'parents':[merge,repair_head],
                           'ciDigest':repair_proposal['ciDigest']}

            def repair_bundle(merge_sha, material='delivery-repair'):
                self.git.run(['branch','-f','transfer',merge_sha],cwd=self.source)
                self.git.run(['bundle','create',bundle_path,'refs/heads/transfer'],cwd=self.source)
                return write(material+'-main.bundle',bundle_path.read_bytes())

            repair_evidence = {'predecessorReceipt':accepted,'proposal':repair_proposal,
                               'observation':repair_post,'ci':repair_ci,'body':observed_repair['body'],
                               'bundleSha256':repair_bundle(repair_merge)}

            def repair(evidence, source=repair_merge):
                pin = write('delivery-repair-evidence.json',evidence)
                return boot.account_delivery_repair(profile_file_sha,repair_evidence_sha256=pin,source_sha=source)

            before_repair = state_path.read_bytes()
            wrong_predecessor = {**repair_evidence,'predecessorReceipt':{**accepted,'eventDigest':'0'*64}}
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_PREDECESSOR'):
                repair(wrong_predecessor)
            wrong_ci = deepcopy(repair_evidence)
            wrong_ci['ci']['checks'][0]['appId'] = 1
            wrong_pin = sc.digest(wrong_ci['ci'])
            wrong_ci['proposal']['ciDigest'] = wrong_ci['observation']['ciDigest'] = wrong_pin
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_CI_CHANGED'):
                repair(wrong_ci)
            bad_merge = commit(repair_tree,[base,repair_head],'skipped transition')
            bad_ancestry = {**repair_evidence,
                'observation':{**repair_post,'mergeSha':bad_merge,'mainSha':bad_merge},
                'bundleSha256':repair_bundle(bad_merge)}
            with self.assertRaisesRegex(Denied,'SUCCESSOR_MERGE_GIT_OBJECT_CHANGED'):
                repair(bad_ancestry,bad_merge)
            self.assertEqual(state_path.read_bytes(),before_repair)
            self.assertEqual(repair_bundle(repair_merge),repair_evidence['bundleSha256'])

            result = repair(repair_evidence)
            self.assertEqual(result['predecessorReceipt'],accepted)
            self.assertEqual(result['legacyPrefixDigest'],witness['prefixDigest'])
            self.assertFalse(result['admissionAllowed'])
            source_receipt = result['sourceRepairReceipt']
            self.assertEqual(source_receipt['kind'],'DELIVERY_REPAIR')
            self.assertEqual(source_receipt['sourceRevision'],2)
            self.assertEqual(source_receipt['sourceCursor'],repair_merge)
            self.assertFalse(source_receipt['deploymentAuthorized'])
            after_repair = state_path.read_bytes()
            self.assertEqual(repair(repair_evidence),result)
            self.assertEqual(state_path.read_bytes(),after_repair)

            reopened = read_service_via_entrypoint(config_path,readonly=False,expected_profile=profile_file_sha)
            view = reopened.frames.service.domain.snapshot()
            self.assertEqual(view['sourceCursor'],repair_merge)
            self.assertEqual(view['sourceOperations'][accepted['operationId']][1],accepted)
            req, saved, _ = view['sourceOperations'][source_receipt['operationId']]
            self.assertEqual(saved,source_receipt)
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_OFFLINE_REQUIRED'):
                reopened.frames.service.domain.register_source(req)
            state = next(iter(view['states'].values()))
            self.assertEqual(state['desired']['provenance'],'REVIEWED_DELIVERY_REPAIR')
            self.assertIsNone(state['installed'])
            self.assertEqual(original.path.read_bytes(),before)
            running_domain = reopened.frames.service.domain
            with self.assertRaisesRegex(Stale,'SOURCE_PREVIEW_STALE'):
                running_domain.source_preflight(repair_proposal)
            next_pr = {**repair_proposal,'number':289,'baseSha':repair_merge,
                       'expectedSourceRevision':2}
            self.assertEqual(running_domain.source_preflight(next_pr)['sourceCursor'],repair_merge)

            # The next correction is prepared on an inactive separate
            # copy. Keep the revision-two source readable for Return until
            # activation, without exposing the new receipt as accepted.
            frozen_state = state_path
            frozen_config = config_root
            frozen_files = {p.name:p.read_bytes() for p in frozen_config.iterdir()}
            frozen_view = running_domain.snapshot()
            state_path = self.state/'corrective'/'registry.sqlite'
            state_path.parent.mkdir(mode=0o700)
            shutil.copy2(frozen_state,state_path)
            config_root=self.root/'corrective-config'
            shutil.copytree(frozen_config,config_root)
            config_path=config_root/'profile.json'
            cfg={**cfg,'registryStatePath':str(state_path)}
            profile_file_sha=write('profile.json',cfg)
            fixture(boot,'STATE_PATH',state_path)
            fixture(boot,'CONFIG_PATH',config_path)
            self.assertEqual(state_path.read_bytes(),after_repair)
            fixture(source_events, '_DELIVERY_288', repair_merge)
            fixture(source_events, '_DELIVERY_288_EVENT', source_receipt['eventDigest'])
            (self.source/'src.py').write_text('raise RuntimeError("restart repair fixture")\n')
            self.git.run(['add','src.py'],cwd=self.source)
            next_tree=self.git.text(['write-tree'],cwd=self.source)
            next_head=commit(next_tree,[repair_merge],'restart repair head')
            next_merge=commit(next_tree,[repair_merge,next_head],'restart repair merge')
            next_observed={**observed_repair,'number':289,'baseSha':repair_merge,
                           'headSha':next_head,'treeSha':next_tree}
            next_impact=self.verifier.verify(next_observed)
            next_ci={**deepcopy(repair_ci),'number':289,'baseSha':repair_merge,
                     'headSha':next_head,'validatedImpactDigest':sc.digest(next_impact)}
            for check in next_ci['checks']:
                check['headSha']=next_head
            next_proposal={**repair_proposal,'number':289,'baseSha':repair_merge,
                           'headSha':next_head,'treeSha':next_tree,'expectedSourceRevision':2,
                           'ciDigest':sc.digest(next_ci)}
            next_post={**repair_post,'number':289,'headSha':next_head,'treeSha':next_tree,
                       'mergeSha':next_merge,'mainSha':next_merge,'parents':[repair_merge,next_head],
                       'ciDigest':next_proposal['ciDigest']}
            next_evidence={'predecessorReceipt':source_receipt,'proposal':next_proposal,
                           'observation':next_post,'ci':next_ci,'body':next_observed['body'],
                           'bundleSha256':repair_bundle(next_merge,'delivery-repair-2')}

            def second_repair(evidence=next_evidence, revision=2):
                pin=write('delivery-repair-2-evidence.json',evidence)
                return boot.account_delivery_repair(profile_file_sha,repair_evidence_sha256=pin,
                    source_sha=next_merge,predecessor_revision=revision)

            with patch.object(source_events,'_DELIVERY_288_EVENT','0'*64):
                with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_PREDECESSOR'):
                    second_repair()
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_SCOPE'):
                second_repair(revision=3)
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_PREDECESSOR'):
                second_repair({**next_evidence,'predecessorReceipt':accepted})
            old_material=(config_root/'delivery-repair-evidence.json').read_bytes()
            write('delivery-repair-evidence.json',b'{}')
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_ORIGINAL_EVIDENCE_CHANGED'):
                second_repair()
            write('delivery-repair-evidence.json',old_material)
            self.assertEqual(state_path.read_bytes(),after_repair)

            second_result=second_repair()
            third=second_result['sourceRepairReceipt']
            self.assertEqual(second_result['predecessorReceipt'],source_receipt)
            self.assertEqual(third['sourceRevision'],3)
            self.assertEqual(third['sourceCursor'],next_merge)
            self.assertFalse(third['deploymentAuthorized'])
            after_second=state_path.read_bytes()
            self.assertEqual(second_repair(),second_result)
            self.assertEqual(state_path.read_bytes(),after_second)
            self.assertEqual((config_root/'delivery-repair-evidence.json').read_bytes(),old_material)
            final_view=read_service_via_entrypoint(
                config_path,readonly=False,expected_profile=profile_file_sha).frames.service.domain.snapshot()
            self.assertEqual(final_view['sourceCursor'],next_merge)
            for original_receipt in (accepted,source_receipt,third):
                self.assertEqual(final_view['sourceOperations'][original_receipt['operationId']][1],
                                 original_receipt)
            with self.assertRaisesRegex(Denied,'SOURCE_DELIVERY_REPAIR_STAGED_STATE_CHANGED'):
                repair(repair_evidence)
            self.assertEqual(state_path.read_bytes(),after_second)
            self.assertIsNone(next(iter(final_view['states'].values()))['installed'])
            # Even after target preparation, the original source and its
            # two receipts remain unchanged and independently readable.
            self.assertEqual(frozen_state.read_bytes(),after_repair)
            self.assertEqual({p.name:p.read_bytes() for p in frozen_config.iterdir()},frozen_files)
            self.assertEqual(running_domain.snapshot(),frozen_view)
            self.assertEqual(frozen_view['sourceRevision'],2)
            self.assertNotIn(third['operationId'],frozen_view['sourceOperations'])
            source_checkpoint=protected.corrective_checkpoint(running_domain,
                expected_revision=2,expected_source_sha=repair_merge)
            target_checkpoint=protected.corrective_checkpoint(
                read_service_via_entrypoint(config_path,readonly=False,
                    expected_profile=profile_file_sha).frames.service.domain,
                expected_revision=3,expected_source_sha=next_merge)
            self.assertEqual(protected.verify_corrective_pair(source_checkpoint,target_checkpoint,
                expected_source_sha=next_merge),{'source':source_checkpoint,'target':target_checkpoint})
            # Simulate the stopped-source RO mount. Real SQLite scratch
            # replay must include committed WAL and leave original files
            # byte-identical; the host mount guard is substituted here only.
            import sqlite3
            from contextlib import closing
            from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
            wal_dir=self.root/'frozen-wal-fixture'
            wal_dir.mkdir(mode=0o700)
            wal_state=wal_dir/frozen_state.name
            shutil.copy2(frozen_state,wal_state)
            old_store=running_domain.store
            wal_store=ReleaseEventJournal(wal_state,instance_id=old_store.instance_id,
                scope=old_store.scope,expected_legacy=old_store.expected_legacy,
                transition_digest=old_store.transition_digest)
            with closing(sqlite3.connect(wal_state)) as db:
                db.execute('PRAGMA wal_autocheckpoint=0')
                db.execute('PRAGMA user_version=4')
                db.commit()
                wal=Path(str(wal_state)+'-wal')
                self.assertGreater(wal.stat().st_size,32)
                original={p.name:p.read_bytes() for p in wal_dir.iterdir()}
                with patch.object(protected,'_check_owner_readonly_mount'):
                    self.assertEqual(protected.frozen_corrective_checkpoint(
                        wal_store,frozen_config,
                        sc.loads_strict((frozen_config/'profile.json').read_bytes())['semantic'],
                        expected_revision=2,expected_source_sha=repair_merge),source_checkpoint)
                self.assertEqual({p.name:p.read_bytes() for p in wal_dir.iterdir()},original)
                # Real stage helper copies the committed snapshot to a
                # distinct empty target and verifies the exact source receipt.
                target_root=self.root/'corrective-copy-fixture'
                target_root.mkdir(mode=0o700)
                with (patch.object(protected,'_check_owner_readonly_mount'),
                      patch('fortis_approvals.r7_registry_reader_mount._exact_mountinfo',return_value=True)):
                    self.assertEqual(protected.stage_corrective_registry(
                        wal_store,frozen_config,
                        sc.loads_strict((frozen_config/'profile.json').read_bytes())['semantic'],
                        target=target_root/wal_state.name,expected_checkpoint=source_checkpoint),
                        source_checkpoint)
                    with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_TARGET_NOT_FRESH'):
                        protected.stage_corrective_registry(wal_store,frozen_config,
                            sc.loads_strict((frozen_config/'profile.json').read_bytes())['semantic'],
                            target=target_root/wal_state.name,expected_checkpoint=source_checkpoint)
                self.assertEqual({p.name:p.read_bytes() for p in wal_dir.iterdir()},original)

            with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_STATE_CHANGED'):
                protected.corrective_checkpoint(running_domain,expected_revision=3,
                                                 expected_source_sha=next_merge)
            with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_PAIR_CHANGED'):
                protected.verify_corrective_pair(source_checkpoint,
                    {**target_checkpoint,'sourcePrefixDigest':'0'*64},expected_source_sha=next_merge)
            with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_PAIR_CHANGED'):
                protected.verify_corrective_pair(source_checkpoint,target_checkpoint,
                                                 expected_source_sha=repair_merge)
            self.assertEqual(frozen_state.read_bytes(),after_repair)
            self.assertEqual(state_path.read_bytes(),after_second)
            # The earlier regular readback can leave empty SQLite sidecars.
            # Exact offline accounting retry closes them via SQLite, never
            # by unlinking the journal. This is the actual preview boundary.
            self.assertEqual(second_repair(),second_result)
            self.assertEqual(state_path.read_bytes(),after_second)
            # Preview uses the actual entrypoint and the same sealed profile,
            # but physically read-only state and no mutable frame admission.
            with self.assertRaisesRegex(Denied,'REGISTRY_SEMANTIC_READONLY_STATE_REQUIRED'):
                read_service_via_entrypoint(config_path,readonly=False,expected_profile=profile_file_sha,
                                            corrective_preview_sha=next_merge)
            with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_STATE_CHANGED'):
                read_service_via_entrypoint(config_path,readonly=True,expected_profile=profile_file_sha,
                                            corrective_preview_sha=repair_merge)
            # A stale/uncheckpointed sidecar must not be silently ignored
            # by immutable SQLite. Exercise the exact negative before reopen.
            side=Path(str(state_path)+'-wal')
            self.assertFalse(side.exists())
            side.write_bytes(b'fixture')
            side.chmod(0o600)
            try:
                with self.assertRaisesRegex(Denied,'REGISTRY_CORRECTIVE_PREVIEW_UNCHECKPOINTED'):
                    read_service_via_entrypoint(config_path,readonly=True,expected_profile=profile_file_sha,
                                                corrective_preview_sha=next_merge)
            finally:
                side.unlink()
            preview=read_service_via_entrypoint(config_path,readonly=True,expected_profile=profile_file_sha,
                                                corrective_preview_sha=next_merge)
            with self.assertRaisesRegex(Denied,'REGISTRY_CORRECTIVE_PREVIEW_READ_ONLY'):
                preview.frames.store._db()
            self.assertIsNone(preview.frames.source_authorize)
            self.assertIsNone(preview.frames.source_reservation)
            self.assertIsNotNone(preview.frames.source_delivery)
            actor=preview.frames.internal_actor
            from fortis_approvals.integrations.registry_contracts import semantic_wire as wire
            import uuid
            def signed(action,body):
                pins=preview.frames.pins
                request=wire.request({'schemaVersion':2,'requestId':str(uuid.uuid4()),
                    'instanceId':pins['instance'],'scopeDigest':pins['scope'],
                    'generation':pins['generation'],'actor':actor,'action':action,'body':body},**pins)
                frame=wire.seal(preview.frames.key,request)
                # Same host mount substitution used at preview entrypoint;
                # the database itself opens through real immutable SQLite.
                with patch('fortis_approvals.r7_registry_reader_mount._check_owner_readonly_mount'):
                    return wire.open_reply(preview.frames.key,request,preview.frames.dispatch(frame))
            self.assertEqual(signed('HOLD_SNAPSHOT',{})['snapshotRevision'],3)
            for op in ('WRITE','BEGIN_GROUP','SOURCE_REGISTER','SOURCE_REGISTER_EXTERNAL','SOURCE_PREFLIGHT','READ'):
                self.assertFalse(preview.frames.authorize(actor,op,{}))
                self.assertFalse(preview.frames.authorize('owner-actor',op,{}))
            with self.assertRaisesRegex(Denied,'SEMANTIC_WIRE_SCOPE_DENIED'):
                signed('SOURCE_PREFLIGHT',{'proposal':next_proposal})
            self.assertEqual(state_path.read_bytes(),after_second)

            # A separately reviewed bootstrap is not a third repair. Use
            # the real Git/CI/SQLite fixture with synthetic owner proof pins.
            # Patch only the exact historical edge constants for this repo.
            fixture(source_events,'_BOOTSTRAP_BASE',next_merge)
            fixture(source_events,'_BOOTSTRAP_EVENT',third['eventDigest'])
            incumbent_path,incumbent_config=state_path,config_root
            incumbent_files={p.name:p.read_bytes() for p in config_root.iterdir()}
            fixture(boot,'_BOOTSTRAP_INCUMBENT_PROFILE',sha(incumbent_files['profile.json']))
            fixture(boot,'_BOOTSTRAP_INCUMBENT_CONFIG',incumbent_config/'profile.json')
            fixture(boot,'_BOOTSTRAP_INCUMBENT_STATE',incumbent_path)
            fixture(boot,'_BOOTSTRAP_INSTALLED_STATE',incumbent_path)
            incumbent_store=ReleaseEventJournal(incumbent_path,instance_id=instance,scope=scope,
                expected_legacy=witness,transition_digest=manifest_pin)
            prefix=protected.bootstrap_prefix(final_view,incumbent_store)
            state_path=self.state/'bootstrap-clone'/'registry.sqlite'
            state_path.parent.mkdir(mode=0o700)
            with (patch.object(protected,'_check_owner_readonly_mount'),
                  patch('fortis_approvals.r7_registry_reader_mount._exact_mountinfo',return_value=True)):
                with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_STAGE_SOURCE_CHANGED'):
                    protected.stage_bootstrap_registry(incumbent_store,incumbent_config,pins,
                        target=state_path,expected_prefix={**prefix,'sourcePrefixDigest':'0'*64})
                self.assertFalse(state_path.exists())
                self.assertEqual(protected.stage_bootstrap_registry(incumbent_store,incumbent_config,pins,
                    target=state_path,expected_prefix=prefix),prefix)
                with self.assertRaisesRegex(Denied,'SOURCE_CORRECTIVE_TARGET_NOT_FRESH'):
                    protected.stage_bootstrap_registry(incumbent_store,incumbent_config,pins,
                        target=state_path,expected_prefix=prefix)
            config_root=self.root/'bootstrap-config'
            shutil.copytree(incumbent_config,config_root)
            config_path=config_root/'profile.json'
            cfg={**cfg,'registryStatePath':str(state_path)}
            profile_file_sha=write('profile.json',cfg)
            fixture(boot,'STATE_PATH',state_path)
            fixture(boot,'CONFIG_PATH',config_path)
            (self.source/'src.py').write_text('raise RuntimeError("bootstrap code must not execute")\n')
            self.git.run(['add','src.py'],cwd=self.source)
            migration_tree=self.git.text(['write-tree'],cwd=self.source)
            migration_head=commit(migration_tree,[next_merge],'bootstrap head')
            migration_merge=commit(migration_tree,[next_merge,migration_head],'bootstrap merge')
            migration_observed={**next_observed,'number':291,'baseSha':next_merge,
                                'headSha':migration_head,'treeSha':migration_tree}
            migration_impact=self.verifier.verify(migration_observed)
            migration_ci={**deepcopy(next_ci),'number':291,'baseSha':next_merge,'headSha':migration_head,
                          'validatedImpactDigest':sc.digest(migration_impact)}
            for check in migration_ci['checks']:check['headSha']=migration_head
            migration_proposal={**next_proposal,'number':291,'baseSha':next_merge,'headSha':migration_head,
                'treeSha':migration_tree,'expectedSourceRevision':3,'ciDigest':sc.digest(migration_ci)}
            migration_post={**next_post,'number':291,'headSha':migration_head,'treeSha':migration_tree,
                'mergeSha':migration_merge,'mainSha':migration_merge,'parents':[next_merge,migration_head],
                'ciDigest':migration_proposal['ciDigest']}
            review={'schemaVersion':1,'prefix':prefix,'proposal':migration_proposal,'authorityDigest':authority,
                    'authorityWitnessDigest':'1'*64,'primaryRecordDigest':'2'*64,'gatewayBackupDigest':'3'*64,
                    'registryBackupDigest':'4'*64}
            def proof_for(content):
                return sc.canonical({'schema':'fortis-registry-bootstrap-review-v1',
                    'decision':'APPROVE_BOOTSTRAP_MERGE','reviewContentDigest':sc.digest(
                        {k:v for k,v in content.items() if k!='ownerReviewProofDigest'}),'reviewedAt':100}).encode()
            proof_raw=proof_for(review)
            review['ownerReviewProofDigest']=sha(proof_raw)
            review_pin=write('bootstrap-review.json',review)
            evidence={'reviewDigest':review_pin,'observation':migration_post,'ci':migration_ci,
                'body':migration_observed['body'],'bundleSha256':repair_bundle(migration_merge,'bootstrap'),'mergedAt':101}
            clone_before=state_path.read_bytes()
            def account(review_value=review,evidence_value=evidence,*,pin=None,source=migration_merge,mount=True,proof=None):
                if proof is None:
                    proof=proof_for(review_value)
                    updated={**review_value,'ownerReviewProofDigest':sha(proof)}
                    if evidence_value['reviewDigest']==sc.digest(review_value):
                        evidence_value={**evidence_value,'reviewDigest':sc.digest(updated)}
                    review_value=updated
                reviewed_pin=write('bootstrap-review.json',review_value)
                evidence_pin=write('bootstrap-evidence.json',evidence_value)
                with patch('fortis_approvals.r7_registry_reader_mount._exact_mountinfo',return_value=mount):
                    return boot.account_bootstrap_migration(profile_file_sha,
                        review_sha256=pin or reviewed_pin,evidence_sha256=evidence_pin,source_sha=source,owner_review_raw=proof)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_OWNER_REVIEW_CHANGED'):
                account(proof=b'{}')
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_OWNER_REVIEW_ORDER_UNPROVEN'):
                account(evidence_value={**evidence,'mergedAt':100})
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_CLONE_MOUNT_REQUIRED'):
                account(mount=False)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_EVIDENCE_PIN_CHANGED'):
                account(pin='0'*64)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_REVIEW_CHANGED'):
                account(evidence_value={**evidence,'reviewDigest':'0'*64})
            for bad,code in (({**review,'prefix':{**prefix,'sourcePrefixDigest':'0'*64}},
                              'SOURCE_BOOTSTRAP_REVIEW_CHANGED'),
                             ({**review,'authorityDigest':'0'*64},'SOURCE_BOOTSTRAP_RUNTIME_PINS_CHANGED')):
                with self.assertRaisesRegex(Denied,code):
                    account(bad,{**evidence,'reviewDigest':sc.digest(bad)})
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_RUNTIME_PINS_CHANGED'):
                account(source=next_merge)
            bad_ci=deepcopy(migration_ci);bad_ci['checks'][0]['appId']=1
            bad_review={**review,'proposal':{**migration_proposal,'ciDigest':sc.digest(bad_ci)}}
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_CI_CHANGED'):
                account(bad_review,{**evidence,'reviewDigest':sc.digest(bad_review),'ci':bad_ci,
                    'observation':{**migration_post,'ciDigest':sc.digest(bad_ci)}})
            bad_merge=commit(migration_tree,[repair_merge,migration_head],'skipped incumbent')
            with self.assertRaisesRegex(Denied,'SUCCESSOR_MERGE_GIT_OBJECT_CHANGED'):
                account(evidence_value={**evidence,'observation':{**migration_post,
                    'mergeSha':bad_merge,'mainSha':bad_merge},
                    'bundleSha256':repair_bundle(bad_merge,'bootstrap')},source=bad_merge)
            self.assertEqual(repair_bundle(migration_merge,'bootstrap'),evidence['bundleSha256'])
            self.assertEqual(state_path.read_bytes(),clone_before)
            self.assertEqual(incumbent_path.read_bytes(),after_second)
            # The actual launcher now stages a fresh clone itself. Keep
            # the negative-case fixture and its SQLite sidecars untouched.
            state_path=self.state/'bootstrap-integrated'/'registry.sqlite'
            state_path.parent.mkdir(mode=0o700)
            cfg={**cfg,'registryStatePath':str(state_path)}
            profile_file_sha=write('profile.json',cfg)
            fixture(boot,'STATE_PATH',state_path)
            self.assertFalse(list(state_path.parent.iterdir()))
            with patch.object(boot,'_BOOTSTRAP_INCUMBENT_PROFILE','0'*64):
                with self.assertRaisesRegex(Denied,'REGISTRY_SUCCESSOR_PROFILE_PIN_CHANGED'):account()
            self.assertFalse(list(state_path.parent.iterdir()))
            migration_result=account()
            migration_receipt=migration_result['sourceMigrationReceipt']
            self.assertEqual(migration_receipt['kind'],source_events.BOOTSTRAP_MIGRATION)
            self.assertEqual(migration_receipt['sourceRevision'],4)
            self.assertEqual(migration_receipt['sourceCursor'],migration_merge)
            self.assertFalse(migration_receipt['deploymentAuthorized'])
            self.assertFalse(migration_result['hostAccepted'])
            self.assertFalse(migration_result['admissionAllowed'])
            clone_after=state_path.read_bytes()
            self.assertEqual(account(),migration_result)
            self.assertEqual(state_path.read_bytes(),clone_after)
            migrated=read_service_via_entrypoint(config_path,readonly=False,expected_profile=profile_file_sha)
            migrated_domain=migrated.frames.service.domain
            migrated_view=migrated_domain.snapshot()
            for old_receipt in (accepted,source_receipt,third):
                self.assertEqual(migrated_view['sourceOperations'][old_receipt['operationId']][1],old_receipt)
            req,saved,_=migrated_view['sourceOperations'][migration_receipt['operationId']]
            self.assertEqual(saved,migration_receipt)
            with self.assertRaisesRegex(Denied,'SOURCE_BOOTSTRAP_OFFLINE_REQUIRED'):
                migrated_domain.register_source(req)
            self.assertEqual(migrated_view['sourceRevision'],4)
            self.assertEqual(migrated_view['sourceCursor'],migration_merge)
            self.assertEqual(migrated_domain.source_preflight({**migration_proposal,'number':292,
                'baseSha':migration_merge,'expectedSourceRevision':4})['sourceCursor'],migration_merge)
            state=next(iter(migrated_view['states'].values()))
            self.assertEqual(state['desired']['provenance'],'REVIEWED_BOOTSTRAP_MIGRATION')
            self.assertIsNone(state['installed'])
            self.assertIsNone(state['activeAttempt'])
            self.assertEqual(incumbent_path.read_bytes(),after_second)
            self.assertEqual({p.name:p.read_bytes() for p in incumbent_config.iterdir()},incumbent_files)
            print('BOOTSTRAP_MIGRATION_LOCAL_PREFIX_AND_READBACK_PASS')


    def test_owner_portal_exact_merge_register_and_shared_read(self):
        self._owner_portal_merge()

    def test_owner_portal_base_race_keeps_original_receipt_without_registration(self):
        self._owner_portal_merge(base_race=True)

    def test_owner_can_confirm_only_the_unstarted_registry_step(self):
        self._owner_portal_merge(partial=True)

    def test_external_merge_registration_uses_own_receipt_and_owner_approval(self):
        self._owner_portal_merge(external=True)

    def test_owner_portal_merge_and_shared_read_over_private_unix(self):
        self._owner_portal_merge(kernel_peer=True)

    def test_corrective_staged_reopen_keeps_compiled_authority(self):
        self._owner_portal_merge(kernel_peer=True, corrective=True)

    def _owner_portal_merge(self, *, base_race=False, partial=False, external=False,
                            kernel_peer=False, corrective=False):
        """Real source components with isolated Git, virtual passkey and synthetic GitHub."""
        from time import perf_counter
        from fortis_approvals.core import Authenticator
        from fortis_approvals.extensions.composite_authority import (
            ContextEnrollment, MergeContextGrant, ProviderGuard)
        from fortis_approvals.extensions.composite_contract import definition
        from fortis_approvals.extensions.composite_preservation import (
            install_checked, inspect_companion, legacy_schema_witness)
        from fortis_approvals.extensions.composite_successor import (
            CompositeUnifiedCore, ReviewedHistory, ReviewedRegistrySuccessor)
        from fortis_approvals.extensions.maintenance_gate import MaintenanceGate
        from fortis_approvals.extensions.owner_policy_editor_v2 import UnifiedPolicyPortal
        from fortis_approvals.extensions.owner_policy_engine_v2 import PolicyAdmission, UnifiedPolicyCore
        from fortis_approvals.extensions.owner_policy_r7_v2 import R7UnifiedPolicySourceOptIn
        from fortis_approvals.extensions.semantic_enrollment import SemanticEnrollment
        from fortis_approvals.extensions.native_merge_receipt import NativeMergeProvider
        from fortis_approvals.extensions.transition_authority import authority_witness
        from fortis_approvals.extensions.semantic_gateway import GatewayRegistrySemanticTransport
        from fortis_approvals.extensions.semantic_owner_portal import PREFIX
        from fortis_approvals.integrations.github.pilot import GitHubPilotConfig
        from fortis_approvals.integrations.registry.candidate_gateway import GatewayRegistryUnixCandidateRead
        from fortis_approvals.integrations.registry_contracts.transition_contract import BASE_CATALOG, REPOSITORY
        from fortis_approvals.owner_auth import OwnerWebAuthn
        from fortis_approvals.registry.semantic_unix_service import SemanticFrameService
        from fortis_approvals.repo_action_contract import RepoIntentBroker
        from fortis_approvals.repo_ingress import RepoIngress
        from fortis_approvals.tests.test_maintenance_gate import Controller, OLD
        from fortis_approvals.tests.test_owner_portal import G2WebAuthnTest, VirtualKey
        from fortis_approvals.tests.test_registry_source_lineage import LineageFixture
        from fortis_approvals.tests.test_semantic_access import SemanticAccessTests
        from fortis_approvals.tests.test_composite_successor import snapshot
        from fortis_approvals.synthetic import SyntheticAdapter
        from fortis_approvals.tests.test_semantic_wire import (
            WireTests, owner_read_configuration, read_service_via_entrypoint, start_kernel_semantic_peer)
        from fortis_approvals.workflow.adapters import NativeGitHubAdapter

        repo=REPOSITORY
        profile=from_resolved_catalog(self.catalog,_resolved(self.binding,self.catalog),
            repository=repo,catalog_sha256=sha(self.catalog_text.encode()),build_pins={})
        self.verifier.repository=repo
        self.verifier.profile_digest=sc.digest(profile)
        lineage=LineageFixture()
        lineage.addCleanup=self.addCleanup
        gateway_config = owner_scope = registry_instance = None
        if kernel_peer:
            from fortis_approvals.tests.test_r7_registry_reader_mount import (
                functional_mount_config, incumbent_286_ci_profile)
            registry_instance = str(uuid.uuid4())
            incumbent_profile = incumbent_286_ci_profile()
            gateway_config, owner_scope = functional_mount_config(
                baseline_sha=lc.BASELINE, catalog_sha=BASE_CATALOG, validator_revision=self.pin,
                instance_id=registry_instance, ci_profile=incumbent_profile)
        lineage.setUp(successor=(profile,self.catalog_text), owner_scope=owner_scope,
                      instance_id=registry_instance)
        transition=lineage.transition()
        from fortis_approvals.registry import source_event_journal as source_events
        transition_base=source_events._DELIVERY_287 if corrective else self.base
        transition['observation'].update(mergeSha=transition_base,mainSha=transition_base)
        transition_receipt=lineage.domain.register_source(transition)  # Synthetic predecessor fixture only.

        def fixture_repair(number, previous, cursor=None):
            # Seed the already verified historical receipt in this product
            # fixture. Actual evidence verification is covered by the existing
            # real Git/bundle test; never use this path for host accounting.
            req=lineage.merge(number=number)
            if cursor is not None:
                req['observation'].update(mergeSha=cursor,mainSha=cursor)
            req.update(kind=source_events.DELIVERY_REPAIR,parentRequestId=None,
                       operationId=source_events.delivery_repair_id(
                           previous['operationId'],req['observation']['mergeSha']),
                       transition={'predecessorOperationId':previous['operationId'],
                                   'predecessorEventDigest':previous['eventDigest']})
            with lineage.store._db() as db:
                view=lineage.domain._project(db)
                receipt=source_events.append(lineage.store,db,source_events.request(req,lineage.store),
                                             view['operations'])
                lineage.domain._project(db)
            return receipt

        if corrective:
            repair_receipt=fixture_repair(288,transition_receipt)
            self.enterContext(patch.object(source_events,'_DELIVERY_288',repair_receipt['sourceCursor']))
            self.enterContext(patch.object(source_events,'_DELIVERY_288_EVENT',repair_receipt['eventDigest']))
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],2)

        api=CheckProvider()
        api.head=self.head;api.base=self.base;api.ci_head=self.head
        observed={**self.observed,'repository':repo,'number':7,'headBranch':api.branch}
        api.body=observed['body']
        def retarget(value):
            return json.loads(json.dumps(value).replace(
                pub_fixture.OWNER+'/fortis-approvals',repo))
        merge=self.git.text(['-c','user.name=Fixture','-c','user.email=fixture@example.invalid',
            'commit-tree',observed['treeSha'],'-p',self.base,'-p',self.head,'-m','Fixture merge'],
            cwd=self.source)
        merged_signal=None
        evidence_root = None
        if kernel_peer:
            evidence_root = self.root/'registry-evidence'
            evidence_root.mkdir(mode=0o700)
            from fortis_approvals.integrations.registry_contracts import merge_evidence as proof
            proof_root = self.root/'proof'
            proof_root.mkdir(mode=0o750)
            proof_root.chmod(0o2750)
            self.enterContext(patch.object(proof, 'MOUNT', proof_root))
            self.enterContext(patch.object(proof, 'check_directory'))
            shutil.copytree(self.code, evidence_root/'validator.git')
            from multiprocessing import get_context
            merged_signal=get_context('fork').Event()

        class GitHub:
            writes=0
            external=False

            @property
            def merged(inner):
                return (inner.external or inner.writes>0 or
                        (merged_signal is not None and merged_signal.is_set()))

            def request(inner,method,path,**kw):
                if method=='PUT' and path.endswith('/pulls/7/merge'):
                    self.assertEqual(kw['body'],{'sha':self.head,'merge_method':'merge'})
                    self.assertEqual(inner.writes,0)
                    inner.writes+=1
                    if merged_signal is not None:
                        merged_signal.set()
                    return {'merged':True,'sha':merge}
                self.assertEqual(method,'GET')
                if path.endswith('/pulls/7'):
                    row=retarget({**api.pr(),'changed_files':1})
                    return ({**row,'state':'closed','merged':True,'merge_commit_sha':merge}
                            if inner.merged else row)
                if path.endswith('/pulls'):
                    return [] if inner.merged else [retarget({**api.pr(),'changed_files':1})]
                if path.endswith('/branches/main') and not path.endswith('/rules/branches/main'):
                    return {'name':'main','commit':{'sha':merge if inner.merged else self.base}}
                if path.endswith('/git/commits/'+merge):
                    return {'sha':merge,'tree':{'sha':observed['treeSha']},
                            'parents':[{'sha':x} for x in ('f'*40 if base_race else self.base,self.head)]}
                if path.endswith('/git/commits/'+self.head):
                    return {'sha':self.head,'tree':{'sha':observed['treeSha']}}
                if '/compare/' in path:
                    return {'status':'ahead','ahead_by':1,'base_commit':{'sha':self.base},
                        'merge_base_commit':{'sha':self.base},
                        'files':[{'filename':'src.py','status':'modified'}]}
                if path.endswith('/contents/release/targets.yaml'):
                    raw=self.catalog_text.encode()
                    return {'type':'file','path':'release/targets.yaml','encoding':'base64',
                            'size':len(raw),'content':base64.b64encode(raw).decode(),
                            'sha':observed['catalogBlobSha']}
                if kernel_peer:
                    return retarget(api.request(method,path.replace(repo,pub_fixture.OWNER+'/fortis-approvals',1),**kw))
                raise AssertionError(path)

        endpoint=GitHub()
        if kernel_peer:
            from fortis_approvals.workflow.git_backend import GitHubGitBackend
            fetches = []

            def fetch_bundle(repository, ref, expected):
                self.assertEqual(repository, 'fortis-approvals')
                current = ((merge if endpoint.merged else self.base) if ref == 'main' else self.head)
                self.assertIn(ref, ('main',api.branch))
                self.assertEqual(expected,current)
                fetches.append((ref,expected))
                with tempfile.TemporaryDirectory(dir=self.root) as tmp:
                    target = Path(tmp)/'upstream.bundle'
                    self.git.run(['update-ref','refs/heads/transfer',current],cwd=self.source)
                    self.git.run(['bundle','create',target,'refs/heads/transfer'],cwd=self.source)
                    data = target.read_bytes()
                return {'repository':repository,'ref':ref,'sha':expected,'bundleSha256':sha(data),
                        'bundle':base64.b64encode(data).decode()}

            self.enterContext(patch.object(GitHubGitBackend, 'fetch_bundle', side_effect=fetch_bundle))
        config_options = (dict(native_worktree=True, ci_reads=True,
                               file_pr_branch='fortis-e2e/'+str(uuid.uuid4())+'-approve',
                               required_workflows=tuple(w.ident for w in WORKFLOWS)) if kernel_peer else {})
        github_config=GitHubPilotConfig(*repo.split('/'), **config_options)
        native=NativeGitHubAdapter(endpoint,config=github_config,
            root=self.root,actor='agent-1',backend=None,store=None)
        class RetargetCI:
            def request(inner,method,path,**kwargs):
                path=path.replace(repo,pub_fixture.OWNER+'/fortis-approvals',1)
                return retarget(api.request(method,path,**kwargs))
        ci=make_ci(api,self.root/'ci.sqlite',repository=repo,transport=RetargetCI())
        projector=SuccessorProjector(self.verifier,ci,
            source_revision=lambda:lineage.domain.snapshot()['sourceRevision'],
            expected_composition_digest=sc.digest({'repository':repo,'validatorRevision':self.pin,
                'ciPolicyDigest':ci.pin,'profileDigest':sc.digest(profile)}))
        discovery=NativeMergeDiscovery(native,repository=repo,
            read_guard=lambda a,r,op,p:a=='owner-actor' and r==repo,
            branch_guard=lambda a,r,b:b==api.branch,project=projector)
        reader=NativeMergeReceiptReader(native,source_repository=self.source,
            state_root=self.state,read_guard=lambda ctx,kind,identity:
                ctx.actor=='owner-actor' and identity['repository']==repo)
        registry_source=SuccessorImpact(validator_repository=self.code,validator_revision=self.pin,
            source_repository=self.source,state_root=self.state,repository=repo,
            binding=self.binding,build_pins={},profile_digest=sc.digest(profile))
        def merged_body(p,observation):
            row=native._api('GET',native._path('fortis-approvals','pulls/'+str(p['number'])))
            self.assertEqual(row['merge_commit_sha'],observation['mergeSha'])
            self.assertTrue(row['merged'])
            return row['body']
        lineage.domain._source_verify=lambda req:registry_source.verify_registered_merge(
            req,read_merged_body=merged_body)
        from fortis_approvals.r7_unified_candidate import ACTOR as primary_actor
        semantic_actor = primary_actor if kernel_peer else 'agent-1'
        lineage.service.authorize=lambda a,op,s:a in ('owner-actor',semantic_actor) and s['repository']==repo
        self.frames=SemanticFrameService(lineage.service,frame_key=b'f'*32,generation=OLD,
            authorize=lambda a,act,b:a in ('owner-actor',semantic_actor,'internal'),
            provenance=lambda a:'OWNER_DIRECT',internal_actor='internal',
            source_authorize=lambda a,act,b:
                (a=='internal' if act=='SOURCE_PREFLIGHT' else a=='owner-actor'))
        from fortis_approvals.extensions.successor_runtime import _RETAINED_288_ENROLLMENT_SOURCE
        enrollment_source = _RETAINED_288_ENROLLMENT_SOURCE if corrective else 'a'*64
        opt_in=R7UnifiedPolicySourceOptIn(enrollment_source,lambda:'b'*64,
                                        allow_all_method_policy_upgrade=True)
        if kernel_peer:
            from functools import partial
            from fortis_approvals import r7_unified_server as server
            from fortis_approvals.extensions.runtime import ExtensionConfig
            from fortis_approvals.integrations.github.gateway.functional_review_runtime import (
                FunctionalRegistryConfiguration, initialize_functional_state)
            from fortis_approvals.r7_unified_candidate import ACTOR as machine_actor, _fresh_r7_state

            runtime_root = self.root/'gateway-state'
            runtime_root.mkdir(mode=0o700)
            _fresh_r7_state(runtime_root)
            initialize_functional_state(runtime_root, gateway_config['collectorInstanceId'])
            protected_source = runtime_root/'registry-functional-v1'
            shutil.rmtree(protected_source/'validator.git')
            shutil.copytree(self.code, protected_source/'validator.git')
            gateway_origin, gateway_host = 'http://localhost:19203', 'host.docker.internal:19204'
            machine_grant = 'A'*64
            extensions = ExtensionConfig({'schemaVersion':1, 'ownerPolicyEditor':'UNIFIED_V2',
                'ownerPolicyAuthorityUpgrade':'OWNER_ALL_METHODS_V1',
                'providers':{'registry':{'credentials':{}, 'operations':{
                    op:{'policy':'DENY', 'targets':['fortis-approvals']} for op in (
                        'candidate_head','candidate_list_desired','candidate_original_operation')}}}})
            incumbent_peer = object.__new__(GatewayRegistryUnixCandidateRead)
            incumbent_peer._instance, incumbent_peer._scope = lineage.instance, lineage.witness['scopeDigest']
            incumbent_peer._owner_pidfd = None
            incumbent_peer._peer_key, incumbent_peer._check_identity = b'p'*32, lambda: None
            # The incumbent binary treats the retained policy as current.
            from fortis_approvals.integrations.github.gateway import registry_review_policy
            with patch.object(registry_review_policy, 'policy', return_value=incumbent_profile):
                incumbent_peer._functional_config = FunctionalRegistryConfiguration(
                    gateway_config, b'p'*32, scope_digest=incumbent_peer._scope)
                old, owner, self.portal, _ = server.build_r7_unified_candidate(
                    state=runtime_root, owner_origin=gateway_origin, ingress_host=gateway_host,
                    ingress_grant=machine_grant, sonar_transport=server.SonarHTTPTransport(
                        region='eu', bearer_token='local-sonar-fixture-only'),
                    organizations=('pilot',), project_keys=('pilot',), github_pilot=github_config,
                    github_transport=endpoint, extensions=extensions, unified_policy_source_opt_in=opt_in,
                    registry_candidate_reader=incumbent_peer)
            old_scope = old.authority.scope_binding
            old_choices = dict(old.authority.choices)
            old_policies = dict(old.policies)
            native = old.adapters['github']
            owner_call = partial(G2WebAuthnTest.call.__get__(self), origin=gateway_origin,
                                 host=gateway_origin.removeprefix('http://'))
        else:
            machine_actor = 'agent-1'
            owner=OwnerWebAuthn(self.root/'owner.sqlite',origin='http://localhost:18990')
            machine=Authenticator({'machine-secret':'agent-1'})
            old_policies={('agent-1','synthetic','set_ask','existing'):'ASK'}
            old_choices={coord:{'DENY','ASK'} for coord in old_policies}
            old_scope={'fixture':'isolated predecessor'}
            synthetic=SyntheticAdapter(self.root/'ordinary.sqlite')
            core_path=self.root/'core.sqlite'
            old=UnifiedPolicyCore(core_path,adapters={'synthetic':synthetic},policies=old_policies,
                                 authenticator=machine,owner_verifier=owner)
            old.install_policy_authority(old_choices,scope_binding=old_scope)
            witness=snapshot(old,lambda db:authority_witness(old,db))
            owner_call = G2WebAuthnTest.call.__get__(self)
            self.portal = UnifiedPolicyPortal(old,owner)
        witness=snapshot(old,lambda db:authority_witness(old,db))
        history=snapshot(old,lambda db:ReviewedHistory(old,db,
                                    expected_witness_digest=sc.digest(witness)))

        if kernel_peer:
            from fortis_approvals import r7_registry_reader_mount as mount
            socket_peer = stop_peer = None
            gateway_root = self.root/'gateway-mount'
            gateway_root.mkdir(mode=0o700)
            raw = sc.canonical(gateway_config).encode()
            released = {
                'schemaVersion':5, 'enabled':True, 'purpose':'registry-functional-successor-v1',
                'releaseNonce':str(uuid.uuid4()), 'gatewaySourceDigest':enrollment_source,
                'instanceId':lineage.instance, 'scopeDigest':lineage.witness['scopeDigest'],
                'socketPath':str(self.root/'semantic-peer'/'registry.sock'),
                'registryUid':os.geteuid(), 'registryGid':os.getegid(),
                'readerUid':os.geteuid(), 'readerGid':os.getegid(),
                'functionalConfigSha256':sha(raw), 'plannerKeySha256':sha(b'p'*32),
                'semanticFrameKeySha256':sha(b'f'*32), 'semanticGeneration':OLD,
                'semanticProfileDigest':sc.digest(profile), 'semanticInternalActor':'internal',
                'policyHistorySha256':sc.digest(history.seal()),
            }

            def write_mounted(name, data):
                path = gateway_root/name
                path.write_bytes(data)
                path.chmod(0o600)

            write_mounted('functional.json', raw)
            write_mounted('planner.key', b'p'*32)
            write_mounted('semantic-frame.key', b'f'*32)
            write_mounted('policy-history.json', sc.canonical(history.seal()).encode())

            checkout_scratch = self.root/'controller-copy-scratch'
            checkout_scratch.mkdir(mode=0o700)

            def load_peer(seal, *, interlock=None, incumbent_core=None, reuse=False):
                if reuse:
                    self.assertEqual((gateway_root/'profile.json').read_bytes(),
                                     sc.canonical(seal).encode())
                else:
                    write_mounted('profile.json', sc.canonical(seal).encode())
                # This fixture runs both ends as one UID. The real socket and
                # managed peer proof still authenticate every exchange.
                with patch.object(mount, '_check_owner_readonly_mount'), \
                     patch.object(mount, 'GatewayRegistryUnixCandidateRead', return_value=copy.copy(socket_peer)):
                    pins = dict(root=gateway_root, expected_release_nonce=released['releaseNonce'],
                                expected_source_digest=released['gatewaySourceDigest'])
                    if interlock is not None:
                        return mount.reviewed_successor_delivery(
                            **pins, expected_interlock_digest=interlock, incumbent_core=incumbent_core,
                            scratch_root=checkout_scratch)
                    return mount.load_owner_registry_reader(**pins)

            peer = transport = None
        else:
            peer=object.__new__(GatewayRegistryUnixCandidateRead)
            peer._instance=lineage.instance;peer._scope=lineage.witness['scopeDigest'];peer._peer_key=b'p'*32
            transport=GatewayRegistrySemanticTransport(peer,frame_key=b'f'*32,
                generation=OLD,internal_actor='internal')
            transport._exchange=WireTests.exchange.__get__(self)
        controller=Controller(lineage.instance,lineage.witness['scopeDigest'])
        gate = None
        if not kernel_peer:
            gate=MaintenanceGate(instance_id=lineage.instance,scope_digest=lineage.witness['scopeDigest'],
                generation=OLD,read_interlock=controller.read,read_holds=transport.maintenance_snapshot)
        action=('release','merge_and_register')
        recipe_digest=definition(*action).definition_digest
        grants=(MergeContextGrant('owner-actor','scope','github','merge_pull_request',
                     'fortis-approvals',repo,recipe_digest),
                MergeContextGrant('owner-actor','scope','registry','register_merge',
                     'scope',repo,recipe_digest))
        grant_rows=sorted([g.record() for g in grants],key=sc.canonical)
        enrollment=ContextEnrollment(grants,source_digest=enrollment_source,
            expected_digest=sc.digest({'schemaVersion':1,'sourceDigest':enrollment_source,'grants':grant_rows}))
        semantic_rows=[
            ('owner-actor',*action,'scope',{'repository':repo}),
            ('owner-actor',*action,'scope',lineage.subjects[0]),
            ('owner-actor','github','list_pull_requests','fortis-approvals',{'repository':repo})]
        for actor in ('owner-actor',machine_actor):
            semantic_rows.append((actor,'registry','get_component','scope',lineage.subjects[0]))
            for operation in ('list_components','plan_batch'):
                semantic_rows.extend((actor,'registry',operation,'scope',subject)
                                     for subject in ({'repository':repo},lineage.subjects[0]))
        semantic_rows=[dict(zip(('actor','service','operation','target','subject'),r))
                       for r in semantic_rows]
        semantic=SemanticEnrollment(semantic_rows,source_digest=enrollment_source,
            expected_digest=sc.digest({'schemaVersion':1,'sourceDigest':enrollment_source,
                                       'grants':sorted(semantic_rows,key=sc.canonical)}))
        previous_schema=snapshot(old,legacy_schema_witness)
        if kernel_peer:
            import sqlite3
            from contextlib import closing
            from fortis_approvals.extensions.composite_preservation import prepare_staged_companion
            incumbent_core = self.root/'incumbent.sqlite'
            with closing(sqlite3.connect(old.path)) as source, closing(sqlite3.connect(incumbent_core)) as copy_db:
                source.backup(copy_db)
        with old._db() as db:
            db.execute('BEGIN IMMEDIATE')
            install_checked(db,expected=previous_schema)
        companion_digest=sc.digest(snapshot(old,inspect_companion))

        self.owner=owner
        self.key=VirtualKey()
        if kernel_peer:
            self.key.enroll = partial(self.key.enroll, origin=gateway_origin)
            self.key.assert_ = partial(self.key.assert_, origin=gateway_origin)
        self.invite=owner.issue_invitation()
        self.call=owner_call
        G2WebAuthnTest.enroll(self)
        coords=semantic.coordinates() | {tuple(row[key]) for row in grant_rows
                                          for key in ('parent','child')}
        choices={**old_choices,**{c:{'DENY','ASK','ALLOW'} for c in coords}}
        scope={**old_scope,'compositeContext':enrollment.sha,'semanticScope':semantic.sha}
        if kernel_peer:
            from fortis_approvals.extensions import successor_runtime
            from fortis_approvals.extensions.maintenance_interlock_reader import InterlockReservations
            from fortis_approvals.integrations.github.gateway.transport import GitHubHTTPTransport
            from fortis_approvals.integrations.registry_contracts.maintenance_contract import bind_record
            from fortis_approvals.tests.test_r7_unified_candidate import create_test_identity

            cert, key = self.root/'gateway.crt', self.root/'gateway.key'
            create_test_identity(cert, key)
            grant = self.root/'machine-grant'
            grant.write_text(machine_grant)
            grant.chmod(0o600)
            sonar = self.root/'sonar-token'
            sonar.write_text('local-sonar-fixture-only')
            sonar.chmod(0o600)
            reservations = InterlockReservations(self.root)

            def read_interlock(**pins):
                return bind_record(controller.record, **pins)

            interlock_patch = patch.object(successor_runtime, 'read_owner_interlock', side_effect=read_interlock)
            interlock_patch.start()
            self.addCleanup(interlock_patch.stop)
            registry_config = None

            def start_registry_writer(profile_path, *, check_readonly=False):
                from contextlib import nullcontext
                from fortis_approvals.registry import protected_source_write as writer
                # Host and controller provisioning are local fixtures.
                with (patch.object(writer, 'SOURCE_MOUNT', evidence_root),
                      patch.object(writer, '_check_owner_readonly_mount'),
                      patch.object(writer, 'read_owner_interlock', side_effect=read_interlock),
                      patch.object(writer, 'InterlockReservations', return_value=reservations),
                      patch.object(reservations, 'reserve', side_effect=nullcontext)):
                    if check_readonly:
                        with self.assertRaisesRegex(Denied,'REGISTRY_SEMANTIC_WRITE_STATE_REQUIRED'):
                            read_service_via_entrypoint(profile_path)
                    digest = sc.digest(json.loads(profile_path.read_text()))
                    if check_readonly:
                        with self.assertRaisesRegex(Denied,'REGISTRY_SUCCESSOR_PROFILE_PIN_CHANGED'):
                            read_service_via_entrypoint(profile_path, readonly=False, expected_profile='0'*64)
                    selected = read_service_via_entrypoint(profile_path, readonly=False, expected_profile=digest)
                    # The sandbox uses one UID/GID on both sides.
                    selected.frames.source_authorize.__self__._identity['uid'] = os.geteuid()
                    return start_kernel_semantic_peer(self, selected.frames, self.root,
                                                      peer_key=(profile_path.parent/'semantic-peer.key').read_bytes())

        server_pair = None

        def build(*, transition, companion, adapter=native, reopening=False, rebind=False):
            nonlocal peer, transport, socket_peer, stop_peer, registry_config, server_pair
            initial = not reopening and not rebind
            from fortis_approvals.extensions.semantic_enrollment import OwnerPrincipalAuth
            if kernel_peer:
                # Compute the expected staged successor pin from the incumbent
                # baseline and independently reviewed scope. The server
                # rebuilds and verifies that authority on the same clone.
                baseline = {**old_policies, **{key:'DENY' for key in coords if key not in old_policies}}
                digest = sc.digest({
                    'baseline':[[list(k),v if type(v) is str else 'CONDITIONAL']
                                for k,v in sorted(baseline.items(), key=lambda item:repr(item[0]))],
                    'choices':[[list(k),sorted(v)] for k,v in sorted(choices.items())],
                    'scope':scope,
                })
            else:
                def owner_active(name):
                    return name==owner.owner
                # The production method checks the already enrolled active key in owner.sqlite.
                auth=OwnerPrincipalAuth(machine,owners={owner.owner:'owner-actor'},active_owner=owner_active)
                core=CompositeUnifiedCore(core_path,adapters={'synthetic':synthetic,
                    'github':adapter,'registry':synthetic,'release':synthetic},policies=dict(old_policies),
                    authenticator=auth,owner_verifier=owner)
                adapter.observation_core=core
                for coord in coords:
                    core.policies[coord]='DENY'
                digest=PolicyAdmission(core,choices,scope_binding=scope).sha
                for coord in coords:
                    del core.policies[coord]
            if kernel_peer:
                from contextlib import nullcontext
                config = {
                    'schemaVersion':1, 'repository':repo, 'target':'scope', 'ownerPrincipal':'owner-actor',
                    'context':grant_rows, 'contextDigest':enrollment.sha,
                    'semantic':semantic_rows, 'semanticDigest':semantic.sha,
                    'successorDigest':digest, 'companionDigest':companion,
                    'interlockDigest':controller.pin, 'transition':transition, 'frozenHandoff':None,
                    'validatorRevision':self.pin, 'impactBinding':self.binding, 'buildPins':{},
                    'ciPolicy':sc.loads_strict(ci.policy), 'ciPolicyDigest':ci.pin,
                }

                if rebind:
                    config.update(schemaVersion=2, retainedEnrollmentSourceDigest=enrollment_source)
                if initial:
                    source_config = {'ownerActor':'owner-actor', 'ownerName':owner.owner,
                        'target':'scope', 'policyAuthorityDigest':digest, 'interlockDigest':controller.pin,
                        'validatorRevision':self.pin, 'impactBinding':self.binding, 'buildPins':{}}
                    _, registry_config = owner_read_configuration(lineage,self.root,
                        operation=('list_components','plan_batch'),machine_actor=machine_actor,
                        source_write=source_config)

                    socket_peer, stop_peer = start_registry_writer(registry_config, check_readonly=True)

                def mount_successor(payload):
                    write_mounted('successor.json', sc.canonical(payload).encode())
                    released['successorSha256'] = sc.digest(payload)
                    return load_peer(released)

                if reopening:
                    self.assertEqual(released['successorSha256'], sc.digest(config))
                    self.assertEqual((gateway_root/'successor.json').read_bytes(),
                                     sc.canonical(config).encode())
                    peer = load_peer(released,reuse=True)
                else:
                    peer = mount_successor(config)
                if initial:
                    for field, code in (
                        ('semanticFrameKeySha256', 'PLANNER_KEY'),
                        ('policyHistorySha256', 'POLICY_HISTORY_PIN_DENIED'),
                        ('semanticProfileDigest', 'SEMANTIC_PROFILE_CHANGED'),
                        ('successorSha256', 'SUCCESSOR_PIN_DENIED'),
                    ):
                        with self.subTest(field=field), self.assertRaisesRegex(Denied,code):
                            load_peer({**released, field:'0'*64})
                    peer = load_peer(released)
                transport = peer._semantic_transport
                if rebind and not reopening:
                    import sqlite3
                    from contextlib import closing
                    from fortis_approvals.extensions.transition_authority import stored_authority_witness
                    source_profile = transport.profile(source_checkpoint=True)
                    target_view = lineage.domain.snapshot()
                    self.assertEqual(source_profile['sourceRevision'], target_view['sourceRevision'])
                    self.assertEqual(source_profile['sourceCheckpoint'], {
                        **{k: target_view[k] for k in ('sourceCursor', 'snapshotRevision', 'eventDigest')},
                        'registryDigest': sc.digest(lineage.domain.maintenance_snapshot()),
                    })
                    frozen = Path(old.path)
                    before_bytes = frozen.read_bytes()
                    receipt = load_peer(released,interlock=controller.pin,incumbent_core=frozen,reuse=True)
                    self.assertNotIn('legacyCompanion',receipt)
                    self.assertEqual(receipt['existingCompanion'],{
                        'schemaDigest':snapshot(old,inspect_companion)['schemaDigest'],
                        'companionDigest':companion,
                        'authorityWitnessDigest':sc.digest(snapshot(old,stored_authority_witness))})
                    self.assertEqual(frozen.read_bytes(),before_bytes)
                    drifted=self.root/'corrective-drift.sqlite'
                    shutil.copy2(frozen,drifted)
                    with closing(sqlite3.connect(drifted)) as db, db:
                        db.execute('UPDATE owner_local_policy_v2_meta SET authority=?',('0'*64,))
                    with self.assertRaisesRegex(Denied,'COMPOSITE_SUCCESSOR_MODE_MISMATCH'):
                        load_peer(released,interlock=controller.pin,incumbent_core=drifted,reuse=True)
                if initial:
                    self.assertEqual(peer._functional_config.value, gateway_config)
                    with self.assertRaisesRegex(Denied, 'P5_REGISTRY_POLICY_REFERENCE_MISMATCH'):
                        registry_review_policy.policy_reference(
                            lambda: gateway_config['policyReference'], owner_scope['policyReferenceDigest'])
                    with self.assertRaisesRegex(Denied,'R7_REGISTRY_SUCCESSOR_CONTROLLER_PIN_CHANGED'):
                        load_peer(released,interlock='0'*64,incumbent_core=incumbent_core)
                    before = incumbent_core.read_bytes()
                    receipt = load_peer(released,interlock=controller.pin,incumbent_core=incumbent_core)
                    self.assertEqual(receipt['legacyCompanion'],previous_schema)
                    self.assertEqual(receipt['companionDigest'],companion)
                    self.assertEqual(incumbent_core.read_bytes(),before)
                    apply_clone = self.root/'apply-preview.sqlite'
                    shutil.copyfile(incumbent_core,apply_clone)
                    prepare_staged_companion(apply_clone, legacy=receipt['legacyCompanion'],
                        expected_digest=receipt['companionDigest'],
                        verify_history=peer._policy_history.verify_incumbent_storage)

                    # Policy history can drift without changing the Core request rows.
                    import sqlite3
                    from contextlib import closing
                    drifted = self.root/'policy-drift.sqlite'
                    shutil.copyfile(incumbent_core,drifted)
                    with closing(sqlite3.connect(drifted)) as db, db:
                        db.execute('UPDATE owner_local_policy_v2_meta SET legacy_digest=?', ('0'*64,))
                    drifted_bytes = drifted.read_bytes()
                    with self.assertRaisesRegex(Denied,'COMPOSITE_INCUMBENT_CLONE_CHANGED'):
                        load_peer(released,interlock=controller.pin,incumbent_core=drifted)
                    with self.assertRaisesRegex(Denied,'COMPOSITE_INCUMBENT_CLONE_CHANGED'):
                        prepare_staged_companion(drifted, legacy=receipt['legacyCompanion'],
                            expected_digest=receipt['companionDigest'],
                            verify_history=peer._policy_history.verify_incumbent_storage)
                    self.assertEqual(drifted.read_bytes(),drifted_bytes)
                options = dict(state=runtime_root, grant_path=grant, sonar_token_path=sonar,
                    cert_path=cert, key_path=key, region='eu', organizations=('pilot',), project_key='pilot',
                    release_nonce=released['releaseNonce'], bind_host='127.0.0.1',
                    github_pilot=github_config, extensions=extensions)

                from fortis_approvals.extensions.staging import ReleaseGate
                with (patch.object(ReleaseGate, 'ready', return_value=reopening),
                      patch.object(server, '_owner_release_unified_policy', return_value=opt_in),
                      patch.object(server, 'build_r7_unified_candidate',
                                   wraps=server.build_r7_unified_candidate) as candidate,
                      patch.object(server, 'runtime_endpoints', return_value=(gateway_origin,gateway_host)),
                      patch.object(GitHubHTTPTransport, 'from_file', return_value=endpoint),
                      patch.object(server, 'OWNER_PORT', 0), patch.object(server, 'MACHINE_PORT', 0),
                      patch.object(successor_runtime, 'InterlockReservations', return_value=reservations),
                      patch.object(reservations, 'reserve', side_effect=nullcontext)):
                    if initial:
                        invalid = mount_successor({**config, 'interlockDigest':'0'*64})
                        with self.assertRaisesRegex(Denied,'MAINTENANCE_STATE_UNKNOWN'):
                            server.create_servers(**options, registry_candidate_reader=invalid)
                        candidate.assert_not_called()
                        peer = mount_successor(config)
                        transport = peer._semantic_transport
                        location = proof_root.stat()
                        with patch.object(proof, 'mount_binding',
                                return_value={'device':location.st_dev,'inode':location.st_ino+1}):
                            with self.assertRaisesRegex(Denied,'SOURCE_EVIDENCE_BINDING_CHANGED'):
                                server.create_servers(**options, registry_candidate_reader=peer)
                        candidate.assert_not_called()
                    owner_server, machine_server = server.create_servers(**options, registry_candidate_reader=peer)
                server_pair = (owner_server, machine_server)
                self.addCleanup(owner_server.server_close)
                self.addCleanup(machine_server.server_close)
                self.assertGreater(owner_server.server_port, 0)
                self.assertGreater(machine_server.server_port, 0)
                self.portal = owner_server.get_app()
                machine_app = machine_server.get_app()

                def ingress(env, start):
                    return machine_app({**env, 'HTTP_HOST':gateway_host, 'wsgi.url_scheme':'https',
                                        'HTTP_AUTHORIZATION':'Bearer '+machine_grant}, start)

                self.ingress = ingress
                # Exercise the actual staged machine wrapper and classifier:
                # metadata catalog is passive; ordinary integration calls are not.
                with patch.object(machine_app.delegate.gate,'reserve',
                                  side_effect=Denied('RELEASE_MAINTENANCE')):
                    status,catalog=SemanticAccessTests.http(self,'/v1/integrations/catalog',{})
                    self.assertEqual(status,200,catalog)
                    self.assertIn('configurationDigest',catalog)
                    self.assertEqual(SemanticAccessTests.http(self,
                        '/v1/integrations/catalog',{'unexpected':True})[0],403)
                if not reopening:
                    blocked = {'service':'registry','operation':'list_components'}
                    self.assertEqual(SemanticAccessTests.http(self, '/v1/reads', blocked),
                                     (403, {'error':'RELEASE_STAGED_MUTATIONS_BLOCKED'}))
                self.portal.gate.ready = lambda: True  # simulated owner activation for the local ports
                # The gate callbacks are used after the factory returns as well.
                reservations.reserve = nullcontext
                return machine_app.broker.core

            def native_provider(current):
                local_discovery=NativeMergeDiscovery(current,repository=repo,
                    read_guard=discovery.read_guard,branch_guard=discovery.branch_guard,project=projector)
                local_reader=NativeMergeReceiptReader(current,source_repository=self.source,
                    state_root=self.state,read_guard=reader.read_guard)
                return NativeMergeProvider(local_discovery,local_reader)
            composition=ReviewedRegistrySuccessor(history=history,
                context=enrollment,
                semantic=semantic,owner_principal='owner-actor',repository=repo,target='scope',
                build_native_provider=native_provider,transport=transport,gate=gate,
                profile_digest=sc.digest(profile),successor_digest=digest,
                companion_digest=companion,transition=transition,
                provider_guard=lambda a,row,step:
                    ProviderGuard(True,a=='owner-actor','ASK' if step['ordinal']==0 else 'ALLOW','a'*64),
                effect_guard=lambda ctx:ctx.actor=='owner-actor' and ctx.target=='scope',
                ready=lambda *_:True)
            core.auth=composition.owner_auth(machine,owner)
            base=RepoIntentBroker(core,actor_operations={})
            base_ingress=RepoIngress(base,host='localhost:18992',allow_http_local_test=True,max_bytes=32768)
            base_portal=UnifiedPolicyPortal(core,owner)
            base_portal._extension_runtime=None
            self.portal,self.ingress=composition.install(core=core,portal=base_portal,
                ingress=base_ingress,machine_base=base_ingress,native={'adapter':adapter},reader=peer,
                incumbent_choices=old_choices,incumbent_scope=old_scope,opt_in=opt_in,
                release_active=reopening)
            return core
        def change_policy(core, cookie, csrf, coord, revision, desired):
            actor,service,operation,target=coord
            candidate={'actor':actor,'provider':service,'operation':operation,'target':target,
                       'scope':'exact','expectedPolicy':'DENY','desiredPolicy':desired,
                       'expectedRevision':revision,'expectedPolicyVersion':core.policy_version,
                       'reasonCode':'ISOLATED_SCOPE_REVIEW'}
            code,change,_=self.call('/v1/owner/policy/editor/begin',{'candidate':candidate},
                                     cookie=cookie,csrf=csrf)
            self.assertEqual(code,200,change)
            code,saved,_=self.call('/v1/owner/policy/editor/finish',{'ceremonyId':change['ceremonyId'],
                'change':change['change'],'response':self.key.assert_(change)},cookie=cookie,csrf=csrf)
            self.assertEqual(code,200,saved)

        core=build(transition=True,companion=companion_digest)
        retained_policies={}
        if corrective:
            # Reproduce the owner's reported partial configuration before
            # copying the source. No provider execution or product approval.
            cookie,csrf=G2WebAuthnTest.login(self)
            for service,op,target,policy in (
                    ('release','merge_and_register','scope','ASK'),
                    ('github','merge_pull_request','fortis-approvals','ASK'),
                    ('github','list_pull_requests','fortis-approvals','ALLOW')):
                coord=('owner-actor',service,op,target)
                self.assertIn(coord,coords)
                change_policy(core,cookie,csrf,coord,len(retained_policies),policy)
                retained_policies[coord]=policy
            self.assertEqual(endpoint.writes,0)
            before = snapshot(core, lambda db: authority_witness(core,db))
            frozen_companion = snapshot(core,inspect_companion)
            self.assertEqual(frozen_companion['parents'],0)
            old_gateway, old_state, old_seal = gateway_root, runtime_root, dict(released)
            old_files = {p.name:p.read_bytes() for p in old_gateway.iterdir()}
            for listener in server_pair:
                listener.server_close()
            stop_peer()
            self.assertEqual(snapshot(core,lambda db:authority_witness(core,db)),before)
            runtime_root=self.root/'corrective-state'
            shutil.copytree(old_state,runtime_root)
            gateway_root=self.root/'corrective-mount'
            shutil.copytree(old_gateway,gateway_root)
            new_source='9'*64
            from fortis_approvals.extensions.successor_runtime import project_corrective_profiles
            old_registry = sc.loads_strict(registry_config.read_bytes())
            # The fixture's original initial transition has just been
            # installed. Model the separately sealed #288 recovery profile.
            old_composition={**sc.loads_strict(old_files['successor.json']),
                             'transition':False,'companionDigest':sc.digest(frozen_companion)}
            recovered_seal={**old_seal,'successorSha256':sc.digest(old_composition)}
            old_registry_files={p.name:p.read_bytes() for p in registry_config.parent.iterdir()}
            next_peer,next_frame=b'x'*32,b'y'*32
            kw=dict(expected_gateway_digest=sc.digest(recovered_seal),
                    expected_registry_digest=sc.digest(old_registry),new_source_digest=new_source,
                    nonce=str(uuid.uuid4()),peer_key_digest=sha(next_peer),frame_key_digest=sha(next_frame))
            # The test profile uses the same UID and fixture-specific
            # socket path. Its generation is independently pinned.
            projected=project_corrective_profiles(recovered_seal,old_registry,old_composition,**kw)
            with self.assertRaisesRegex(Denied,'R7_REGISTRY_CORRECTIVE_SOURCE_SEAL_CHANGED'):
                project_corrective_profiles(recovered_seal,old_registry,old_composition,
                                            **{**kw,'expected_gateway_digest':'0'*64})
            with self.assertRaisesRegex(Denied,'R7_REGISTRY_CORRECTIVE_PAIR_CHANGED'):
                project_corrective_profiles(recovered_seal,old_registry,old_composition,
                                            **{**kw,'peer_key_digest':old_registry['semantic']['peerKeyDigest']})
            # Re-project the already-installed v2 profile from a separately
            # checked incumbent. The oldest enrollment pin must survive.
            incumbent=projected
            next_peer,next_frame=b'j'*32,b'k'*32
            next_source='8'*64
            next_inputs=dict(expected_gateway_digest=sc.digest(incumbent['gateway']),
                expected_registry_digest=sc.digest(incumbent['registry']),
                new_source_digest=next_source,nonce=str(uuid.uuid4()),
                peer_key_digest=sha(next_peer),frame_key_digest=sha(next_frame))
            profiles=(incumbent['gateway'],incumbent['registry'],incumbent['successor'])
            deny='R7_REGISTRY_CORRECTIVE_SOURCE_SEAL_CHANGED'
            with self.assertRaisesRegex(Denied,deny):
                project_corrective_profiles(*profiles,**next_inputs)
            next_inputs['expected_gateway_source_digest']=new_source
            with self.assertRaisesRegex(Denied,deny):
                project_corrective_profiles(*profiles,**{**next_inputs,'expected_gateway_source_digest':next_source})
            with self.assertRaisesRegex(Denied,deny):
                project_corrective_profiles(*profiles,**{**next_inputs,'new_source_digest':new_source})
            with self.assertRaisesRegex(Denied,deny):
                project_corrective_profiles(incumbent['gateway'],old_registry,incumbent['successor'],**next_inputs)
            projected=project_corrective_profiles(*profiles,**next_inputs)
            from fortis_approvals.extensions.successor_runtime import project_staged_profiles
            from fortis_approvals.tests.test_maintenance_gate import Controller
            from fortis_approvals.tests.test_registry_semantic_contract import begin
            ctrl=Controller(profiles[0]['instanceId'],profiles[0]['scopeDigest'],
                            profiles[0]['semanticGeneration'])
            target_generation='7'*64
            item=begin(repo=profiles[2]['repository'],target='fortis-gateway')
            attempt={'attemptId':str(uuid.uuid4()),'subject':item['subject'],'source':item['source'],
                     'restrictionDigest':'c'*64,'sourceGeneration':ctrl.record['generation'],
                     'targetGeneration':target_generation}
            ctrl.advance('DRAINING',attempt=attempt)
            for phase in ('FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):
                ctrl.advance(phase)
            ctrl.advance('STAGED_TARGET_FROZEN',generation=target_generation)
            handoff={'role':'staged_target','attemptId':attempt['attemptId'],
                     'restrictionDigest':attempt['restrictionDigest'],'interlockDigest':ctrl.pin,
                     'registryDigest':'d'*64}
            inputs={**next_inputs,'handoff':handoff,'staged_record':ctrl.record,
                    'staged_companion_digest':'e'*64}
            originals=copy.deepcopy(profiles)
            staged=project_staged_profiles(*profiles,**inputs)
            self.assertEqual(profiles,originals)
            self.assertEqual(staged['gateway']['semanticGeneration'],target_generation)
            self.assertEqual(staged['registry']['semantic']['generation'],target_generation)
            self.assertEqual(staged['registry']['sourceWrite']['interlockDigest'],ctrl.pin)
            self.assertEqual(staged['gateway']['successorSha256'],sc.digest(staged['successor']))
            self.assertEqual(staged['successor'],{**projected['successor'],'schemaVersion':3,'latestPin':True,
                'frozenHandoff':handoff,'interlockDigest':ctrl.pin,'companionDigest':'e'*64})
            self.assertIs(staged['registry']['sourceWrite']['latestPin'],True)
            # Bootstrap already has a fresh checked nonce/keys. Finalization
            # must not rotate either or change the retained authority. This
            # is synthetic phase evidence; real SQLite receipt reconstruction
            # is exercised by the bootstrap source-lineage test.
            from fortis_approvals.extensions.successor_runtime import project_bootstrap_final_profiles
            from fortis_approvals.integrations.registry_contracts import maintenance_contract as mc
            pre_g,pre_r,pre_c=(projected[k] for k in ('gateway','registry','successor'))
            # The local socket fixture uses intentionally different mocked
            # peer UIDs. Model the exact matched host reader here only.
            pre_r={**pre_r,'readerUid':pre_g['readerUid'],'readerGid':pre_g['readerGid']}
            sem=pre_r['semantic']
            binding={'instanceId':pre_r['instanceId'],'scopeDigest':sc.digest(pre_r['scope']),
                'profileDigest':sem['successorProfileDigest'],'generation':sem['generation'],
                'internalActor':sem['internalActor'],'peerKeyDigest':sem['peerKeyDigest'],
                'frameKeyDigest':sem['frameKeyDigest'],'socketPath':pre_r['socketPath'],
                'readerUid':pre_r['readerUid'],'readerGid':pre_r['readerGid'],
                'authorityDigest':pre_r['sourceWrite']['policyAuthorityDigest'],
                'interlockDigest':pre_r['sourceWrite']['interlockDigest']}
            subjects=mc.paired_subjects(repo)
            items={role:{**begin(repo=repo,target=subject['targetId']),'subject':subject}
                   for role,subject in subjects.items()}
            checkpoint={'sourceRevision':4,'snapshotRevision':4,'sourceCursor':items['gateway']['source']['sourceSha'],
                'eventDigest':'a'*64,'profileDigest':sem['successorProfileDigest']}
            from fortis_approvals.extensions.transition_authority import stored_authority_witness
            companion_witness={'schemaDigest':frozen_companion['schemaDigest'],
                'companionDigest':pre_c['companionDigest'],
                'authorityWitnessDigest':sc.digest(snapshot(core,stored_authority_witness))}
            checked={'gateway':{'result':'BOOTSTRAP_GATEWAY_MATERIAL_ONLY','profileDigest':sc.digest(pre_g),
                'sourceDigest':pre_g['gatewaySourceDigest'],'releaseNonce':pre_g['releaseNonce'],
                'incumbentProfileDigest':sc.digest(incumbent['gateway']),'companion':companion_witness,
                'binding':binding},'registry':{'result':'BOOTSTRAP_REGISTRY_MATERIAL_ONLY',
                'profileDigest':sc.digest(pre_r),'binding':binding,'checkpoint':checkpoint,'items':items,
                'sourceMigrationReceipt':{},'review':{'authorityWitnessDigest':companion_witness['authorityWitnessDigest'],'ownerReviewProofDigest':'f'*64}},
                'artifacts':{role:items[role]['source']['artifactSha256'] or 'a'*64 for role in items}}
            seed=Controller(pre_g['instanceId'],pre_g['scopeDigest'],pre_g['semanticGeneration']).record
            owner_go={'schemaVersion':1,'attemptId':str(uuid.uuid4()),'checkDigest':'c'*64,
                'sourceRecordDigest':'d'*64,'compatibilityDigest':mc.bootstrap_compatibility_digest(checked),
                'reviewDigest':'e'*64,'evidenceDigest':'1'*64,'reviewProofDigest':'f'*64,
                'targetGeneration':target_generation,'recordedAt':100}
            # The fixture's original interlock pin is the same genesis.
            self.assertEqual(sc.digest(seed),binding['interlockDigest'])
            auth=mc.bootstrap_pair_authorization(checked,owner_go,{'sha256':{},'summary':{}},
                review_sha256='e'*64,evidence_sha256='1'*64,seed_digest=sc.digest(seed))
            pair=mc.paired_begin({'schemaVersion':1,'attemptId':auth['attemptId'],'checkpoint':checkpoint,
                'items':items,'artifacts':checked['artifacts'],'controllerReceiptDigest':sc.digest(auth),
                'compatibilityReadbackDigest':auth['compatibilityDigest']},repo)
            holds={'instanceId':binding['instanceId'],'scopeDigest':binding['scopeDigest'],
                'snapshotRevision':6,'eventDigest':'a'*64,'holds':[]}
            receipts=[]
            for role in ('registry','gateway'):
                ident=mc.paired_operation_id(pair['attemptId'],role)
                holds['holds'].append({'attemptId':ident,'subject':items[role]['subject'],'source':items[role]['source'],
                    'restrictionDigest':'c'*64,'stateFreeze':True,'blockedOperations':[],
                    'pairId':pair['attemptId'],'pairDigest':sc.digest(pair)})
                receipts.append({'operationId':ident,'eventKind':'PROTECTED_PAIRED_BEGIN','instanceId':binding['instanceId'],
                    'subject':items[role]['subject'],'recordedAt':100,'technicalInstallationVerified':False})
            plan=mc.bootstrap_phase_plan(seed,auth,pair,receipts,holds)
            result={'result':'BOOTSTRAP_PAIR_BEGIN_ACCOUNTED_ONLY','pair':pair,'receipts':receipts,
                'holdSnapshot':holds,'registryDigest':plan['registryDigest'],'phasePlan':plan,
                'hostAccepted':False,'admissionAllowed':False}
            publication={'schema':'fortis-successor-maintenance-publication-v2','state':'Committed',
                'sourceRecordHash':auth['sourceRecordDigest'],'record':plan['records'][-2],
                'digest':sc.digest(plan['records'][-2]),'previous':plan['records'][-3],
                'registryDigest':plan['registryDigest'],'previousRegistryDigest':plan['registryDigest']}
            final_inputs=dict(checked=checked,authorization=auth,seed=seed,begin=result,publication=publication)
            pre=(pre_g,pre_r,pre_c);before_final=copy.deepcopy(pre)
            final=project_bootstrap_final_profiles(*pre,**final_inputs)
            self.assertEqual(pre,before_final)
            self.assertEqual(final['gateway'],{**pre_g,'semanticGeneration':target_generation,
                'successorSha256':sc.digest(final['successor'])})
            self.assertEqual(final['registry'],{**pre_r,'semantic':{**sem,'generation':target_generation},
                'sourceWrite':{**pre_r['sourceWrite'],'latestPin':True,'interlockDigest':plan['handoff']['interlockDigest']}})
            self.assertEqual(final['successor'],{**pre_c,'schemaVersion':3,'latestPin':True,
                'frozenHandoff':plan['handoff'],'interlockDigest':plan['handoff']['interlockDigest']})
            with self.assertRaises(Denied):
                project_bootstrap_final_profiles(*pre,**{**final_inputs,'publication':{**publication,'state':'Pending'}})
            with self.assertRaises(Denied):
                project_bootstrap_final_profiles({**pre_g,'releaseNonce':str(uuid.uuid4())},pre_r,pre_c,**final_inputs)
            prepared_root=self.root/'bootstrap-prepared-gateway'
            final_root=self.root/'bootstrap-final-gateway'
            for root in (prepared_root,final_root):root.mkdir(mode=0o700)
            files={**old_files,'profile.json':sc.canonical(pre_g).encode(),
                   'successor.json':sc.canonical(pre_c).encode(),
                   'planner.key':next_peer,'semantic-frame.key':next_frame}
            for name,raw in files.items():
                path=prepared_root/name;path.write_bytes(raw);path.chmod(0o600)
            pin_target={'device':final_root.stat().st_dev,'inode':final_root.stat().st_ino}
            from fortis_approvals.extensions import maintenance_interlock_reader as ir
            from types import SimpleNamespace
            phase=(publication['record'],{'interlockDigest':publication['digest'],
                                          'registryDigest':publication['registryDigest']})
            def seal(verify):
                with (patch.object(mount,'_check_owner_readonly_mount'),
                      patch.object(mount,'GatewayRegistryUnixCandidateRead',return_value=copy.copy(socket_peer)),
                      patch.object(mount,'_exact_mountinfo',return_value=True),
                      patch.object(mount.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY if verify else 0)),
                      patch.object(ir,'read_latest_interlock',return_value=phase)):
                    return mount.seal_bootstrap_gateway_material(**final_inputs,registry_profile=pre_r,
                        verify_only=verify,expected_target=pin_target,incumbent_core=Path(core.path),
                        root=prepared_root,target=final_root)
            sealed=seal(False)
            self.assertEqual(seal(True),sealed)
            self.assertEqual(sealed['profileDigest'],sc.digest(final['gateway']))
            self.assertEqual(sealed['registryProfileDigest'],sc.digest(final['registry']))
            self.assertEqual({p.name:p.read_bytes() for p in prepared_root.iterdir()},files)
            self.assertEqual(snapshot(core,lambda db:authority_witness(core,db)),before)
            # Exercise the actual ordinary material branch on the same
            # preserved Core and the already sealed bootstrap profile.
            from fortis_approvals.extensions.successor_runtime import _project_retained_profiles
            from fortis_approvals.integrations.registry_contracts import maintenance_seal
            prep2=_project_retained_profiles(final['gateway'],final['registry'],final['successor'],
                expected_gateway_digest=sc.digest(final['gateway']),expected_registry_digest=sc.digest(final['registry']),
                expected_gateway_source_digest=pre_g['gatewaySourceDigest'],new_source_digest='9'*64,
                nonce=str(uuid.uuid4()),peer_key_digest=sha(b'l'*32),frame_key_digest=sha(b'm'*32),staged=True)
            g2,r2,c2=(prep2[k] for k in ('gateway','registry','successor'))
            prep_root=self.root/'ordinary-prepared-gateway';target_root=self.root/'ordinary-final-gateway'
            for root in (prep_root,target_root):root.mkdir(mode=0o700)
            files2={**files,'profile.json':sc.canonical(g2).encode(),'successor.json':sc.canonical(c2).encode(),
                    'planner.key':b'l'*32,'semantic-frame.key':b'm'*32}
            for name,raw in files2.items():
                path=prep_root/name;path.write_bytes(raw);path.chmod(0o600)
            normal=plan['records'][-1]
            for phase_name in ('BACKUP_FROZEN','PROMOTE_FROZEN','COMPLETION_PENDING','NORMAL'):
                normal=mc.validate_transition(normal,{**normal,'phase':phase_name,'sequence':normal['sequence']+1,
                    'previousDigest':sc.digest(normal),'proofDigest':'1'*64})
            with patch.object(mount,'_check_owner_readonly_mount'),patch.object(mount,'GatewayRegistryUnixCandidateRead',return_value=copy.copy(socket_peer)):
                gateway2=mount.reviewed_bootstrap_gateway(expected_release_nonce=g2['releaseNonce'],
                    expected_source_digest=g2['gatewaySourceDigest'],incumbent_nonce=final['gateway']['releaseNonce'],
                    incumbent_source_digest=final['gateway']['gatewaySourceDigest'],incumbent_profile_digest=sc.digest(final['gateway']),
                    incumbent_core=Path(core.path),root=prep_root,incumbent_root=final_root,ordinary=True)
            roots={k:{'device':target_root.stat().st_dev,'inode':target_root.stat().st_ino+i}
                   for i,k in enumerate(('gateway','registry','state','backup'))}
            cp={**checkpoint,'snapshotRevision':12}
            ordinary_checked={'gateway':gateway2,'registry':{'result':'ORDINARY_REGISTRY_MATERIAL_ONLY',
                'profileDigest':sc.digest(r2),'incumbentProfileDigest':sc.digest(final['registry']),
                'binding':gateway2['binding'],'checkpoint':cp,'items':items,
                'holdSnapshot':{**holds,'snapshotRevision':cp['snapshotRevision'],'holds':[]}},
                'artifacts':checked['artifacts'],'roots':roots}
            auth2={'attemptId':str(uuid.uuid4()),'sourceRecordDigest':'6'*64,'targetGeneration':'5'*64,
                'targetNonce':g2['releaseNonce'],'recordedAt':200,'normalDigest':sc.digest(normal),
                'compatibilityDigest':sc.digest(ordinary_checked)}
            intent={'schemaVersion':1,'normal':normal,'compatibility':ordinary_checked,'authorization':auth2}
            pair2=mc.ordinary_pair_intent(intent)
            holds2={**holds,'snapshotRevision':cp['snapshotRevision']+2,'holds':[]}
            receipts2=[]
            for role,h,row in zip(('registry','gateway'),holds['holds'],receipts):
                ident=mc.paired_operation_id(pair2['attemptId'],role)
                holds2['holds'].append({**h,'attemptId':ident,'pairId':pair2['attemptId'],'pairDigest':sc.digest(pair2)})
                receipts2.append({**row,'operationId':ident,'recordedAt':auth2['recordedAt']})
            drain=mc.paired_draining_record(normal,pair2,receipts2,holds2,target_generation=auth2['targetGeneration'],recorded_at=auth2['recordedAt'])
            begin2={'result':'PROTECTED_PAIR_BEGIN_READBACK_ONLY','intentDigest':sc.digest(intent),'pair':pair2,
                'receipts':receipts2,'checkpoint':{**cp,'snapshotRevision':holds2['snapshotRevision']},
                'holdSnapshot':holds2,'draining':drain,'registryDigest':sc.digest(holds2)}
            state={'sha256':{},'summary':{}}
            check={'result':'FREEZE_BINDINGS_MATCH_ONLY','interlockDigest':sc.digest(drain),'registryDigest':begin2['registryDigest'],
                'stateReceiptDigest':sc.digest(state),'companionDigest':gateway2['companion']['companionDigest'],
                'workerAttestationDigest':'8'*64,'attemptId':auth2['attemptId'],'restrictionDigest':drain['attempt']['restrictionDigest']}
            checked_phase=maintenance_seal.checked_transitions(check,drain)['checked']
            stop=maintenance_seal.apply_stop_plan(checked_phase,check,{'sourceRecordDigest':auth2['sourceRecordDigest'],
                'checkedRecordDigest':'9'*64,'targetImageId':'sha256:'+pair2['artifacts']['gateway']})
            pub={**publication,'sourceRecordHash':auth2['sourceRecordDigest'],'record':stop['next'],'digest':sc.digest(stop['next']),
                 'previous':checked_phase,'registryDigest':begin2['registryDigest'],'previousRegistryDigest':begin2['registryDigest']}
            ordinary_proof={'intent':intent,'check':check,'sourceReceipt':state,'stop':stop}
            def seal2(verify):
                with (patch.object(mount,'_check_owner_readonly_mount'),
                      patch.object(mount,'GatewayRegistryUnixCandidateRead',return_value=copy.copy(socket_peer)),
                      patch.object(mount,'_exact_mountinfo',return_value=True),
                      patch.object(mount.os,'statvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY if verify else 0)),
                      patch.object(ir,'read_latest_interlock',return_value=(pub['record'],{'interlockDigest':pub['digest'],'registryDigest':pub['registryDigest']})),
                      patch.object(ir,'read_controller_begin',return_value={'intent':intent,'revoked':False})):
                    return mount.seal_bootstrap_gateway_material(checked=ordinary_checked,authorization=auth2,seed=normal,begin=begin2,
                        publication=pub,registry_profile=r2,verify_only=verify,expected_target=roots['gateway'],
                        incumbent_core=Path(core.path),root=prep_root,target=target_root,ordinary=ordinary_proof)
            sealed2=seal2(False)
            self.assertEqual(seal2(True),sealed2)
            self.assertEqual(sealed2['generation'],auth2['targetGeneration'])
            self.assertEqual(sc.loads_strict((target_root/'successor.json').read_bytes())['successorDigest'],final['successor']['successorDigest'])
            self.assertEqual({p.name:p.read_bytes() for p in prep_root.iterdir()},files2)
            self.assertEqual(snapshot(core,lambda db:authority_witness(core,db)),before)
            # A later release carries forward the same original enrollment
            # even though its installed profile has an older frozen handoff.
            ctrl2=Controller(staged['gateway']['instanceId'],staged['gateway']['scopeDigest'],target_generation)
            second_attempt={**attempt,'attemptId':str(uuid.uuid4()),'sourceGeneration':target_generation,
                            'targetGeneration':'6'*64}
            ctrl2.advance('DRAINING',attempt=second_attempt)
            for phase in ('FROZEN_BEFORE_CHECK','CHECK_SEALED','APPLY_STOP'):ctrl2.advance(phase)
            ctrl2.advance('STAGED_TARGET_FROZEN',generation='6'*64)
            second=project_staged_profiles(staged['gateway'],staged['registry'],staged['successor'],
                expected_gateway_digest=sc.digest(staged['gateway']),expected_registry_digest=sc.digest(staged['registry']),
                expected_gateway_source_digest=next_source,new_source_digest='9'*64,nonce=str(uuid.uuid4()),
                peer_key_digest=sha(b'l'*32),frame_key_digest=sha(b'm'*32),staged_record=ctrl2.record,
                handoff={**handoff,'attemptId':second_attempt['attemptId'],'interlockDigest':ctrl2.pin},
                staged_companion_digest='f'*64)
            self.assertEqual(second['gateway']['semanticGeneration'],'6'*64)
            self.assertEqual(second['successor']['retainedEnrollmentSourceDigest'],enrollment_source)
            self.assertEqual(second['successor']['successorDigest'],staged['successor']['successorDigest'])
            with self.assertRaises(Denied):
                project_corrective_profiles(staged['gateway'],staged['registry'],staged['successor'],
                    **{**next_inputs,'expected_gateway_digest':sc.digest(staged['gateway']),
                       'expected_registry_digest':sc.digest(staged['registry']),
                       'expected_gateway_source_digest':next_source,'new_source_digest':'9'*64})
            with self.assertRaises(Denied):
                project_staged_profiles(*profiles,**{**inputs,'handoff':{**handoff,'interlockDigest':'0'*64}})
            for change in ({'registryInstanceId':str(uuid.uuid4())},{'scopeDigest':'0'*64},
                           {'attempt':{**attempt,'sourceGeneration':'6'*64}},
                           {'attempt':{**attempt,'sourceGeneration':target_generation}}):
                mixed={**ctrl.record,**change}
                with self.assertRaises(Denied):
                    project_staged_profiles(*profiles,**{**inputs,'staged_record':mixed,
                        'handoff':{**handoff,'interlockDigest':sc.digest(mixed)}})
            self.assertEqual(projected['successor'],incumbent['successor'])
            self.assertEqual(projected['successor']['retainedEnrollmentSourceDigest'],enrollment_source)
            new_source=next_source
            released=projected['gateway']
            write_mounted('planner.key',next_peer)
            write_mounted('semantic-frame.key',next_frame)
            new_registry_root=self.root/'corrective-registry-config'
            shutil.copytree(registry_config.parent,new_registry_root)
            previous_registry_config=registry_config
            registry_config=new_registry_root/'profile.json'
            # Production volumes use the same path inside different
            # containers. The fixture uses distinct local paths instead.
            from fortis_approvals.registry.release_event_journal import ReleaseEventJournal
            original_store=lineage.store
            original_domain=lineage.domain
            original_snapshot=original_domain.snapshot()
            registry_state=self.root/'corrective-registry-state'
            registry_state.mkdir(mode=0o700)
            target_db=registry_state/original_store.path.name
            shutil.copy2(original_store.path,target_db)
            lineage.store=ReleaseEventJournal(target_db,instance_id=original_store.instance_id,
                scope=original_store.scope,expected_legacy=original_store.expected_legacy,
                transition_digest=original_store.transition_digest)
            lineage.domain=lineage.reopen()
            third_receipt=fixture_repair(289,repair_receipt,cursor=self.base)
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],3)
            self.assertEqual(original_domain.snapshot(),original_snapshot)
            projected_registry={**projected['registry'],'registryStatePath':str(target_db)}
            registry_config.write_bytes(sc.canonical(projected_registry).encode())
            (new_registry_root/'semantic-peer.key').write_bytes(next_peer)
            (new_registry_root/'semantic-frame.key').write_bytes(next_frame)
            opt_in=R7UnifiedPolicySourceOptIn(new_source,lambda:'b'*64,
                                            allow_all_method_policy_upgrade=True)
            socket_peer,stop_peer=start_registry_writer(registry_config)
            # This is a new release, not an ordinary restart: seal the
            # actual stopped source, including its already installed epoch
            # schema, rather than the pre-transition companion snapshot.
            corrected=build(transition=False,companion=sc.digest(frozen_companion),rebind=True)
            self.assertEqual(snapshot(corrected,inspect_companion),frozen_companion)
            self.assertEqual(snapshot(corrected,lambda db:authority_witness(corrected,db)),before)
            self.assertEqual(snapshot(core,lambda db:authority_witness(core,db)),before)
            self.assertEqual({p.name:p.read_bytes() for p in old_gateway.iterdir()},old_files)
            self.assertEqual({p.name:p.read_bytes() for p in previous_registry_config.parent.iterdir()},
                             old_registry_files)
            self.assertEqual((gateway_root/'successor.json').read_bytes(),
                             sc.canonical(projected['successor']).encode())
            self.assertEqual(released,projected['gateway'])
            self.assertNotEqual(released['releaseNonce'],old_seal['releaseNonce'])
            self.assertEqual(corrected.authority.sha,core.authority.sha)
            self.assertEqual(dict(corrected.authority.choices),dict(core.authority.choices))
            self.assertEqual(endpoint.writes,0)
            # Original source profile is still usable if the staged target
            # must be discarded; no provider effect or authority append.
            self.assertEqual(original_domain.snapshot(),original_snapshot)
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],3)
            # Pre-effect probe on preliminary sealed material, without
            # connecting to either Registry or claiming a live receiver.
            preliminary=project_corrective_profiles(released,projected_registry,projected['successor'],
                expected_gateway_digest=sc.digest(released),expected_registry_digest=sc.digest(projected_registry),
                expected_gateway_source_digest=new_source,new_source_digest='6'*64,
                nonce=str(uuid.uuid4()),peer_key_digest=sha(b'q'*32),frame_key_digest=sha(b'r'*32))
            preliminary_root=self.root/'bootstrap-preliminary'
            shutil.copytree(gateway_root,preliminary_root)
            for name,data in (('profile.json',sc.canonical(preliminary['gateway']).encode()),
                    ('successor.json',sc.canonical(preliminary['successor']).encode()),
                    ('planner.key',b'q'*32),('semantic-frame.key',b'r'*32)):
                (preliminary_root/name).write_bytes(data)
            # Match the exact sealed key of each profile in the same-UID fixture.
            def candidate_reader(**kw):
                result=copy.copy(socket_peer)
                result._peer_key=kw['peer_key']
                return result
            with (patch.object(mount,'_check_owner_readonly_mount'),
                  patch.object(mount,'GatewayRegistryUnixCandidateRead',side_effect=candidate_reader),
                  patch.object(mount,'_check_live_peer',side_effect=AssertionError('bootstrap must stay offline'))):
                arguments=dict(expected_release_nonce=preliminary['gateway']['releaseNonce'],
                    expected_source_digest='6'*64,incumbent_nonce=released['releaseNonce'],
                    incumbent_source_digest=new_source,incumbent_profile_digest=sc.digest(released),
                    incumbent_core=Path(corrected.path),
                    root=preliminary_root,incumbent_root=gateway_root)
                probe=mount.reviewed_bootstrap_gateway(**arguments)
                self.assertEqual(probe['profileDigest'],sc.digest(preliminary['gateway']))
                self.assertEqual(probe['companion']['companionDigest'],sc.digest(frozen_companion))
                self.assertEqual(probe['binding']['authorityDigest'],corrected.authority.sha)
                with self.assertRaisesRegex(Denied,'R7_REGISTRY_BOOTSTRAP_PROFILE_CHANGED'):
                    mount.reviewed_bootstrap_gateway(**{**arguments,'incumbent_profile_digest':'0'*64})
            core=corrected
        cookie,csrf=G2WebAuthnTest.login(self)

        def inventory_rows(expected):
            code,inventory,_=self.call('/v1/owner/provider-inventory',cookie=cookie)
            self.assertEqual(code,200,inventory)
            exact=[r for r in inventory['operations'] if r['scope']=='exact']
            by_coord={(r['actor'],r['provider'],r['operation'],r['target']):r for r in exact}
            self.assertEqual(len(by_coord),len(exact))
            for coord in coords:
                row=by_coord[coord]
                self.assertEqual(row['currentPolicy'],expected[coord])
                self.assertIn(expected[coord],row['editablePolicies'])
                self.assertTrue(row['active'])
                if coord in {tuple(g['child']) for g in grant_rows}:
                    self.assertEqual(row['operationKind'],'context-child')
                    self.assertEqual(row['contextParents'],[
                        {'service':'release','operation':'merge_and_register','target':'scope'}])
                    self.assertEqual(row['effectivePolicy'],
                        'DENY' if expected[coord]=='DENY' else 'UNKNOWN')
            if kernel_peer:
                old=[r for r in inventory['operations'] if r['provider']=='registry'
                     and r['operation'].startswith('candidate_')]
                self.assertEqual({r['operation'] for r in old},
                    {'candidate_head','candidate_list_desired','candidate_original_operation'})
                self.assertTrue(all(r['currentPolicy']=='DENY' for r in old))
            return by_coord

        # Real owner HTTP inventory, with the installed Registry extension
        # and reviewed successor sharing the provider name.
        initial=snapshot(core,lambda db:authority_witness(core,db))
        inventory_rows({coord:retained_policies.get(coord,'DENY') for coord in coords})
        self.assertEqual(snapshot(core,lambda db:authority_witness(core,db)),initial)
        desired_policies=dict(retained_policies)
        for coord in sorted(coords-set(retained_policies)):
            operation=coord[2]
            desired='ALLOW' if operation in ('list_components','get_component','list_pull_requests','plan_batch') else 'ASK'
            change_policy(core,cookie,csrf,coord,len(desired_policies),desired)
            desired_policies[coord]=desired

        inventory_rows(desired_policies)
        start=perf_counter()
        code,rows,_=self.call(PREFIX+'/discover',{},cookie=cookie,csrf=csrf)
        self.assertEqual(code,200,rows)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['state'],'PENDING',rows)
        self.assertEqual(endpoint.writes,0)
        discovered=perf_counter()
        discovery_seconds=discovered-start
        decision={'requestId':rows[0]['requestId'],'decision':'approve'}
        def read_board():
            query={'requestId':str(uuid.uuid4()),'service':'registry','operation':'list_components',
                   'target':'scope','reason':'Fixture board read',
                   'params':{'repository':repo,'page':{'limit':10,'cursor':None}}}
            code,portal,_=self.call(PREFIX+'/read',query,cookie=cookie,csrf=csrf)
            ai_code,ai=SemanticAccessTests.http(self,'/v1/reads',query)
            self.assertEqual((code,ai_code),(200,200))
            self.assertEqual(portal['data'],ai['data'])
            board=portal['data']['data']['items'][0]
            self.assertEqual(board['desired']['source']['sourceSha'],merge)
            self.assertTrue(board['desired']['evidenceVerified'])
            self.assertEqual(board['planningState'],'QUEUED')
            self.assertIsNone(board['installed'])
            return query,ai,board

        if external:
            proposed=core._read(decision['requestId'])['request']['params']
            first,second=lc.merge_expansion(decision['requestId'],proposed)['steps']
            endpoint.external=True
            code,external_rows,_=self.call(PREFIX+'/discover',{},cookie=cookie,csrf=csrf)
            self.assertEqual((code,external_rows),(200,[{'number':7,'state':'BLOCKED',
                                                   'reason':'EXTERNAL_MERGE'}]))
            retired=core._read(decision['requestId'])
            self.assertEqual((retired['state'],retired['failure']),('STALE','MERGE_ALREADY_EXTERNAL'))
            self.assertIsNone(native.receipt(first['stepId']))
            self.assertIsNone(lineage.domain.source_operation(second['stepId']))
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],1)
            self.assertEqual(endpoint.writes,0)
            ident={'requestId':decision['requestId']}
            self.assertEqual(self.call(PREFIX+'/register-confirmed/begin',
                ident,cookie=cookie,csrf=csrf)[0],403)
            path=PREFIX+'/register-external'
            self.assertEqual(self.call(path+'/begin',ident,cookie=cookie,csrf=csrf)[0],403)
            self.frames.external_source_authorize=lambda a,act,body:a=='owner-actor'
            code,proof,_=self.call(path+'/begin',ident,cookie=cookie,csrf=csrf)
            self.assertEqual(code,200,proof)
            self.assertEqual(proof['mergeSha'],merge)
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],1)
            code,registered,_=self.call(path+'/finish',{**ident,'fingerprint':proof['fingerprint'],
                'ceremonyId':proof['ceremonyId'],'response':self.key.assert_(proof)},cookie=cookie,csrf=csrf)
            self.assertEqual((code,registered.get('state')),(200,'EXTERNAL_REGISTERED'),registered)
            receipt=lineage.domain.source_operation(lc.external_operation(decision['requestId']))
            self.assertEqual((receipt['kind'],receipt['sourceCursor']),('EXTERNAL_MERGE',merge))
            self.assertEqual(read_board()[2]['desired']['provenance'],'ACCOUNTED_EXTERNAL_MERGE')
            self.assertEqual(core._read(decision['requestId'])['state'],'STALE')
            self.assertIsNone(native.receipt(first['stepId']))
            self.assertIsNone(lineage.domain.source_operation(second['stepId']))
            self.assertEqual(self.call(path+'/begin',ident,cookie=cookie,csrf=csrf)[1],registered)
            self.assertEqual(endpoint.writes,0)
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],2)
            return
        if not (base_race or partial or corrective):
            rejected={**decision,'decision':'reject'}
            code,challenge,_=self.call('/v1/owner/decision/begin',rejected,cookie=cookie,csrf=csrf)
            self.assertEqual(code,200,challenge)
            code,result,_=self.call('/v1/owner/decision/finish',{**rejected,
                'ceremonyId':challenge['ceremonyId'],'response':self.key.assert_(challenge)},
                cookie=cookie,csrf=csrf)
            self.assertEqual((code,result['state']),(200,'REJECTED'))
            code,refresh,_=self.call(PREFIX+'/discover',{},cookie=cookie,csrf=csrf)
            self.assertEqual((code,refresh[0]['requestId'],refresh[0]['state']),
                             (200,decision['requestId'],'REJECTED'))
            code,new,_=self.call(PREFIX+'/repropose',{'requestId':decision['requestId']},
                                 cookie=cookie,csrf=csrf)
            self.assertEqual((code,new['state']),(200,'PENDING'))
            self.assertNotEqual(new['requestId'],decision['requestId'])
            self.assertEqual(endpoint.writes,0)
            decision['requestId']=new['requestId']
            discovered=perf_counter()
        code,challenge,_=self.call('/v1/owner/decision/begin',decision,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200,challenge)
        self.assertTrue(core._read(decision['requestId'])['preview']['composite'])
        from fortis_approvals.extensions import composite_journal
        from contextlib import nullcontext
        append=composite_journal.append_step
        def interrupt(db,ident,*,ordinal,step_id,state,detail):
            if ordinal==1 and state=='DISPATCHED':
                raise RuntimeError('fixture interruption before Registry dispatch')
            return append(db,ident,ordinal=ordinal,step_id=step_id,state=state,detail=detail)
        case=patch.object(composite_journal,'append_step',side_effect=interrupt) if partial else nullcontext()
        if kernel_peer:
            pending = core._read(decision['requestId'])
            proposed = pending['request']['params']
            expansion = lc.merge_expansion(pending['requestId'], proposed)
            first_step, second_step = expansion['steps']
            observation = {k:proposed[k] for k in (
                'repository','number','headSha','treeSha','catalogSha256',
                'bodyDigest','impactDigest','pathsDigest','ciDigest')}
            observation.update(mergeSha=merge, mainSha=merge, parents=[self.base,self.head])
            remote_receipt = {'operationId':first_step['stepId'], 'parentRequestId':pending['requestId'],
                'proposalDigest':sc.digest(proposed), 'captureDigest':'f'*64, 'observation':observation}
            source_request = {'operationId':second_step['stepId'], 'kind':'MERGE',
                'parentRequestId':pending['requestId'], 'proposal':proposed, 'observation':observation,
                'evidenceDigest':sc.digest(remote_receipt), 'transition':None}
            source_context = {'parentId':pending['requestId'], 'stepId':second_step['stepId'],
                'definitionDigest':expansion['definitionDigest'],
                'authorityDigest':pending['preview']['authorityDigest'],
                'policyAuthorityDigest':core.authority.sha, 'fingerprint':pending['fingerprint'],
                'policyVersion':core.policy_version, 'owner':owner.owner, 'target':'scope'}
            proof_path = proof.evidence_path(proof_root, merge)
            with self.assertRaisesRegex(Denied, 'REGISTRY_CANDIDATE_RESPONSE_DENIED'):
                transport.register_source('owner-actor', source_context, source_request, remote_receipt)
            proof_path.write_bytes(b'invalid evidence')
            proof_path.chmod(0o640)
            with self.assertRaisesRegex(Denied, 'REGISTRY_CANDIDATE_RESPONSE_DENIED'):
                transport.register_source('owner-actor', source_context, source_request, remote_receipt)
            proof_path.unlink()
            self.assertIsNone(lineage.domain.source_operation(second_step['stepId']))
            self.assertEqual(endpoint.writes,0)
        with case:
            code,result,_=self.call('/v1/owner/decision/finish',{**decision,
                'ceremonyId':challenge['ceremonyId'],'response':self.key.assert_(challenge)},
                cookie=cookie,csrf=csrf)
        executed=perf_counter()
        p=core._read(decision['requestId'])['request']['params']
        first,second=lc.merge_expansion(decision['requestId'],p)['steps']
        if kernel_peer:
            native = core.adapters['github']
        self.assertEqual(native.receipt(first['stepId'])['sha'],merge)
        if base_race:
            self.assertEqual((code,result.get('state')),(200,'UNCERTAIN'),result)
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],1)
            self.assertIsNone(lineage.domain.source_operation(second['stepId']))
            with self.assertRaisesRegex(Denied,'SUCCESSOR_MERGE_PARENTS_CHANGED'):
                core.reconcile(decision['requestId'])
            self.assertEqual(core._read(decision['requestId'])['state'],'UNCERTAIN')
            self.assertEqual(endpoint.writes,1)
            return
        if partial:
            self.assertEqual((code,result.get('state')),(200,'UNCERTAIN'),result)
            self.assertIsNone(lineage.domain.source_operation(second['stepId']))
            self.assertEqual(core.reconcile(decision['requestId'])['state'],'UNCERTAIN')
            path=PREFIX+'/register-confirmed'
            ident={'requestId':decision['requestId']}
            status,recovery,_=self.call(path+'/begin',ident,cookie=cookie,csrf=csrf)
            self.assertEqual(status,200,recovery)
            self.assertEqual(recovery['mergeSha'],merge)
            code,result,_=self.call(path+'/finish',{**ident,'fingerprint':recovery['fingerprint'],
                'ceremonyId':recovery['ceremonyId'],'response':self.key.assert_(recovery)},
                cookie=cookie,csrf=csrf)
            self.assertEqual(self.call(path+'/begin',ident,cookie=cookie,csrf=csrf)[0],403)
        self.assertEqual((code,result.get('state')),(200,'EXECUTED'),result)
        self.assertEqual(lineage.domain.source_operation(second['stepId'])['sourceCursor'],merge)
        self.assertEqual(endpoint.writes,1)
        if corrective:
            self.assertEqual(p['expectedSourceRevision'],3)
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],4)
            self.assertEqual(lineage.domain.source_operation(second['stepId'])['kind'],'MERGE')
            for receipt in (transition_receipt,repair_receipt,third_receipt):
                self.assertEqual(lineage.domain.source_operation(receipt['operationId']),receipt)
            self.assertEqual(original_domain.snapshot(),original_snapshot)

        query,ai,board=read_board()
        plan={**query,'operation':'plan_batch','params':{'items':[
            {'subject':board['subject'],'source':board['desired']['source']}]}}
        code,planned,_=self.call(PREFIX+'/read',plan,cookie=cookie,csrf=csrf)
        self.assertEqual(code,200,planned)
        self.assertEqual(planned['data']['data']['status'],'PLAN_READY',planned)
        self.assertFalse(planned['data']['data']['deploymentAuthorized'])
        self.frames.service.domain=lineage.reopen()
        reopened_native=NativeGitHubAdapter(endpoint,config=github_config,
            root=self.root,actor='agent-1',backend=None,store=None)
        if not kernel_peer:
            self.assertEqual(reopened_native.receipt(first['stepId']),native.receipt(first['stepId']))
        before_restart = snapshot(core, lambda db: authority_witness(core, db))
        reopened=build(transition=not corrective,
                       companion=sc.digest(frozen_companion) if corrective else companion_digest,
                       adapter=reopened_native,reopening=True,rebind=corrective)
        self.assertEqual(snapshot(reopened, lambda db: authority_witness(reopened, db)),
                         before_restart)
        self.assertEqual(reopened.execute(decision['requestId'])['state'],'EXECUTED')
        self.assertEqual(SemanticAccessTests.http(self,'/v1/reads',query),(200,ai))
        self.assertEqual(endpoint.writes,1)
        if kernel_peer:
            cookie,csrf=G2WebAuthnTest.login(self)
            stop_peer()
            with self.assertRaisesRegex(Denied,'REGISTRY_CANDIDATE_TRANSPORT_UNAVAILABLE'):
                transport.profile_digest()
            socket_peer, _ = start_registry_writer(registry_config)
            self.assertEqual(load_peer(released)._semantic_transport.profile_digest(), sc.digest(profile))
            self.assertEqual(transport.source_operation('owner-actor',source_context,p),
                             lineage.domain.source_operation(second['stepId']))
            self.assertIn((api.branch,self.head),fetches)
            self.assertEqual(fetches.count(('main',merge)),1)
            identity = {'uid':os.geteuid(), 'gid':os.getegid()}
            retained_header,bundle = proof.read_evidence(proof_root,merge,**identity)
            self.assertEqual(retained_header['observation'],observation)
            proof.publish_evidence(proof_root,retained_header,bundle,**identity)
            with self.assertRaisesRegex(Denied,'SOURCE_EVIDENCE_PUBLICATION_CHANGED'):
                proof.publish_evidence(proof_root,{**retained_header,'bundleDigest':'0'*64},
                                       bundle,**identity)
            self.assertEqual(proof.read_evidence(proof_root,merge,**identity),(retained_header,bundle))
            code,after_portal,_=self.call(PREFIX+'/read',query,cookie=cookie,csrf=csrf)
            self.assertEqual(code,200,after_portal)
            self.assertEqual(after_portal['data'],ai['data'])
            self.assertEqual(SemanticAccessTests.http(self,'/v1/reads',query),(200,ai))
            self.assertEqual(endpoint.writes,1)
        if corrective:
            self.assertEqual(lineage.domain.snapshot()['sourceRevision'],4)
            self.assertEqual(original_domain.snapshot(),original_snapshot)
            print('CORRECTIVE_REVISION_3_TO_4_PRODUCT_PASS')
        print('E2_LOCAL_TIMINGS discovery=%.3fs approval_to_merge_and_registry=%.3fs shared_reads=%.3fs'
              % (discovery_seconds,executed-discovered,perf_counter()-executed))

    def test_profile_pin_mismatch(self):
        self.verifier.profile_digest='f'*64
        with self.assertRaises(Denied):self.verifier.verify(self.observed)


class RetainedEnrollmentTests(unittest.TestCase):
    def test_exact_reviewed_source_rebind_does_not_change_enrollment(self):
        from fortis_approvals.extensions.composite_authority import MergeContextGrant
        from fortis_approvals.extensions.composite_contract import definition
        from fortis_approvals.extensions.successor_runtime import (
            ProtectedRegistrySuccessor, _RETAINED_288_ENROLLMENT_SOURCE)
        from fortis_approvals.integrations.registry.read_contract import REPOSITORY

        old = _RETAINED_288_ENROLLMENT_SOURCE
        new = '9'*64  # synthetic newly packaged source, not a live image
        recipe = definition('release','merge_and_register').definition_digest
        context = [MergeContextGrant('owner','scope','github','merge_pull_request',
                                      'fortis-approvals',REPOSITORY,recipe).record()]
        semantic = [{'actor':'agent','service':'registry','operation':'list_components',
                     'target':'scope','subject':{'repository':REPOSITORY}}]
        def pin(rows):
            return sc.digest({'schemaVersion':1,'sourceDigest':old,
                              'grants':sorted(rows,key=sc.canonical)})
        ci = {}
        config = {'schemaVersion':1,'repository':REPOSITORY,'target':'scope',
                  'ownerPrincipal':'owner','context':context,'contextDigest':pin(context),
                  'semantic':semantic,'semanticDigest':pin(semantic),'successorDigest':'a'*64,
                  'companionDigest':'b'*64,'interlockDigest':'c'*64,'transition':False,
                  'frozenHandoff':None,'validatorRevision':'d'*40,'impactBinding':{},
                  'buildPins':{},'ciPolicy':ci,'ciPolicyDigest':sc.digest(ci)}
        original=ProtectedRegistrySuccessor(config,source_digest=old)
        with self.assertRaisesRegex(Denied,'COMPOSITE_CONTEXT_PIN_MISMATCH'):
            ProtectedRegistrySuccessor(config,source_digest=new)
        retained={**config,'schemaVersion':2,'retainedEnrollmentSourceDigest':old}
        revised=ProtectedRegistrySuccessor(retained,source_digest=new)
        self.assertEqual(revised._source_digest,new)
        self.assertEqual(revised.context.metadata(),original.context.metadata())
        self.assertEqual(revised.semantic.metadata(),original.semantic.metadata())
        for changed in ({'transition':True},{'retainedEnrollmentSourceDigest':'0'*64}):
            with self.assertRaisesRegex(Denied,'R7_REGISTRY_RETAINED_ENROLLMENT_DENIED'):
                ProtectedRegistrySuccessor({**retained,**changed},source_digest=new)
        with self.assertRaisesRegex(Denied,'R7_REGISTRY_RETAINED_ENROLLMENT_DENIED'):
            ProtectedRegistrySuccessor(retained,source_digest=old)
        changed=[{**semantic[0],'actor':'other'}]
        with self.assertRaisesRegex(Denied,'SEMANTIC_SCOPE_PIN_CHANGED'):
            ProtectedRegistrySuccessor({**retained,'semantic':changed},source_digest=new)
        changed_context=[{**context[0],'parent':['other',*context[0]['parent'][1:]],
                          'child':['other',*context[0]['child'][1:]]}]
        with self.assertRaisesRegex(Denied,'COMPOSITE_CONTEXT_PIN_MISMATCH'):
            ProtectedRegistrySuccessor({**retained,'context':changed_context},source_digest=new)


class CITests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.rules=[{'type':'required_status_checks','parameters':{'required_status_checks':[
            {'context':'release-impact','integration_id':15368}]}}]
        self.policy={'schemaVersion':1,'repository':'Owner/fortis-approvals',
             'rulesDigest':sc.digest(self.rules),'workflows':[
             {'name':'Source CI','id':1,'path':'.github/workflows/source-ci.yml',
              'jobs':['offline-tests','audit-projections'],'sha256':'a'*64},
             {'name':'Fortis Release Impact','id':2,'path':'.github/workflows/release-impact.yml',
              'jobs':['release-impact'],'sha256':'b'*64}]}
        self.adapter=AnalysisGitHubAdapter(self,owner='Owner',repositories=['fortis-approvals'],
              receipt_store=self.root/'github.sqlite',
              bindings={'fortis-approvals':{'workflows':{str(w['id']):w['path'] for w in self.policy['workflows']},
                        'projectKey':'fixture','allowCiControl':False}})
        self.allowed=True
        self.ci=SuccessorCI(self.adapter,policy=self.policy,expected_digest=sc.digest(self.policy),
                          read_guard=lambda *_:self.allowed)
        self.observed={'repository':self.policy['repository'],'number':12,
                       'baseSha':'a'*40,'headSha':'b'*40,'headBranch':'fixture'}

    def request(self,method,path,**kwargs):
        self.assertEqual(method,'GET')
        self.assertTrue(path.endswith('/rules/branches/main'))
        return copy.deepcopy(self.rules)

    def test_policy_pin_and_required_workflow(self):
        with self.assertRaises(Denied):SuccessorCI(self.adapter,policy=self.policy,
              expected_digest='f'*64,read_guard=lambda *_:True)
        p=copy.deepcopy(self.policy);p['workflows'][0]['jobs']=['offline-tests']
        with self.assertRaises(Denied):SuccessorCI(self.adapter,policy=p,
              expected_digest=sc.digest(p),read_guard=lambda *_:True)

    def test_changed_rules_and_revoked_read_stop_before_runs(self):
        self.rules[0]['parameters']['required_status_checks'].append({'context':'other','integration_id':15368})
        with self.assertRaises(Denied):self.ci.observe('agent',self.observed)
        self.allowed=False
        with self.assertRaises(Denied):self.ci.observe('agent',self.observed)

    def test_exact_attempt_job_and_check_binding(self):
        # Exercise the new join, with existing independently tested native
        # run/check collectors as explicit fixture seams, not live proof.
        runs=[{'runId':n,'attempt':1,'runNumber':n,'jobs':[{'name':j,'id':100*n+i}
              for i,j in enumerate(w.jobs)]} for n,w in enumerate(self.ci.workflows,1)]
        rows=[{'workflowId':w.ident,'runNumber':n,'runAttempt':1,'id':n,
               'name':w.name,'workflowPath':w.path,'status':'completed','conclusion':'success'}
               for n,w in enumerate(self.ci.workflows,1)]
        checks=[{'name':'release-impact','checkRunId':200}]
        mod='fortis_approvals.extensions.successor_ci.'
        with patch(mod+'_collect_workflow_evidence',return_value=runs),patch(mod+'_inventory',return_value=rows),patch(mod+'observe_check_witnesses',return_value=checks):
            out=self.ci.observe('agent',self.observed)
            self.assertEqual(out['policyDigest'],sc.digest(self.policy))
            self.assertEqual(out['runs'],runs)
            rows[1]['runAttempt']=2
            with self.assertRaises(Denied):self.ci.observe('agent',self.observed)

class CheckProvider(ci_fixture.Provider):
    def __init__(self):
        super().__init__()
        self.rules=[{'type':'required_status_checks','parameters':{'required_status_checks':[
            {'context':name,'integration_id':15368} for w in WORKFLOWS for name in w.jobs]}}]
        self.check_changes={}

    def request(self,method,path,**kwargs):
        if path.endswith('/check-runs') or path.endswith('/status'):
            assert method=='GET'
            suffix=path.split('/fortis-approvals',1)[1]
            self.calls.append((method,suffix,kwargs.get('params'),None))
            if path.endswith('/status'):
                return {'sha':self.head,'total_count':0,'statuses':[]}
            rows=[]
            for run in self.runs():
                w=next(w for w in WORKFLOWS if w.ident==run['workflow_id'])
                for i,name in enumerate(w.jobs):
                    ident=1000+run['id']*10+i
                    row={'id':ident,'head_sha':self.head,'name':name,'app':{'id':15368,'slug':'github-actions'},
                         'status':'completed','conclusion':'success',
                         'details_url':'https://github.com/'+pub_fixture.OWNER+'/fortis-approvals/actions/runs/'+str(run['id'])+'/job/'+str(ident),
                         'started_at':'2026-11-16T01:00:00Z','completed_at':'2026-11-16T01:01:00Z'}
                    row.update(self.check_changes.get(name,{}));rows.append(row)
            return {'total_count':len(rows),'check_runs':rows}
        return super().request(method,path,**kwargs)


def make_ci(api,path,*,repository=pub_fixture.OWNER+'/fortis-approvals',transport=None):
    adapter=AnalysisGitHubAdapter(transport or api,owner=repository.split('/')[0],repositories=['fortis-approvals'],
        receipt_store=path,bindings={'fortis-approvals':{'workflows':{str(w.ident):w.path for w in WORKFLOWS},
                                      'projectKey':'fixture','allowCiControl':False}})
    policy={'schemaVersion':1,'repository':repository,
            'rulesDigest':sc.digest(sorted(api.rules,key=sc.canonical)),
            'workflows':[{'name':w.name,'id':w.ident,'path':w.path,'jobs':list(w.jobs),'sha256':w.sha256}
                         for w in WORKFLOWS]}
    return SuccessorCI(adapter,policy=policy,expected_digest=sc.digest(policy),read_guard=lambda *_:True)


class NativeCITests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.api=CheckProvider();self.ci=make_ci(self.api,Path(temp.name)/'receipts.sqlite')
        self.observed={'repository':pub_fixture.OWNER+'/fortis-approvals','number':7,
                      'baseSha':self.api.base,'headSha':self.api.head,'headBranch':self.api.branch}

    def test_real_collectors_all_exact_head_jobs_checks(self):
        result=self.ci.observe('agent',self.observed)
        self.assertEqual(len(result['runs']),2)
        self.assertEqual(len(result['checks']),3)
        self.assertTrue(all(c[0]=='GET' for c in self.api.calls))

    def test_wrong_app_or_new_attempt_or_changed_workflow(self):
        self.api.check_changes['release-impact']={'app':{'id':1,'slug':'other'}}
        with self.assertRaises(Denied):self.ci.observe('agent',self.observed)
        self.api.check_changes={}
        self.api.job_changes['release-impact']={'run_attempt':2}
        with self.assertRaises(Denied):self.ci.observe('agent',self.observed)
        self.api.job_changes={}
        self.api.sources[WORKFLOWS[0].path]+=b'\n# changed'
        with self.assertRaises(Denied):self.ci.observe('agent',self.observed)
