"""Join independent source/CI observations into a proposal and capture.

Source-only composition; the actual current cursor and approved pins are
provided by reviewed server composition. No upstream merge operation.
"""
from contextlib import nullcontext

from ..integrations.registry_contracts import semantic_contract as sc
from ..integrations.registry_contracts.source_lineage_contract import proposal
from .successor_impact import SuccessorImpact
from .successor_ci import SuccessorCI
from .merge_capture import validate


class SuccessorProjector:
    def __init__(self,impact,ci,*,source_revision,expected_composition_digest, source_view=None):
        sc.need(type(impact) is SuccessorImpact and type(ci) is SuccessorCI and callable(source_revision))
        sc.hex_id(expected_composition_digest,64)
        self.impact,self.ci,self.source_revision=impact,ci,source_revision
        sc.need(source_view is None or callable(source_view))
        self.source_view = source_view
        self.pin=expected_composition_digest
        self._check()

    def _check(self):
        ci=sc.loads_strict(self.ci.policy)
        sc.need(ci['repository']==self.impact.repository and
                sc.digest(ci)==self.ci.pin and sc.digest({
                    'repository':self.impact.repository,'validatorRevision':self.impact.revision,
                    'ciPolicyDigest':self.ci.pin,'profileDigest':self.impact.profile_digest
                })==self.pin,'SUCCESSOR_EVIDENCE_COMPOSITION_CHANGED')

    def refresh_ci(self,actor,observed,*,validator_revision,impact_digest,revision):
        self._check()
        sc.need(validator_revision==self.impact.revision and self.source_revision()==revision,
                'SUCCESSOR_SOURCE_REVISION_CHANGED')
        ci=self.ci.observe(actor,observed)
        sc.need(self.source_revision()==revision,'SUCCESSOR_SOURCE_REVISION_CHANGED')
        self._check()
        return {**ci,'validatorRevision':validator_revision,
                'validatedImpactDigest':impact_digest,'compositionDigest':self.pin}

    def evidence(self,actor,observed):
        self._check()
        revision=self.source_revision()
        sc.revision(revision)
        selected = self.source_view(observed) if self.source_view is not None else nullcontext(None)
        with selected as repository:
            verifier = self.impact if repository is None else self.impact.with_source(repository)
            impact=verifier.verify(observed)
            verifier.verify_workflows(observed['headSha'],self.ci.workflows)
        # Retain the immutable validation result under the proposal CI digest.
        ci=self.refresh_ci(actor,observed,validator_revision=impact['validatorRevision'],
                           impact_digest=sc.digest(impact),revision=revision)
        p={k:observed[k] for k in ('repository','number','baseSha','headSha','treeSha',
                                  'catalogSha256','bodyDigest','impactDigest','pathsDigest')}
        p.update({k:impact[k] for k in ('profileDigest','classification','targets','dependencies')})
        p.update(expectedSourceRevision=revision,ciDigest=sc.digest(ci),
                 dependencyDigest=sc.digest(impact['dependencies']))
        p=proposal(p)
        material=validate({'body':observed['body'],'catalog':observed['catalog'],
            'paths':observed['paths'],'ci':ci,'validatedProjectionDigest':sc.digest(
                {k:p[k] for k in ('classification','targets','dependencies','profileDigest')})},p)
        return p,material

    def __call__(self,actor,observed):
        return self.evidence(actor,observed)[0]
