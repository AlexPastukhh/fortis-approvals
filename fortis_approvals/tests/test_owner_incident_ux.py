"""Static owner UI regression: review/action separation, long content, feedback."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
APP=(ROOT/'static/app.js').read_text()
HTML=(ROOT/'static/index.html').read_text()
CSS=(ROOT/'static/style.css').read_text()


class OwnerIncidentUXSourceTests(unittest.TestCase):
    def test_visible_unresolved_tab_distinct_from_pending_and_history(self):
        self.assertIn('id="unresolved-tab"',HTML)
        self.assertIn("api('/v1/owner/unresolved')",APP)
        self.assertIn("tab==='unresolved'?unresolved.items:null",APP)
        self.assertIn("api('/v1/owner/requests/'+id)",APP)
        self.assertIn('unresolved-count',APP)

    def test_approve_reject_controls_first_and_sticky(self):
        show=APP.split('function show(row){',1)[1].split('function decisionMessage',1)[0]
        self.assertLess(show.index('area.append(controls,feedback)'),show.index('area.append(preview)'))
        self.assertIn("btn.onclick=action(()=>decide(row,decision))",show)
        self.assertIn('position:sticky',CSS)
        self.assertIn('.detail-actions',CSS)
        self.assertIn('max-height:55vh',CSS)

    def test_owner_feedback_and_no_automatic_repeated_decisions(self):
        self.assertIn('decisionBusy=true;lockDetailActions(true)',APP)
        self.assertIn("selected=row;const area=$('detail')",APP)
        self.assertIn('Решение по ',APP)
        self.assertIn('выполнение ещё не подтверждено',APP)
        self.assertIn("try{\n   const exact=await api('/v1/owner/requests/'+row.requestId)",APP)
        self.assertIn('Не отправляйте решение повторно',APP)

    def test_owner_approved_cancel_and_passive_assessment_buttons(self):
        self.assertIn("row.state==='APPROVED'",APP)
        self.assertIn("cancel.textContent='Отменить до выполнения'",APP)
        self.assertIn("api('/v1/owner/incidents/cancel/approved'",APP)
        self.assertIn("api('/v1/owner/incidents/assess'",APP)
        self.assertIn("assess.textContent='Автопроверка результата'",APP)
        self.assertIn("CANCELLED_BEFORE_DISPATCH",APP)
        self.assertIn("OUTCOME_UNCONFIRMED",APP)
        self.assertNotIn("api('/v1/workspace/claim'",APP)

    def test_one_click_owner_close_requires_only_session_csrf_and_known_fingerprint(self):
        self.assertIn("row.state==='UNCERTAIN'",APP)
        self.assertIn("close.textContent='Закрыть заявку'",APP)
        self.assertIn("api('/v1/owner/incidents/close/simple'",APP)
        self.assertIn('{requestId:row.requestId,fingerprint:row.fingerprint},true',APP)
        self.assertIn('Результат операции не подтверждён',APP)
        self.assertNotIn('fortis-gateway-backup-[0-9a-f]{32}',APP)
        self.assertNotIn('/v1/owner/incidents/close/begin',APP)
        self.assertNotIn('/v1/owner/incidents/close/finish',APP)
        self.assertNotIn('innerHTML',APP)
