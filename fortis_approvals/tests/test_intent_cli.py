"""CLI continuation uses the same intent entrypoint and needs no stdin/UUID."""
import io
import json
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock,patch

from fortis_approvals.workflow.client import main


class CLITests(unittest.TestCase):
    def invoke(self,args,body='',client=None):
        client=client or MagicMock()
        client.command.return_value={'status':'DONE'}
        client.publish.return_value={'status':'DONE'}
        client.intents.retry.return_value={'status':'DONE'}
        client.resume.return_value={'state':'PENDING'}
        output=io.StringIO()
        with patch.object(sys,'argv',['workflow',*args]),patch.object(sys,'stdin',io.StringIO(body)),\
             patch.object(sys,'stdout',output),patch('fortis_approvals.workflow.client.default_client',return_value=client):
            main()
        return client,json.loads(output.getvalue())
    def test_supported_command_and_publish_do_not_require_request_id(self):
        client,result=self.invoke(['create_task'],json.dumps(dict(task='agent',baseSha='a'*40,adoptHeadSha=None)))
        self.assertEqual(result['status'],'DONE')
        self.assertIsNone(client.command.call_args.kwargs['request_id'])
        client,_=self.invoke(['publish'],json.dumps(dict(task='agent',expectedHeadSha=None,newSha='b'*40)))
        self.assertIsNone(client.publish.call_args.kwargs['request_id'])
    def test_retry_accepts_only_intent_id_and_never_reads_stdin(self):
        client=MagicMock();client.intents.retry.return_value={'status':'WAITING'}
        stdin=SimpleNamespace(read=lambda: self.fail('retry must not wait for stdin'))
        with patch.object(sys,'argv',['workflow','retry','--intent-id','saved-intent']),\
             patch.object(sys,'stdin',stdin),patch.object(sys,'stdout',io.StringIO()),\
             patch('fortis_approvals.workflow.client.default_client',return_value=client):
            main()
        client.intents.retry.assert_called_once_with('saved-intent')
        client.resume.assert_not_called()
    def test_explicit_legacy_request_id_is_forwarded_and_resume_is_distinct(self):
        ident='11111111-1111-4111-8111-111111111111'
        client,_=self.invoke(['publish','--request-id',ident],
                            json.dumps(dict(task='agent',expectedHeadSha=None,newSha='b'*40)))
        self.assertEqual(client.publish.call_args.kwargs['request_id'],ident)
        client,result=self.invoke(['resume','--request-id',ident])
        client.resume.assert_called_once_with(ident)
        client.intents.retry.assert_not_called()
    def test_missing_or_mixed_handle_fails_before_client_creation(self):
        for args in [['retry'],['retry','--intent-id','x','--request-id','y'],['inspect'],
                     ['publish','--intent-id','x']]:
            with patch.object(sys,'argv',['workflow',*args]),patch.object(sys,'stderr',io.StringIO()),\
                 patch('fortis_approvals.workflow.client.default_client') as create:
                with self.assertRaises(SystemExit):main()
                create.assert_not_called()


if __name__=='__main__':unittest.main()
