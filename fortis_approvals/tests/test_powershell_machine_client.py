import unittest

from fortis_approvals.core import Denied
from fortis_approvals.workflow.powershell_client import PowerShellMachineClient

UUID = "01234567-89ab-4def-8abc-0123456789ab"


class FakeGateway:
    def __init__(self):
        self.calls = []
        self.fail = False

    def post(self, path, payload, **kwargs):
        self.calls.append((path,payload,kwargs))
        if self.fail:
            raise TimeoutError("synthetic lost ACK")
        if path.endswith("capabilities"):
            return dict(configured=True,policy="ASK",
                        machineExecutionAutoApprove=False,version=1)
        if path.endswith("submit"):
            return dict(requestId=payload["requestId"],state="PENDING")
        return dict(requestId=payload["requestId"],state="PENDING",
                    result=None,failure=None)


class MachineClientTest(unittest.TestCase):
    def setUp(self):
        self.gateway=FakeGateway()
        self.client=PowerShellMachineClient(self.gateway)

    def test_capabilities_is_ask_only(self):
        self.assertEqual(self.client.capabilities()["policy"],"ASK")
        self.assertEqual(len(self.gateway.calls),1)

    def test_submit_carries_no_authority_and_no_retry(self):
        result=self.client.submit("Get-Date",request_id=UUID)
        self.assertEqual(result["state"],"PENDING")
        self.assertEqual(self.gateway.calls, [
            ("/v1/powershell/submit",
             {"requestId":UUID,"target":"windows-owner","command":"Get-Date"},
             {"accept_202":True})])

    def test_lost_ack_does_not_automatically_resubmit(self):
        self.gateway.fail=True
        with self.assertRaises(TimeoutError):
            self.client.submit("Get-Date",request_id=UUID)
        self.assertEqual(len(self.gateway.calls),1)

    def test_bad_actor_chosen_privileged_params_not_supported(self):
        with self.assertRaises(TypeError):
            self.client.submit("Get-Date",request_id=UUID, bearer="secret")
        self.assertEqual(self.gateway.calls,[])

    def test_reject_invalid_before_network(self):
        for command in ("", "\x00", "x"*8193, "\ud800"):
            with self.subTest(repr=repr(command)),self.assertRaises(Denied):
                self.client.submit(command,request_id=UUID)
        with self.assertRaises(Denied):
            self.client.submit("Get-Date",request_id="invalid")
        with self.assertRaises(Denied):
            self.client.submit("Get-Date",request_id=UUID,target="http://evil")
        self.assertEqual(self.gateway.calls,[])

    def test_result_is_read_only_and_original_uuid(self):
        result=self.client.result(UUID)
        self.assertEqual(result["state"],"PENDING")
        self.assertEqual(self.gateway.calls[0][0],"/v1/powershell/result")
        self.assertEqual(self.gateway.calls[0][1],{"requestId":UUID})

    def test_insecure_capabilities_rejected(self):
        self.gateway.post=lambda *_args,**_kw: dict(
            configured=True,policy="ALLOW",
            machineExecutionAutoApprove=True,version=1)
        with self.assertRaises(Denied):
            self.client.capabilities()


if __name__ == "__main__":
    unittest.main()
