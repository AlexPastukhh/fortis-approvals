"""Focused regressions for the trusted OpenHolidays draft hooks."""
from email.message import Message
from http.client import IncompleteRead
import unittest
from unittest.mock import MagicMock

from fortis_approvals.core import Denied
from fortis_approvals.integrations.open_holidays_pilot import manual


class ManualContractTests(unittest.TestCase):
    def test_route_is_closed_to_caller_query(self):
        transport = manual.make_transport()
        with self.assertRaisesRegex(Denied, "PILOT_REQUEST_NOT_FIXED"):
            transport.call("public_holidays", query={"countryIsoCode": "FR"})

    def test_request_rejects_non_mapping_empty_query_before_connecting(self):
        opener = MagicMock()
        transport = manual.HolidayTransport(opener=opener)
        with self.assertRaisesRegex(Denied, "PILOT_REQUEST_NOT_FIXED"):
            transport.call("public_holidays", query=[])
        opener.open.assert_not_called()

    def response_transport(self):
        response = MagicMock()
        response.status = 200
        response.geturl.return_value = manual.URL
        response.headers = Message()
        response.headers["Content-Type"] = "application/json"
        response.read.return_value = b"[]"
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        return manual.HolidayTransport(opener=opener), response

    def test_fixed_query_accepts_a_complete_json_array(self):
        transport, response = self.response_transport()
        response.headers["Content-Length"] = "2"
        self.assertEqual(transport.call("public_holidays"), {"holidays": []})
        self.assertEqual(manual.URL, "https://openholidaysapi.org/PublicHolidays?"
                         "countryIsoCode=DE&languageIsoCode=EN&validFrom=2026-01-01&validTo=2026-12-31")

    def test_truncated_response_with_parseable_json_is_rejected(self):
        transport, response = self.response_transport()
        response.headers["Content-Length"] = "12"
        with self.assertRaisesRegex(Denied, "PILOT_UPSTREAM_TRUNCATED"):
            transport.call("public_holidays")

    def test_incomplete_http_read_is_a_controlled_denial(self):
        transport, response = self.response_transport()
        response.read.side_effect = IncompleteRead(b"[", 1)
        with self.assertRaisesRegex(Denied, "PILOT_UPSTREAM_TRUNCATED"):
            transport.call("public_holidays")

    def test_ambiguous_response_framing_is_rejected_before_read(self):
        transport, response = self.response_transport()
        response.headers["Content-Length"] = "2"
        response.headers["Transfer-Encoding"] = "chunked"
        with self.assertRaisesRegex(Denied, "PILOT_UPSTREAM_BAD_FRAMING"):
            transport.call("public_holidays")
        response.read.assert_not_called()

    def test_date_check_accepts_scope_and_rejects_invalid_date(self):
        postcheck = manual.result_postchecks()["public_holidays"]
        postcheck({"holidays": [{"start_date": "2026-01-01", "end_date": "2026-01-01"}]})
        for start, end in (("2026-02-30", "2026-02-30"),
                           ("2026-12-31", "2027-01-01"),
                           ("2026-04-02", "2026-04-01")):
            with self.subTest(start=start, end=end), self.assertRaisesRegex(Denied, "PILOT_HOLIDAY_DATE"):
                postcheck({"holidays": [{"start_date": start, "end_date": end}]})
