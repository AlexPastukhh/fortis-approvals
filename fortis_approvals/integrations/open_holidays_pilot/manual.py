"""Fixed OpenHolidays READ pilot transport for an isolated Fortis source test."""
from datetime import date
from http.client import HTTPException, IncompleteRead
from urllib import error, request
from urllib.parse import urlencode

from fortis_approvals.core import Denied, loads_strict
from fortis_approvals.extensions.http import NoRedirect, Route
from fortis_approvals.extensions.model import check

ORIGIN = "https://openholidaysapi.org"
ROUTE = Route("public_holidays", "GET", "/PublicHolidays", readonly=True)
DATE_RANGE = ("2026-01-01", "2026-12-31")
QUERY = {
    "countryIsoCode": "DE",
    "languageIsoCode": "EN",
    "validFrom": DATE_RANGE[0],
    "validTo": DATE_RANGE[1],
}
MAX_BYTES = 262144
URL = ORIGIN + ROUTE.path + "?" + urlencode(QUERY)


class HolidayTransport:
    def __init__(self, *, opener=None):
        self.routes = {ROUTE.name: ROUTE}
        self._opener = opener or request.build_opener(request.ProxyHandler({}), NoRedirect())

    def call(self, route_name, *, credential=None, path=None, query=None, body=None, request_id=None):
        check(route_name == ROUTE.name, "PILOT_ROUTE_DENIED")
        check(credential is None and path in (None, {}) and query in (None, {}) and body is None,
              "PILOT_REQUEST_NOT_FIXED")
        upstream = request.Request(URL, method="GET", headers={"Accept": "application/json"})
        try:
            with self._opener.open(upstream, timeout=8) as response:
                check(response.status == 200, "PILOT_UPSTREAM_STATUS")
                check(response.geturl() == URL, "PILOT_REDIRECT_DENIED")
                check(response.headers.get_content_type() == "application/json",
                      "PILOT_UPSTREAM_CONTENT_TYPE")
                lengths = response.headers.get_all("Content-Length", ())
                declared_length = None
                if lengths:
                    length = lengths[0].strip()
                    check(len(lengths) == 1 and response.headers.get("Transfer-Encoding") is None
                          and 1 <= len(length) <= 10 and length.isascii() and length.isdecimal(),
                          "PILOT_UPSTREAM_BAD_FRAMING")
                    declared_length = int(length)
                    check(declared_length <= MAX_BYTES, "PILOT_UPSTREAM_SIZE")
                raw = response.read(MAX_BYTES + 1)
        except error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise Denied("PILOT_REDIRECT_DENIED" if 300 <= code < 400
                         else "PILOT_UPSTREAM_STATUS") from None
        except IncompleteRead:
            raise Denied("PILOT_UPSTREAM_TRUNCATED") from None
        except (error.URLError, OSError, HTTPException):
            raise Denied("PILOT_UPSTREAM_UNAVAILABLE") from None
        check(len(raw) <= MAX_BYTES, "PILOT_UPSTREAM_SIZE")
        check(declared_length is None or len(raw) == declared_length, "PILOT_UPSTREAM_TRUNCATED")
        rows = loads_strict(raw)
        check(type(rows) is list, "PILOT_HOLIDAY_ROWS")
        return {"holidays": rows}


def holiday_dates(result):
    for holiday in result["holidays"]:
        try:
            start, end = (date.fromisoformat(holiday[key]).isoformat()
                          for key in ("start_date", "end_date"))
        except ValueError:
            raise Denied("PILOT_HOLIDAY_DATE") from None
        check(DATE_RANGE[0] <= start <= end <= DATE_RANGE[1] and
              start == holiday["start_date"] and end == holiday["end_date"],
              "PILOT_HOLIDAY_DATE")


def make_transport():
    return HolidayTransport()


def result_postchecks():
    return {"public_holidays": holiday_dates}


def context_postchecks():
    return {}


def manual_operations():
    return ()
