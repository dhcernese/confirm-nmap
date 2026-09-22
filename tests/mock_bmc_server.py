"""Local stand-in for the management processors this repo scans.

Serves the endpoints the CLIs request (``/xmldata?item=All`` and
``/redfish/v1``) so the Python and Go implementations can be compared against
real HTTP responses instead of connection failures.

The profiles reproduce response shapes observed in previous scan results:
iLO 4/5/6/7, a c7000 Onboard Administrator, a non-HPE BMC, an unauthorized
Redfish service, malformed XML, and a host that answers 404 for everything.
All identifiers are synthetic; only the response structure is taken from real
scans.

Usage:
    python tests/mock_bmc_server.py --profile ilo5
    python tests/mock_bmc_server.py --list
"""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


def nic(port, description, mac, ipaddr, status):
    return (
        "<NIC>"
        f"<PORT>{port}</PORT>"
        f"<DESCRIPTION>{description}</DESCRIPTION>"
        f"<MACADDR>{mac}</MACADDR>"
        f"<IPADDR>{ipaddr}</IPADDR>"
        f"<STATUS>{status}</STATUS>"
        "</NIC>"
    )


def rimp(hsi_block=None, mp_block=None, health_block=None):
    parts = ['<?xml version="1.0"?>', "<RIMP>"]
    for block in (hsi_block, mp_block, health_block):
        if block:
            parts.append(block)
    parts.append("</RIMP>")
    return "\n".join(parts)


def hsi(serial, product_name, uuid, product_id, nics):
    return (
        "<HSI>"
        f"<SBSN>  {serial}  </SBSN>"
        f"<SPN>{product_name}</SPN>"
        f"<UUID>{uuid}</UUID>"
        f"<PRODUCTID>{product_id}</PRODUCTID>"
        "<NICS>" + "".join(nics) + "</NICS>"
        "</HSI>"
    )


def mp(product_name, firmware, serial, state):
    return (
        "<MP>"
        f"<PN>{product_name}</PN>"
        f"<FWRI>{firmware}</FWRI>"
        f"<SN>{serial}</SN>"
        f"<ST>{state}</ST>"
        "</MP>"
    )


def health(status):
    return f"<HEALTH><STATUS>{status}</STATUS></HEALTH>"


def hpe_root(
    product,
    redfish_version,
    uuid,
    manager,
    managers_path="/redfish/v1/Managers",
    service_name="HPE RESTful Root Service",
    vendor="HPE",
    oem_time="2026-05-13T17:23:41Z",
):
    return {
        "@odata.id": "/redfish/v1",
        "Id": "RootService",
        "Name": service_name,
        "Product": product,
        "Vendor": vendor,
        "RedfishVersion": redfish_version,
        "UUID": uuid,
        "Managers": {"@odata.id": managers_path},
        "Systems": {"@odata.id": "/redfish/v1/Systems"},
        "Oem": {"Hpe": {"Manager": [manager], "Time": oem_time}},
    }


def hpe_manager(
    hostname,
    fqdn,
    manager_type,
    firmware,
    manager_health="OK",
    external_manager=None,
):
    return {
        "HostName": hostname,
        "FQDN": fqdn,
        "ManagerType": manager_type,
        "ManagerFirmwareVersion": firmware,
        "ExternalManager": external_manager,
        "DefaultLanguage": "en",
        "Status": {"Health": manager_health},
        "Languages": [{"Language": "en", "TranslationName": "English", "Version": "2.99"}],
    }


# iLO 5 on a Gen10 blade: the common, fully populated case.
ILO5_XML = rimp(
    hsi_block=hsi(
        serial="MXQ1000001A",
        product_name="Synergy 480 Gen10",
        uuid="871940MXQ1000001A",
        product_id="871940-B21",
        nics=[
            nic(1, "iLO 5", "aa:bb:cc:00:00:01", "10.0.0.11", "OK"),
            nic(2, "Synergy 3820C 10/20Gb CNA", "aa:bb:cc:00:00:02", "Unknown", "Unknown"),
            nic(3, "Synergy 3820C 10/20Gb CNA", "aa:bb:cc:00:00:03", "N/A", "Link Down"),
        ],
    ),
    mp_block=mp("Integrated Lights-Out 5 (iLO 5)", "2.99", "ILOMXQ1000001A", "1"),
    health_block=health("2"),
)

# iLO 4 on a Gen9 blade: legacy service naming, trailing-slash Managers link, no
# Product/Vendor and no Oem manager block, so most OEM columns go <missing>.
ILO4_XML = rimp(
    hsi_block=hsi(
        serial="CN1000002B",
        product_name="Synergy 480 Gen9",
        uuid="754683CN1000002B",
        product_id="754683-001",
        nics=[
            nic(1, "iLO 4", "aa:bb:cc:00:01:01", "10.0.0.12", "OK"),
            nic(2, "Synergy 3820C 10/20Gb CNA", "aa:bb:cc:00:01:02", "Unknown", "OK"),
            nic(3, "Synergy 3820C 10/20Gb CNA", "aa:bb:cc:00:01:03", "Unknown", "Unknown"),
        ],
    ),
    mp_block=mp("Integrated Lights-Out 4 (iLO 4)", "2.78", "ILOCN1000002B", "1"),
    health_block=health("3"),
)

ILO4_REDFISH = {
    "@odata.id": "/redfish/v1/",
    "Name": "HP RESTful Root Service",
    "RedfishVersion": "1.0.0",
    "UUID": "a489f357-dd5b-5371-afc7-9388cddedb6f",
    "Managers": {"@odata.id": "/redfish/v1/Managers/"},
    "Systems": {"@odata.id": "/redfish/v1/Systems/"},
}

# iLO 6: newer Redfish version, Warning health, Compute Ops Management, and a
# vendor/service name that is not HPE.
ILO6_XML = rimp(
    hsi_block=hsi(
        serial="3M1000003C",
        product_name="Express5800/R110k-1M",
        uuid="P527663M1000003C",
        product_id="P52766-B21",
        nics=[
            nic(1, "iLO 6", "aa:bb:cc:00:02:01", "10.0.0.13", "OK"),
            nic(2, "10Gb 2-port SFP+ BCM57412 OCP3 Adapter", "aa:bb:cc:00:02:02", "Unknown", "OK"),
            nic(3, "10Gb 2-port SFP+ BCM57412 OCP3 Adapter", "aa:bb:cc:00:02:03", "Unknown", "Unknown"),
            nic(4, "BCM 5720 1GbE 2p BASE-T LOM Adptr - NIC", "aa:bb:cc:00:02:04", "N/A", "OK"),
        ],
    ),
    mp_block=mp("Integrated Lights-Out 6 (iLO 6)", "1.73", "ILO3M1000003C", "1"),
    health_block=health("2"),
)

# iLO 7: no iLO 4/5/6 NIC description, so ILOManagementIP resolves to <missing>
# while AllAssignedNICIPs still reports the address.
ILO7_XML = rimp(
    hsi_block=hsi(
        serial="2M1000004D",
        product_name="HPE ProLiant Compute DL380 Gen12",
        uuid="P732822M1000004D",
        product_id="P73282-B21",
        nics=[
            nic(1, "iLO 7", "aa:bb:cc:00:03:01", "10.0.0.14", "OK"),
            nic(2, "BCM 5719 1Gb 4p BASE-T OCP Adptr", "aa:bb:cc:00:03:02", "Unknown", "Unknown"),
            nic(3, "Mellanox Network Adapter - AA:BB:CC:00:03:03", "aa:bb:cc:00:03:03", "Unknown", "Unknown"),
            nic(4, "Network Controller", "aa:bb:cc:00:03:04", "Unknown", "Unknown"),
        ],
    ),
    mp_block=mp("Integrated Lights-Out 7 (iLO 7)", "1.20.00", "ILO2M1000004D", "1"),
    health_block=health("2"),
)

# c7000 Onboard Administrator: MP block only, so every HSI/NICS/HEALTH field is
# <missing> and there is no Redfish service at all.
ONBOARD_ADMIN_XML = rimp(
    mp_block=mp("BladeSystem c7000 DDR2 Onboard Administrator with KVM", "4.96", "OB25BP0005E", "1")
)

# Non-HPE BMC: Redfish only, minimal root, no UUID and no Oem block.
IDRAC_REDFISH = {
    "@odata.id": "/redfish/v1",
    "Name": "Root Service",
    "Product": "Integrated Dell Remote Access Controller",
    "Vendor": "Dell",
    "RedfishVersion": "1.20.1",
    "Managers": {"@odata.id": "/redfish/v1/Managers"},
}

UNAUTHORIZED_BODY = {
    "error": {
        "code": "Base.1.0.GeneralError",
        "message": "A general error has occurred. See ExtendedInfo for more information.",
    }
}

MALFORMED_XML = '<?xml version="1.0"?>\n<RIMP>\n<HSI><SBSN>MXQ1000005E</SBSN>\n<MP><PN>Integrated'

PROFILES = {
    "ilo5": {
        "description": "Gen10 iLO 5: full XML plus HPE Redfish root with Oem manager block",
        "xml": ILO5_XML,
        "redfish": hpe_root(
            product="Synergy 480 Gen10",
            redfish_version="1.6.0",
            uuid="1612e489-ee9f-537c-b4e1-3e8c834c7ab6",
            manager=hpe_manager(
                hostname="ILOMXQ1000001A",
                fqdn="ilomxq1000001a.mock.invalid",
                manager_type="iLO 5",
                firmware="2.99",
                external_manager="HPE OneView",
            ),
        ),
    },
    "ilo4": {
        "description": "Gen9 iLO 4: legacy HP service name, trailing-slash Managers, no Oem block",
        "xml": ILO4_XML,
        "redfish": ILO4_REDFISH,
    },
    "ilo6": {
        "description": "iLO 6: Redfish 1.20.0, Warning health, Compute Ops Management",
        "xml": ILO6_XML,
        "redfish": hpe_root(
            product="Express5800/R110k-1M",
            redfish_version="1.20.0",
            uuid="393f59b5-e022-5a78-98a1-18a324e2593e",
            service_name="RESTful Root Service",
            vendor="NEC",
            oem_time="2026-05-13T17:23:24Z",
            manager=hpe_manager(
                hostname="MOCK-DL320G11-ilo",
                fqdn="mock-dl320g11-ilo.mock.invalid",
                manager_type="iLO 6",
                firmware="1.73",
                manager_health="Warning",
                external_manager="HPE Compute Ops Management",
            ),
        ),
    },
    "ilo7": {
        "description": "iLO 7: Redfish 1.22.1, and an iLO NIC description the XPaths do not cover",
        "xml": ILO7_XML,
        "redfish": hpe_root(
            product="HPE ProLiant Compute DL380 Gen12",
            redfish_version="1.22.1",
            uuid="e21f0ba2-b592-5113-b664-4efffd30e139",
            manager=hpe_manager(
                hostname="MOCK124",
                fqdn="mock124.mock.invalid",
                manager_type="iLO 7",
                firmware="1.20.00",
                external_manager="None",
            ),
        ),
    },
    "onboard-admin": {
        "description": "c7000 Onboard Administrator: MP-only XML, no Redfish service",
        "xml": ONBOARD_ADMIN_XML,
        "redfish": None,
    },
    "idrac": {
        "description": "Non-HPE BMC: no XML endpoint, minimal Redfish root without UUID or Oem",
        "xml": None,
        "redfish": IDRAC_REDFISH,
    },
    "redfish-unauthorized": {
        "description": "XML responds, Redfish returns HTTP 401 with a JSON error body",
        "xml": ILO5_XML,
        "redfish": UNAUTHORIZED_BODY,
        "redfish_status": 401,
    },
    "malformed-xml": {
        "description": "Truncated XML body with a working Redfish service",
        "xml": MALFORMED_XML,
        "redfish": IDRAC_REDFISH,
    },
    "dead-host": {
        "description": "Listening host that answers 404 for every path",
        "xml": None,
        "redfish": None,
    },
}


class Handler(BaseHTTPRequestHandler):
    profile = PROFILES["ilo5"]
    profile_name = "ilo5"

    def log_message(self, *args):
        pass

    def do_GET(self):
        # Lets a test harness confirm it is talking to the profile it started.
        if self.path.rstrip("/") == "/mock/profile":
            self.respond(200, self.profile_name.encode("utf-8"), "text/plain")
            return

        if self.path.startswith("/xmldata"):
            xml_body = self.profile.get("xml")
            if xml_body is None:
                self.respond(404, b"", "text/plain")
            else:
                self.respond(200, xml_body.encode("utf-8"), "text/xml")
            return

        if self.path.rstrip("/") == "/redfish/v1":
            payload = self.profile.get("redfish")
            if payload is None:
                self.respond(404, b"", "text/plain")
            else:
                status = self.profile.get("redfish_status", 200)
                self.respond(status, json.dumps(payload).encode("utf-8"), "application/json")
            return

        self.respond(404, b"", "text/plain")

    def respond(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


class MockServer(HTTPServer):
    # HTTPServer defaults this to 1, which on Windows lets a second instance bind
    # over a live listener and silently serve the wrong profile.
    allow_reuse_address = False


def main():
    parser = argparse.ArgumentParser(description="Mock iLO/Redfish responder for parity testing.")
    parser.add_argument("--profile", default="ilo5", choices=sorted(PROFILES))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--list", action="store_true", help="List available profiles and exit.")
    args = parser.parse_args()

    if args.list:
        for name in sorted(PROFILES):
            print(f"{name}: {PROFILES[name]['description']}")
        return 0

    Handler.profile = PROFILES[args.profile]
    Handler.profile_name = args.profile
    MockServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
