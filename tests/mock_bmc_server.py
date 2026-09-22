import json
from http.server import BaseHTTPRequestHandler, HTTPServer

# Minimal stand-in for an iLO/Redfish BMC so the Python and Go CLIs can be
# compared against real HTTP responses instead of connection failures.

XML_BODY = """<?xml version="1.0"?>
<RIMP>
<HSI>
<SBSN>  ABC12345  </SBSN>
<SPN>ProLiant DL380 Gen10</SPN>
<UUID>0123456789ABC</UUID>
<PRODUCTID>868703-B21</PRODUCTID>
<NICS>
<NIC><PORT>1</PORT><DESCRIPTION>iLO 5</DESCRIPTION><MACADDR>aa:bb:cc:dd:ee:01</MACADDR><IPADDR>10.152.161.101</IPADDR><STATUS>OK</STATUS></NIC>
<NIC><PORT>2</PORT><DESCRIPTION>iLO 6</DESCRIPTION><MACADDR>aa:bb:cc:dd:ee:02</MACADDR><IPADDR>Unknown</IPADDR><STATUS>Unknown</STATUS></NIC>
</NICS>
</HSI>
<MP><PN>Integrated Lights-Out 5</PN><FWRI>2.44</FWRI><SN>ILOABC12345</SN><ST>1</ST></MP>
<HEALTH><STATUS>2</STATUS></HEALTH>
</RIMP>
"""

REDFISH_BODY = {
    "Name": "HPE RESTful Root Service",
    "Product": "ProLiant DL380 Gen10",
    "Vendor": "HPE",
    "RedfishVersion": "1.6.0",
    "UUID": "d1b1a2c3-0000-1111-2222-333344445555",
    "Managers": {"@odata.id": "/redfish/v1/Managers"},
    "Oem": {
        "Hpe": {
            "Manager": [
                {
                    "HostName": "ilo-node-1",
                    "FQDN": "ilo-node-1.example.com",
                    "ManagerType": "iLO 5",
                    "ManagerFirmwareVersion": "2.44",
                    "ExternalManager": None,
                    "Status": {"Health": "OK"},
                }
            ],
            "Time": "2026-09-22T12:00:00Z",
        }
    },
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/xmldata"):
            body = XML_BODY.encode("utf-8")
            content_type = "text/xml"
        elif self.path.rstrip("/") == "/redfish/v1":
            body = json.dumps(REDFISH_BODY).encode("utf-8")
            content_type = "application/json"
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 80), Handler).serve_forever()
