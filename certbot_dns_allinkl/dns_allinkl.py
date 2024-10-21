from zeep import Client
import json, logging
import xml.etree.ElementTree as ET
from certbot.plugins import dns_common
from datetime import datetime, timedelta
from time import sleep

# thanks to https://github.com/m42e/certbot-dns-ispconfig/tree/master

logger = logging.getLogger(__name__)

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for AllInkl

    This Authenticator uses the AllInkl SOAP API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using AllInkl for DNS)."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        logger.debug("Init Authenticator")

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="AllInkl credentials INI file.")

    def more_info(self):
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the AllInkl SOAP API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "AllInkl credentials INI file",
            {
                "username": "Username for AllInkl Remote API.",
                "password": "Password for AllInkl Remote API.",
            },
        )
        logger.debug("Set up credentials")

    def _perform(self, domain, validation_name, validation):
        logger.debug("Exec perform")
        self._get_allinkl_client(domain).add_txt_record(
            validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        logger.debug("Exec cleanup")
        self._get_allinkl_client(domain).del_txt_record(
            validation_name, validation
        )

    def _get_allinkl_client(self, domain):
        return _AllInklConfigClient(
            self.credentials.conf("username"),
            self.credentials.conf("password"),
            domain
        )

class _AllInklConfigClient:

    def __init__(self, user, password, domain):
        self._user = user
        self._password = password
        self._domain = domain
        self._provided_domain = domain
        if self._domain[-1] != ".":
            self._domain += "."
        logger.debug(f"Set up All-Inkl client with {user=} and domain={self._domain}")
        self._client = Client("https://kasapi.kasserver.com/soap/wsdl/KasApi.wsdl")
        self._flood_protect_last = datetime.now()

    def add_txt_record(self, name, value):
        if name.endswith("." + self._provided_domain):
            name = name[:-(len(self._provided_domain)+1)]
        params = {
            "kas_login": self._user,
            "kas_auth_type": "plain",
            "kas_auth_data": self._password,
            "kas_action": "add_dns_settings",
            "KasRequestParams": {
                "record_name": name,
                "record_type": "TXT",
                "record_data": value,
                "record_aux": 0,
                "zone_host": self._domain
            }
        }
        try:
            with self._client.settings(strict=False, xsd_ignore_sequence_order=False):
                while datetime.now() < (self._flood_protect_last + timedelta(seconds=5)): sleep(0.5)
                self._flood_protect_last = datetime.now()
                result = self._client.service.KasApi(json.dumps(params))
                logger.info(f"Created dns entry {name} with value {value}")
        except Exception as e:
            logger.exception(f"Failed to create record: {repr(e)}", exc_info=True)
        

    def _parse_dns_list(self, xmldata):
        # [(id, type, name, data)]
        entries = []
        doc = ET.fromstring(xmldata)
        for item in doc.findall(".//item[key='ReturnInfo']/value/item"):
            record_id = item.find("./item[key='record_id']/value").text
            record_type = item.find("./item[key='record_type']/value").text
            record_name = item.find("./item[key='record_name']/value").text or ""
            record_value = item.find("./item[key='record_data']/value").text or ""
            entries.append((record_id, record_type, record_name, record_value))
        return entries

    def find_record(self, record_type, name, value):
        if name.endswith("." + self._provided_domain):
            name = name[:-(len(self._provided_domain)+1)]
        params = {
            "kas_login": self._user,
            "kas_auth_type": "plain",
            "kas_auth_data": self._password,
            "kas_action": "get_dns_settings",
            "KasRequestParams": {
                "zone_host": self._domain
            }
        }
        try:
            with self._client.settings(raw_response=True): 
                while datetime.now() < (self._flood_protect_last + timedelta(seconds=5)): sleep(0.5)
                self._flood_protect_last = datetime.now()
                result = self._client.service.KasApi(json.dumps(params))
                content = result.content.decode()
                if not result.ok:
                    raise Exception(content)
                dns_entries = self._parse_dns_list(content)
                for _id, _type, _name, _data in dns_entries:
                    if _type == record_type and _name == name and _data == value:
                         return _id
        except Exception as e:
            logger.exception(f"Failed to retrieve records: {repr(e)}", exc_info=True)
        return None

    def del_txt_record(self, name, value):
        if name.endswith("." + self._provided_domain):
            name = name[:-(len(self._provided_domain)+1)]
        record_id = self.find_record("TXT", name, value)
        if record_id is None:
            logger.warning(f"Entry named {name} with value {value} not found")
            return False
        
        params = {
            "kas_login": self._user,
            "kas_auth_type": "plain",
            "kas_auth_data": self._password,
            "kas_action": "delete_dns_settings",
            "KasRequestParams": {
                "record_id": record_id
            }
        }

        try:
            with self._client.settings(strict=False, xsd_ignore_sequence_order=False):
                while datetime.now() < (self._flood_protect_last + timedelta(seconds=5)): sleep(0.5)
                self._flood_protect_last = datetime.now()
                self._client.service.KasApi(json.dumps(params))
                logger.info(f"Deleted entry {name} with value {value}")
                return True
        except Exception as e:
            logger.exception(f"Failed to delete record: {repr(e)}", exc_info=True)

        return False
        