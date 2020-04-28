import logging
import json
import hashlib
import hmac
import httplib
import email
import time
import netaddr
import netaddr.core
import re

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)

DOMAIN_RE = re.compile('^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$')
SHA256_RE = re.compile('[A-Fa-f0-9]{64}')


class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.public_key = self.config.get('public_key', None)
        if self.public_key is None:
            raise ValueError('%s - Public key is required' % self.name)

        self.private_key = self.config.get('private_key', None)
        if self.private_key is None:
            raise ValueError('%s - Private key is required' % self.name)

        self.numdays = self.config.get('numdays', None)
        if self.numdays is None:
            raise ValueError('%s - Number of days is required' % self.name)

        self.url = 'api.isightpartners.com'
        self.indicators = 'ip,url,domain,sha256,md5'


    def _build_iterator(self, item):
        start = int(time.time()) - (86400 * self.numdays)
        end = int(time.time())
        search_query = '/view/iocs?startDate=' + str(start) + '&endDate=' + str(end) + '&indicatorTypes=' + self.indicators
        accept_version = '2.2'
        accept_header = 'application/json'
        time_stamp = email.Utils.formatdate(localtime=True)
        hash_data = search_query + accept_version + accept_header + time_stamp
        hashed = hmac.new(self.private_key, hash_data, hashlib.sha256)
        headers = {
            'Accept': accept_header,
            'Accept-Version': accept_version,
            'X-Auth': self.public_key,
            'X-Auth-Hash': hashed.hexdigest(),
            'Date': time_stamp,
        }
        conn = httplib.HTTPSConnection(self.url)
        conn.request('GET', search_query, '', headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        indicators = self.indicators.split(',')
        iocs = []
        for indicator in indicators:
            for message in data['message']:
                if message[indicator]:
                    iocs.append(message[indicator])
        return iocs
    
    
    def _process_item(self, item):
        indicator = item

        result = {}
        result['type'] = self._type_of_indicator(indicator)
        return [[indicator, result]]

    def _check_for_ip(self, indicator):
        if '-' in indicator:
            # check for address range
            a1, a2 = indicator.split('-', 1)

            try:
                a1 = netaddr.IPAddress(a1)
                a2 = netaddr.IPAddress(a2)

                if a1.version == a2.version:
                    if a1.version == 6:
                        return 'IPv6'
                    if a1.version == 4:
                        return 'IPv4'

            except:
                return None

            return None

        if '/' in indicator:
            # check for network
            try:
                ip = netaddr.IPNetwork(indicator)

            except:
                return None

            if ip.version == 4:
                return 'IPv4'
            if ip.version == 6:
                return 'IPv6'

            return None

        try:
            ip = netaddr.IPAddress(indicator)
        except:
            return None

        if ip.version == 4:
            return 'IPv4'
        if ip.version == 6:
            return 'IPv6'

        return None

    def _type_of_indicator(self, indicator):
        ipversion = self._check_for_ip(indicator)
        if ipversion is not None:
            return ipversion

        if DOMAIN_RE.match(indicator):
            return 'domain'
        
        if SHA256_RE.match(indicator):
            return 'sha256'
                
        return 'URL'
