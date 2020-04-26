import logging
import json
import hashlib
import hmac
import httplib
import email
import time

from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)


class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)
        self.public_key = self.config.get('public_key', None)
        if self.public_key is None:
            raise ValueError('%s - Public Key is required' % self.name)
        self.private_key = self.config.get('private_key', None)
        if self.private_key is None:
            raise ValueError('%s - Private Key is required' % self.name)
        self.numdays = self.config.get('numdays', None)
        if self.numdays is None:
            raise ValueError('%s - # of Days is required' % self.name)
        self.url = 'https://api.isightpartners.com'

    def _build_iterator(self, item):
        start = int(time.time()) - (86400 * self.numdays)
        end = int(time.time())
        indicators = 'ip,sha256,url,domain'
        search_query = '/view/iocs?startDate=' + str(start) + '&endDate=' + str(end) + '&indicatorTypes=' + indicators
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
        conn = httplib.HTTPSConnection('api.isightpartners.com')
        conn.request('GET', search_query, '', headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return data
        
    def _process_item(self, item):
        indicators = 'ip,sha256,url,domain'
        indicators = indicators.split(',')
        # iocs = []
        for indicator in indicators:
            for message in item['message']:
                if message[indicator]:
                    if indicator == 'ip':
                        value = {'type': 'IPv4', 'confidence': 100}
                    else:
                        value = {'type': indicator, 'confidence': 100}
                    #iocs.append([str(message[indicator]), value])
                    return [[indicator, value]]
