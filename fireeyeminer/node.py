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
        
        self.public_key = None
        self.private = None
        self.numdays = None
        
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)
        self.url = 'api.isightpartners.com'
        self.indicators = 'ip,sha256,url,domain'
        
        self.side_config_path = self.config.get('side_config', None)
        if self.side_config_path is None:
            self.side_config_path = os.path.join(
                os.environ['MM_CONFIG_DIR'],
                '%s_side_config.yml' % self.name
            )        
        
        self._load_side_config()
        
        
    def _load_side_config(self):
        try:
            with open(self.side_config_path, 'r') as f:
                sconfig = yaml.safe_load(f)

        except Exception as e:
            LOG.error('%s - Error loading side config: %s', self.name, str(e))
            return

        self.public_key = sconfig.get('public_key', None)
        if self.public_key is not None:
            LOG.info('%s - Public key set', self.name)

        self.private_key = sconfig.get('private_key', None)
        if self.private_key is not None:
            LOG.info('%s - Private key set', self.name)
        
        self.numdays = sconfig.get('numdays', None)
        if self.numdays is not None:
            LOG.info('%s - number of day set', self.name)            
         

   def _process_item(self, item):
        indicators = 'ip,sha256,url,domain'
        indicators = indicators.split(',')
        iocs = {}
        for indicator in indicators:
            for message in item['message']:
                if message[indicator]:
                    if indicator in iocs:
                        iocs[indicator].append(message[indicator])
                    else:
                        iocs[indicator] = [message[indicator]]
        for ioc in iocs:
            if ioc == 'ip':
                value = {'type': 'IPv4', 'confidence': 100}
            else:
                value = {'type': ioc, 'confidence': 100}
            return [[iocs[ioc], value]]
        
        
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
    
