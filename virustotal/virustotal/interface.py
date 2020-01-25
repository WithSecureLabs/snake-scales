import requests

from snake import config
from snake import db
from snake import error
from snake import fields
from snake import scale
from snake.utils import markdown as md

# Global things
API_KEY = config.scale_configs['virustotal']['api_key']
IS_PRIVATE = bool(config.scale_configs['virustotal']['api_private'])

PROXIES = {}
if config.snake_config['http_proxy']:
    PROXIES['http'] = config.snake_config['http_proxy']
if config.snake_config['https_proxy']:
    PROXIES['https'] = config.snake_config['https_proxy']

HEADERS = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent": config.constants.USER_AGENT
}


# Interface things
class Interface(scale.Interface):
    def _vt_scan(self, sha256_digest, cache=True):
        params = {
            'apikey': API_KEY,
            'resource': sha256_digest,
            'allinfo': 1
        }

        document = db.file_collection.select(sha256_digest)
        if 'vt' not in document or not cache:
            try:
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                        params=params,
                                        headers=HEADERS,
                                        proxies=PROXIES,
                                        timeout=10)
            except Exception:
                raise error.InterfaceWarning("failed to connect to VirusTotal")
            if 'application/json' not in response.headers.get('content-type'):
                raise error.InterfaceWarning("invalid response received from VirusTotal")
            if 'response_code' not in response.json():
                raise error.InterfaceWarning("unknown response from VirusTotal")
            data = {'vt': response.json()}
            db.file_collection.update(sha256_digest, data)
            document = db.file_collection.select(sha256_digest)
            if not document or 'vt' not in document:
                raise error.MongoError('error adding vt into file document %s' % sha256_digest)
        if document['vt']["response_code"] is 0:
            raise error.InterfaceWarning("file is not present on VirusTotal")

        # Check if we had public key but now its private, if so warn that cache is out of date
        # NOTE: we just check for missing info variable
        if IS_PRIVATE and 'first_seen' not in document['vt']:
            raise error.InterfaceWarning("private key specified but no private api data in cache, please flush vt cache for sample")

        return document['vt']

    def check(self):
        if not API_KEY:
            raise error.InterfaceError("config variable 'api_key' has not been set")

    @scale.pull({
        'args': {
            'cache': fields.Bool(missing=True)
        },
        'info': 'virustotal results report'
    })
    def results(self, args, file, opts):
        j = self._vt_scan(file.sha256_digest, cache=args['cache'])
        return j['scans']

    def results_markdown(self, json):
        scanresults = sorted(json)
        score = 0
        count = 0
        output = 'AV Vendor | Result\r\n'
        output += ':--- | :---\r\n'
        cleanoutput = ''
        for vendor in scanresults:
            count += 1
            if str(json[vendor]['detected']) == "True":
                score += 1
                output += vendor + ' | '
                output += str(json[vendor]['result']).replace('%', r'\%')
                output += ' | \r\n'
            else:
                cleanoutput += vendor + ' | '
                cleanoutput += 'Clean'
                cleanoutput += ' | \r\n'

        if score < 3:
            output = '**Score: ' + str(score) + '/' + str(count) + '**\r\n\r\n' + output
        else:
            output = '**Score: ' + str(score) + '/' + str(count) + '**\r\n\r\n' + output

        output = output + cleanoutput

        return output

    # TODO: Do It!
    # @scale.push({
    #     'info': 'submit file to virustotal'
    # })
    # def submit(self, args, file, opts):
    #     # TODO: Implement
    #     pass

    if IS_PRIVATE:
        @scale.pull({
            'args': {
                'cache': fields.Bool(missing=True)
            },
            'info': 'VirusTotal general info report'
        })
        def info(self, args, file, opts):
            j = self._vt_scan(file.sha256_digest, cache=args['cache'])
            score = 0
            for _, v in j['scans'].items():
                if v['detected'] is True:
                    score += 1
            output = {
                'vt_link': j['permalink'],
                'first_seen': j['first_seen'],
                'last_seen': j['last_seen'],
                'score': "%i/%i" % (score, len(j['scans'])),
                'times_submitted': j['times_submitted'],
                'type': j['type']
            }
            return output

        def info_markdown(self, json):
            output = md.table_header(('Attribute', 'Value'))
            output += md.table_row(('VT Link', json['vt_link']))
            output += md.table_row(('First Seen', json['first_seen']))
            output += md.table_row(('Last Seen', json['last_seen']))
            if int(json['score'].split('/')[0]) < 3:
                output += md.table_row(('Score', json['score']))
            else:
                output += md.table_row(('Score', json['score']))
            output += md.table_row(('Times Submitted', str(json['times_submitted'])))
            output += md.table_row(('Type', json['type']))
            return output

        @scale.pull({
            'args': {
                'cache': fields.Bool(missing=True)
            },
            'info': 'VirtualTotal submission names'
        })
        def names(self, args, file, opts):
            j = self._vt_scan(file.sha256_digest, cache=args['cache'])
            return j['submission_names']

        def names_markdown(self, json):
            output = '| Submission Names |\r\n'
            output += '| :------ |\r\n'
            for name in json:
                output += '| ' + name + ' |' + '\r\n'

            return output

        @scale.pull({
            'args': {
                'cache': fields.Bool(missing=True)
            },
            'info': 'VirusTotal associates URLs'
        })
        def urls(self, args, file, opts):
            j = self._vt_scan(file.sha256_digest, cache=args['cache'])
            return j['ITW_urls']

        def urls_markdown(self, json):
            output = '| Associated URLs |\r\n'
            output += '| :------ |\r\n'
            for url in json:
                # TODO: Determine some kind of URL sanitiser for use here
                output += '| ' + url.replace('http', 'hxxp') + ' |' + '\r\n'

            return output

        @scale.pull({
            'args': {
                'cache': fields.Bool(missing=True)
            },
            'info': 'VirtualTotal submission names'
        })
        def parents(self, args, file, opts):
            j = self._vt_scan(file.sha256_digest, cache=args['cache'])
            if 'compressed_parents' in j['additional_info']:
                return j['additional_info']['compressed_parents']
            return []

        def parents_markdown(self, json):
            output = '| Compressed Parents |\r\n'
            output += '| :------ |\r\n'
            for name in json:
                output += '| [' + name + '](https://www.virustotal.com/#/file/' + name + '/analysis) |' + '\r\n'
            if not json:
                output += md.table_row(('-'))
            return output
    else:
        @scale.pull({
            'args': {
                'cache': fields.Bool(missing=True)
            },
            'info': 'VirusTotal general info report'
        })
        def info(self, args, file, opts):
            j = self._vt_scan(file.sha256_digest, cache=args['cache'])
            score = 0
            for _, v in j['scans'].items():
                if v['detected'] is True:
                    score += 1
            output = {
                'vt_link': j['permalink'],
                'score': "%i/%i" % (score, len(j['scans'])),
            }
            return output

        def info_markdown(self, json):
            output = md.table_header(('Attribute', 'Value'))
            output += md.table_row(('VT Link', json['vt_link']))
            if int(json['score'].split('/')[0]) < 3:
                output += md.table_row(('Score', json['score']))
            else:
                output += md.table_row(('Score', json['score']))
            return output
