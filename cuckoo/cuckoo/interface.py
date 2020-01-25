import requests

from snake import config
from snake import db
from snake import fields
from snake import error
from snake import scale
from snake.utils import markdown as md


# pylint: disable=invalid-name


CUCKOO_API = config.scale_configs['cuckoo']['cuckoo_api']
VERIFY = config.scale_configs['cuckoo']['verify']


class Interface(scale.Interface):
    def check(self):
        if CUCKOO_API is None or CUCKOO_API == '':
            raise error.InterfaceError("config variable 'cuckoo_api' has not been set")

    @scale.pull({
        'info': 'summary of scores for the sample'
    })
    def info(self, args, file, opts):
        try:
            j = requests.get(CUCKOO_API + '/files/view/sha256/' + file.sha256_digest, verify=VERIFY).json()
        except requests.exceptions.RequestException:
            raise error.InterfaceError("failed to connect to Cuckoo")

        if 'sample' not in j:
            raise error.InterfaceWarning("file has never been submitted to Cuckoo")
        s_id = j['sample']['id']
        r = requests.get(CUCKOO_API + '/tasks/list', verify=VERIFY)
        if not r.status_code == requests.codes.ok:  # pylint: disable=no-member
            return "No reports, sample must be pending/running", "pending"
        j = r.json()
        output = []
        for t in j['tasks']:
            if t['sample_id'] == s_id:
                r = requests.get(CUCKOO_API + '/tasks/report/' + str(t['id']), verify=VERIFY)
                if r.status_code == requests.codes.ok:  # pylint: disable=no-member
                    j = r.json()
                    name = j['info']['machine']['name'] if 'name' in j['info']['machine'] else 'unknown'
                    output += [{
                        'score': j['info']['score'],
                        'name': j['info']['machine']['name']
                    }]
        if not output:
            return error.InterfaceWarning("no information available!")
        return {'info': output}

    def info_markdown(self, json):
        output = md.table_header(('Machine', 'Score'))
        for j in json['info']:
            score = j['score']
            if score > 5:
                s = str(score)
            elif score > 3:
                s = str(score)
            else:
                s = str(score)
            output += md.table_row((j['name'], s))
        return output

    @scale.pull({
        'args': {
            'id': fields.Str(required=True)
        },
        'info': 'view report summary'
    })
    def report(self, args, file, opts):
        # TODO: Hash match!
        try:
            r = requests.get(CUCKOO_API + '/tasks/report/' + args['id'], verify=VERIFY)
        except requests.exceptions.RequestException:
            raise error.InterfaceError("failed to connect to Cuckoo")
        if not r.status_code == requests.codes.ok:  # pylint: disable=no-member
            return "No task for given id"
        j = r.json()
        output = {
            'score': j['info']['score'],
            'platform': j['info']['platform'],
            'analysis': {
                'category': j['info']['category'],
                'started': j['info']['started'],
                'ended': j['info']['ended'],
                'duration': j['info']['duration']
            },
            'machine': {
                'name': j['info']['machine']['name'],
                'manager': j['info']['machine']['manager']
            },
            'signatures': [
                {'severity': x['severity'], 'description': x['description']} for x in j['signatures']
            ]
        }
        return output

    def report_markdown(self, json):
        output = md.h4('General')
        output += md.paragraph(md.bold('Score: ') + str(json['score']))
        output += md.cr()
        output += md.paragraph(md.bold('Platform: ') + json['platform'])
        output += md.h4('Analysis')
        output += md.table_header(('Category', 'Started', 'Ended', 'Duration'))
        output += md.table_row((json['analysis']['category'],
                                str(json['analysis']['started']),
                                str(json['analysis']['ended']),
                                str(json['analysis']['duration'])))
        output += md.h4('Machines')
        output += md.table_header(('Name', 'Manager'))
        output += md.table_row((json['machine']['name'], json['machine']['manager']))
        output += md.h4('Signatures')
        output += md.table_header(('Severity', 'Description'))
        for s in json['signatures']:
            output += md.table_row((str(s['severity']), s['description']))
        return output

    @scale.pull({
        'info': 'view reports for sample'
    })
    def reports(self, args, file, opts):
        try:
            j = requests.get(CUCKOO_API + '/files/view/sha256/' + file.sha256_digest, verify=VERIFY).json()
        except requests.exceptions.RequestException:
            raise error.InterfaceError("failed to connect to Cuckoo")

        if 'sample' not in j:
            raise error.InterfaceWarning("file has never been submitted to Cuckoo")
        s_id = j['sample']['id']
        r = requests.get(CUCKOO_API + '/tasks/list', verify=VERIFY)
        if not r.status_code == requests.codes.ok:  # pylint: disable=no-member
            return "No reports, sample must be pending/running", "pending"
        j = r.json()
        output = {'reports': []}
        for t in j['tasks']:
            if t['sample_id'] == s_id:
                output['reports'] += [{
                    'id': str(t['id']),
                    'url': config.scale_configs['cuckoo']['cuckoo_url'] + str(t['id']),
                    'timestamp': str(t['added_on']),
                    'status': str(t['status'])
                }]
        return output

    def reports_markdown(self, json):
        output = md.table_header(('ID', 'URL', 'Timestamp', 'Status'))
        for r in json['reports']:
            output += md.table_row((r['id'], r['url'], r['timestamp'], r['status']))
        return output

    @scale.push({
        'args': {
            'machine': fields.Str(required=False),
            'priority': fields.Int(required=False),
            'timeout': fields.Int(required=False)
        },
        'info': 'submit sample to cuckoo'
    })
    def submit(self, args, file, opts):
        document = db.file_collection.select(file.sha256_digest)
        with open(file.file_path, "rb") as f:
            try:
                r = requests.post(CUCKOO_API + '/tasks/create/file', files={"file": (document['name'], f)}, verify=VERIFY)
            except requests.exceptions.RequestException:
                raise error.InterfaceError("failed to connect to Cuckoo")

        if not r.status_code == requests.codes.ok:  # pylint: disable=no-member
            raise error.InterfaceError('failed to submit sample to Cuckoo')

        j = r.json()

        if not j["task_id"]:
            raise error.InterfaceError('failed to submit sample to Cuckoo')

        return j
