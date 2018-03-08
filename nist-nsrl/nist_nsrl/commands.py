from os import path
import subprocess

from snake import config
from snake import db
from snake import error
from snake import scale
from snake.utils import markdown as md


NSRL_PATH = config.scale_configs['nist_nsrl']['nsrl_path']


class Commands(scale.Commands):
    def check(self):
        if not NSRL_PATH:
            raise error.CommandError('path to nsrl hashes file is not set')
        if not path.isfile(NSRL_PATH):
            raise error.CommandError('nsrl hashes file not found')

    @scale.command({
        'info': 'search the nsrl hashes'
    })
    def hash_search(self, args, file, opts):
        document = db.file_collection.select(file.sha256_digest)

        proc = subprocess.run(['grep', document['md5_digest'], NSRL_PATH], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "status 1" in str(proc.stderr):
            raise error.CommandWarning('file not found: ' + str(proc.stderr))
        elif "status 2" in str(proc.stderr):
            raise error.CommandWarning('nist-nsrl module return status 2 error: ' + str(proc.stderr))

        # Store the SHA1, MD5 and File Name hits in a list of tuples
        # We specifically drop the first and last char to remove quotes from the NIST DB file
        hits = []
        for line in str(proc.stdout, encoding='utf').splitlines():
            hits.append((str(line).split(',')[0][1:-1], str(line).split(',')[1][1:-1], str(line).split(',')[3][1:-1]))

        # Deduplicate the list
        deduphits = list(set(hits))

        output = []
        for line in deduphits:
            output += [{
                'sha1': str(line[0]),
                'md5': str(line[1]),
                'file': str(line[2])
            }]
        return {'hits': output}

    def hash_search_markdown(self, json):
        output = '**Hits: ' + str(len(json['hits'])) + '**\r\n\r\n'
        output += md.table_header(('SHA1', 'MD5', 'File Name'))
        for row in json['hits']:
            output += md.table_row((row['sha1'], row['md5'], row['file']))
        if not json:
            output += md.table_row(('-', '-', '-'))
        return output
