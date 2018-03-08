import pyclamd

from snake import error
from snake import scale


class Commands(scale.Commands):
    def check(self):
        # Check the Clam Daemon is alive and well
        try:
            clamd = pyclamd.ClamdAgnostic()
            if not clamd.ping():
                raise error.CommandError('clamav daemon not running')
        except Exception:
            raise error.CommandError('clamav daemon not running')

    @scale.command({
        'info': 'scan a file with clamav'
    })
    def scan(self, args, file, opts):
        try:
            clamd = pyclamd.ClamdAgnostic()
            res = clamd.scan_file(file.file_path)
        except Exception:
            raise error.CommandWarning('scanning file with clamav failed. check apparmor permissions?')

        if res is None:
            return {'hits': 'no hits with clamav'}
        elif res[file.file_path][0] == 'FOUND':
            return {'hits': str(res[file.file_path][1])}
        else:
            raise error.CommandWarning('unknown error occurred scanning file with clamav failed.')

    def scan_plaintext(self, json):
        return json['hits']
