import shutil
import subprocess

from snake import error
from snake import scale


class Commands(scale.Commands):
    def check(self):
        exiftool = shutil.which("exiftool")
        if not exiftool:
            raise error.CommandError("binary 'exiftool' not found")

    @scale.command({
        'info': 'parse exif data of the file passed'
    })
    def exiftool(self, args, file, opts):
        return {'exiftool': str(subprocess.check_output(['exiftool', file.file_path]), encoding='latin-1')}

    def exiftool_plaintext(self, json):
        return json['exiftool']
