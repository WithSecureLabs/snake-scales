import shutil
import subprocess

from snake import error
from snake import scale


class Commands(scale.Commands):
    def check(self):
        binwalk = shutil.which("binwalk")
        if not binwalk:
            raise error.CommandError("binary 'binwalk' not found")

    @scale.command({
        'info': "parse the file with binwalk the scrape contents"
    })
    def binwalk(self, args, file, opts):
        return {'binwalk': str(subprocess.check_output(['binwalk', file.file_path]), encoding='utf-8')}

    def binwalk_plaintext(self, json):
        return json['binwalk']
