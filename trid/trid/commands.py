from os import path
import shutil
import subprocess

from snake import config
from snake import error
from snake import scale


class Commands(scale.Commands):
    def check(self):
        self.trid_path = None
        if config.scale_configs['trid']['trid_path']:
            if path.exists(config.scale_configs['trid']['trid_path']):
                self.trid_path = config.scale_configs['trid']['trid_path']
        else:
            self.trid_path = shutil.which("trid")
        if not self.trid_path:
            raise error.CommandError("binary 'trid' not found")

        # TODO: Call tridupdate.py to update defs
        # self.tridupdate_path = None
        # if config.scale_configs['trid']['tridupdate_path']:
        #     if path.exists(config.scale_configs['trid']['tridupdate_path']):
        #         self.tridupdate_path = config.scale_configs['trid']['tridupdate_path']
        # if not self.tridupdate_path:
        #     raise error.CommandError("file 'tridupdate.py' not found")

        self.triddefs_path = None
        if config.scale_configs['trid']['triddefs_path']:
            if path.exists(config.scale_configs['trid']['triddefs_path']):
                self.triddefs_path = config.scale_configs['trid']['triddefs_path']
        if not self.triddefs_path:
            raise error.CommandError("file 'triddefs.trd' not found")

    @scale.command({
        'info': 'return the trid output of the file passed'
    })
    def trid(self, args, file, opts):
        try:
            return {'trid': str(subprocess.check_output([self.trid_path, file.file_path, '-d:{}'.format(self.triddefs_path)]), encoding="utf-8").lstrip('\r\n')}
        except Exception:
            raise error.CommandWarning("an error occurred with the trid module")

    def trid_plaintext(self, json):
        return json['trid']
