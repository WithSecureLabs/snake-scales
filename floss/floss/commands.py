import os
import subprocess

import shutil

from snake import config
from snake import error
from snake import scale


class Commands(scale.Commands):
    def check(self):
        self.floss_path = None
        if config.scale_configs['floss']['floss_path']:
            if os.path.exists(config.scale_configs['floss']['floss_path']):
                self.floss_path = config.scale_configs['floss']['floss_path']
        else:
            self.floss = shutil.which("floss")
        if not self.floss_path:
            raise error.CommandError("binary 'floss' not found")

        self.env = os.environ
        if 'HOME' not in self.env:
            if config.scale_configs['floss']['home']:
                self.env['HOME'] = config.scale_configs['floss']['home']
            else:
                raise error.CommandError("home directory is not set and is required by floss")

    @scale.command({
        'info': 'This function will return all strings found within the file passed'
    })
    def all_strings(self, args, file, opts):
        try:
            proc = subprocess.run([self.floss_path, file.file_path],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env=self.env)
        except TimeoutError:
            raise error.CommandWarning("timeout when running floss")

        if proc.stderr:
            raise error.CommandWarning("an error occurred with the floss module:\n%s" % proc.stderr.decode('utf-8'))

        if proc.stdout == '':
            raise error.CommandWarning("floss all strings returned no output")

        return {'all_strings': proc.stdout.decode('utf-8')}

    def all_strings_plaintext(self, json):
        return json['all_strings']

    @scale.command({
        'info': 'This function will return floss decoded strings found within the file passed'
    })
    def decoded_strings(self, args, file, opts):
        try:
            proc = subprocess.run([self.floss_path, file.file_path, '--no-static-strings', '--no-stack-strings'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env=self.env)
        except TimeoutError:
            raise error.CommandWarning("timeout when running floss")

        if proc.stderr:
            raise error.CommandWarning("an error occurred with the floss module:\n%s" % proc.stderr.decode('utf-8'))

        if proc.stdout == '':
            raise error.CommandWarning("floss decoded strings returned no output")

        return {'decoded_strings': proc.stdout.decode('utf-8')}

    def decoded_strings_plaintext(self, json):
        return json['decoded_strings']

    @scale.command({
        'info': 'This function will return floss stack strings found within the file passed'
    })
    def stack_strings(self, args, file, opts):
        try:
            proc = subprocess.run([self.floss_path, file.file_path, '--no-static-strings', '--no-decoded-strings'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,
                                  env=self.env)
        except TimeoutError:
            raise error.CommandWarning("timeout when running floss")

        if proc.stderr:
            raise error.CommandWarning("an error occurred with the floss module:\n%s" % proc.stderr.decode('utf-8'))

        if proc.stdout == '':
            raise error.CommandWarning("floss stack strings returned no output")

        return {'stack_strings': proc.stdout.decode('utf-8')}

    def stack_strings_plaintext(self, json):
        return json['stack_strings']
