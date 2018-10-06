from os import path
import shutil
import subprocess
import tempfile

import r2pipe
import requests

from snake import config
from snake import error
from snake import fields
from snake import scale
from snake.utils import markdown as md

# Global things
PROXIES = {}
if config.snake_config['http_proxy']:
    PROXIES['http'] = config.snake_config['http_proxy']
if config.snake_config['https_proxy']:
    PROXIES['https'] = config.snake_config['https_proxy']


# NOTE: retdec-python does not have proxy support, hack it in...
def start_new_session(self):
    """Starts a new session to be used to send requests and returns it."""
    session = requests.Session()
    session.auth = (self._api_key, '')  # pylint: disable=protected-access
    session.headers['User-Agent'] = config.constants.USER_AGENT
    session.proxies = PROXIES
    return session


# Now import retdec cause we need to override some of it!
import retdec  # noqa pylint: disable=wrong-import-position
from retdec import conn  # noqa pylint: disable=unused-import, wrong-import-position
retdec.conn.APIConnection._start_new_session = start_new_session  # pylint: disable=protected-access
from retdec import decompiler  # noqa pylint: disable=wrong-import-position
from retdec import exceptions  # noqa pylint: disable=wrong-import-position


# Interface things
class Commands(scale.Commands):
    def _decompile(self, kwargs):
        # NOTE: Using kwargs is lazy but it just makes life easier!
        # Online
        if self.decomp:
            try:
                decompilation = self.decomp.start_decompilation(**kwargs)
                decompilation.wait_until_finished()
            except exceptions.RetdecError as err:
                raise error.CommandError("retdec-python error: {}".format(err))

            return decompilation.get_hll_code()
        # Local
        else:
            with tempfile.NamedTemporaryFile('rb') as fp:
                cmd = [path.join(self.retdec_dir, 'bin/retdec-decompiler.sh'), '-o', fp.name]
                if 'sel_decomp_funcs' in kwargs:
                    cmd += ['--select-functions', kwargs['sel_decomp_funcs']]
                if 'sel_decomp_ranges' in kwargs:
                    cmd += ['--select-ranges', kwargs['sel_decomp_ranges']]
                cmd += [kwargs['input_file']]
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if proc.returncode:
                    raise error.CommandError("retdec error: {}".format(proc.stderr.decode()))
                return fp.read().decode()

    def check(self):
        self.decomp = None
        self.retdec_dir = None
        if not shutil.which('radare2'):
            raise error.CommandError("binary 'radare2' not found")
        if config.scale_configs['retdec']['online']:
            if not config.scale_configs['retdec']['api_key']:
                raise error.CommandError("config variable 'api_key' has not been set and is required to query the online retdec")
            self.decomp = decompiler.Decompiler(api_key=config.scale_configs['retdec']['api_key'])
        else:
            if not config.scale_configs['retdec']['retdec_dir']:
                raise error.CommandError("config variable 'retdec_dir' has not been set and is required to use a local retdec instance")
            self.retdec_dir = config.scale_configs['retdec']['retdec_dir']

    @scale.command({
        'args': {
            'address_range': fields.Str(),
            'function_name': fields.Str(),
            'mode': fields.Str(default='bin')
        },
        'info': 'decompile a function with retdec'
    })
    def decompile(self, args, file, opts):
        kwargs = {
            'input_file': file.file_path
        }

        name = ''

        # Check the mode and ensure the options
        if args['mode'] == 'bin':
            if 'address_range' in args and args['address_range'] == '':
                del args['address_range']
            if 'function_name' in args and args['function_name'] == '':
                del args['function_name']

            if 'address_range' not in args and 'function_name' not in args:
                raise error.CommandError("'address_range' or 'function_name' must be set")
            if 'address_range' in args and 'function_name' in args:
                raise error.CommandError("'address_range' and 'function_name' are mutually exclusive")

            if 'address_range' in args:
                name = '{}'.format(args['address_range'].strip())
                kwargs['sel_decomp_ranges'] = name.strip()
            elif 'function_name' in args:
                name = '{}'.format(args['function_name'].strip())
                kwargs['sel_decomp_funcs'] = name.strip()
        else:
            raise error.CommandError("incorrect mode specified '{}' the following are supported: 'bin'".format(args['mode']))

        return {
            'code': self._decompile(kwargs),
            'name': name
        }

    def decompile_markdown(self, json):
        output = md.h3(json['name'])
        output += md.code(json['code'], lang='c')
        return output

    @scale.command({
        'info': 'returns a list of functions using radare2'
    })
    def functions(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])  # pylint: disable=invalid-name

        output = {}
        output['exports'] = r2.cmdj('iEj')
        output['functions'] = []
        r2.cmd('aaa')
        funcs = r2.cmdj('aflj')
        if funcs:
            for i in funcs:
                i['address_range'] = '0x%08x-0x%08x' % (i['offset'], i['offset'] + i['size'])
                output['functions'] += [i]

        return output

    def functions_markdown(self, json):
        output = md.h3('Exports')
        output += md.table_header(('Virtual Address', 'Size', 'Type', 'Name'))
        if not json['exports']:
            output += md.table_row(('-', '-', '-', '-'))
        else:
            for row in json['exports']:
                output += md.table_row((
                    '0x%08x' % row['vaddr'],
                    '%u' % row['size'],
                    row['type'],
                    md.bold(row['name'])
                ))
        output += md.newline()
        output += md.h3('Functions')
        output += md.table_header(('Address Range', 'Offset', 'Size', 'Name'))
        if not json['functions']:
            output += md.table_row(('-', '-', '-'))
        else:
            for row in json['functions']:
                output += md.table_row((
                    md.bold(row['address_range']),
                    '0x%08x' % row['offset'],
                    '%u' % row['size'],
                    row['name']
                ))
        return output
