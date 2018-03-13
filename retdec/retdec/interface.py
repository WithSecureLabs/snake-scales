import shutil

import r2pipe
import requests

from snake import config
from snake import error
from snake import fields
from snake import scale
from snake.utils import markdown as md

# Global things
API_KEY = config.scale_configs['retdec']['api_key']
API_URL = config.scale_configs['retdec']['api_url']

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
DEFAULT_API_URL = API_URL
retdec.conn.APIConnection._start_new_session = start_new_session  # pylint: disable=protected-access
from retdec import decompiler  # noqa pylint: disable=wrong-import-position
from retdec import exceptions  # noqa pylint: disable=wrong-import-position


# Interface things
class Interface(scale.Interface):
    def check(self):
        if not API_URL:
            raise error.InterfaceError("config variable 'api_url' has not been set")
        if API_URL == 'https://retdec.com/service/api' and not API_KEY:
            raise error.InterfaceError("config variable 'api_key' has not been set and is required to query the online retdec")
        self.objdump_path = shutil.which('radare2')
        if not self.objdump_path:
            raise error.InterfaceError("binary 'radare2' not found")

        self.decomp = decompiler.Decompiler(api_key=API_KEY)

    @scale.pull({
        'args': {
            'address_range': fields.Str(),
            'function_name': fields.Str(),
            'mode': fields.Str(default='bin', missing='bin')
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
                raise error.InterfaceError("'address_range' or 'function_name' must be set")
            if 'address_range' in args and 'function_name' in args:
                raise error.InterfaceError("'address_range' and 'function_name' are mutually exclusive")

            if 'address_range' in args:
                name = '{}'.format(args['address_range'])
                kwargs['sel_decomp_ranges'] = name
            elif 'function_name' in args:
                name = '{}'.format(args['function_name'])
                kwargs['sel_decomp_funcs'] = [name]
        else:
            raise error.InterfaceError("incorrect mode specified '{}' the following are supported: 'bin'".format(args['mode']))

        try:
            decompilation = self.decomp.start_decompilation(**kwargs)
            decompilation.wait_until_finished()
        except exceptions.RetdecError as err:
            raise error.InterfaceError("retdec-python error: {}".format(err))

        return {
            'code': decompilation.get_hll_code(),
            'name': name
        }

    def decompile_markdown(self, json):
        output = md.h3(json['name'])
        output += md.code(json['code'], 'c')
        return output

    @scale.pull({
        'args': {
            'analyse': fields.Bool(default=False, missing=False)
        },
        'info': 'returns a list of functions using radare2'
    })
    def functions(self, args, file, opts):
        # NOTE: Not really an interface but this makes sense, promise!
        r2 = r2pipe.open(file.file_path, ['-2'])  # pylint: disable=invalid-name

        output = {}
        output['exports'] = r2.cmdj('iEj')
        output['functions'] = []
        if args['analyse']:
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
