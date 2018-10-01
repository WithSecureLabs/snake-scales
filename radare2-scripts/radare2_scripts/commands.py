from os import path
import shutil
import subprocess
import tempfile

from snake import config
from snake import db
from snake import enums
from snake import error
from snake import fields
from snake import scale
from snake import schema
from snake.utils import file_storage as fs
from snake.utils import markdown as md
from snake.utils import submitter

from . import NAME
from .scripts import r2_bin_carver
from .scripts import r2_hash_func_decoder

# pylint: disable=invalid-name


class Commands(scale.Commands):  # pylint: disable=too-many-public-methods
    def check(self):
        strings = shutil.which('radare2')
        if not strings:
            raise error.CommandWarning("binary 'radare2' not found")
        return

    @scale.command({
        'args': {
            'offset': fields.Str(required=True),
            'magic_bytes': fields.Str(default=None, missing=None),
            'patch': fields.Bool(default=True, missing=True),
            'size': fields.Str(required=True),
        },
        'info': 'this function will carve binaries out of MDMP files'
    })
    def binary_carver(self, args, file, opts):
        sample = {}
        with tempfile.TemporaryDirectory(dir=path.abspath(path.expanduser(config.snake_config['cache_dir']))) as temp_dir:
            # Try and carve
            file_path = r2_bin_carver.carve(file.file_path, temp_dir, args['offset'], args['size'], args['magic_bytes'])
            if not file_path:
                raise error.CommandError('failed to carve binary')
            if args['patch']:
                if not r2_bin_carver.patch(file_path):
                    raise error.CommandError('failed to patch binary, not a valid pe file')

            # Get file name
            document = db.file_collection.select(file.sha256_digest)
            if not document:
                raise error.SnakeError("failed to get sample's metadata")

            # Create schema and save
            name = '{}.{}'.format(document['name'], args['offset'])
            file_schema = schema.FileSchema().load({
                'name': name,
                'description': 'extracted with radare2 script r2_bin_carver.py'
            })
            new_file = fs.FileStorage()
            new_file.create(file_path)
            sample = submitter.submit(file_schema, enums.FileType.FILE, new_file, file, NAME)
            sample = schema.FileSchema().dump(schema.FileSchema().load(sample))  # Required to clean the above

        return sample

    def binary_carver_markdown(self, json):
        output = md.table_header(('Name', 'SHA256 Digest', 'File Type'))
        output += md.table_row((
            json['name'],
            md.url(json['sha256_digest'], '/#/{}/{}'.format(json['file_type'], json['sha256_digest'])),
            json['file_type']
        ))
        if not json.keys():
            output += md.table_row(('-', '-', '-'))
        return output

    @scale.command({
        'args': {
            'bits': fields.Str(default='32', missing='32', values=['32', '64']),
            'technique': fields.Str(required=True, values=r2_hash_func_decoder.TECHNIQUES)
        },
        'info': 'scan shellcode for hashed functions'
    })
    def hash_function_decoder(self, args, file, opts):
        # Validate
        if args['bits'] not in ['32', '64']:
            raise error.CommandError('invalid bits provided, currently supported: 32, 64')
        if args['technique'] not in r2_hash_func_decoder.TECHNIQUES:
            raise error.CommandError('invalid technique provided, currently supported: {}'.format(r2_hash_func_decoder.TECHNIQUES))

        scale_dir = path.dirname(__file__)
        func_decoder = path.join(scale_dir, 'scripts/r2_hash_func_decoder.py')
        hash_db = path.join(scale_dir, 'scripts/r2_hash_func_decoder.db')

        # Get the output
        proc = subprocess.run(['python3', '{}'.format(func_decoder), 'analyse', '-f', '{}'.format(file.file_path), '-d', '{}'.format(hash_db), '{}'.format(args['technique'])],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        if proc.returncode:
            raise error.CommandError('failed to execute script')

        return {'analysis': str(proc.stdout, encoding='utf-8')}

    def hash_function_decoder_plaintext(self, json):
        return json['analysis']
