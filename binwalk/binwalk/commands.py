import os
from os import path
import shutil
import subprocess
import tempfile

from snake import config
from snake import db
from snake import enums
from snake import error
from snake import scale
from snake import schema
from snake.utils import file_storage as fs
from snake.utils import markdown as md
from snake.utils import submitter

from . import NAME


class Commands(scale.Commands):
    def check(self):
        self.binwalk_path = shutil.which("binwalk")
        if not self.binwalk_path:
            raise error.CommandError("binary 'binwalk' not found")

    @scale.command({
        'info': "parse the file with binwalk the scrape contents"
    })
    def binwalk(self, args, file, opts):
        return {'binwalk': str(subprocess.check_output([self.binwalk_path, file.file_path]), encoding='utf-8')}

    def binwalk_plaintext(self, json):
        return json['binwalk']

    @scale.command({
        'info': "extract known file types using binwalk and upload them into snake"
    })
    def extract(self, args, file, opts):
        samples = []
        with tempfile.TemporaryDirectory(dir=path.abspath(path.expanduser(config.snake_config['cache_dir']))) as temp_dir:
            # Extract the samples
            proc = subprocess.run([self.binwalk_path, file.file_path, '-e', '-C', temp_dir],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
            if not proc:
                raise error.CommandError("failed to successfully extract from sample")
            # Get file name
            document = db.file_collection.select(file.sha256_digest)
            if not document:
                raise error.SnakeError("failed to get sample's metadata")
            # There will be one output directory connataining files with the offsets as names
            contents = os.listdir(temp_dir)
            if not contents:
                return []
            directory = path.join(temp_dir, contents[0])
            for i in os.listdir(directory):
                file_path = path.join(directory, i)
                name = '{}.{}'.format(document['name'], i)
                file_schema = schema.FileSchema().load({
                    'name': name,
                    'description': 'extracted with binwalk'
                })
                new_file = fs.FileStorage()
                new_file.create(file_path)
                new_document = submitter.submit(file_schema, enums.FileType.FILE, new_file, file, NAME)
                new_document = schema.FileSchema().dump(schema.FileSchema().load(new_document))  # Required to clean the above
                samples += [new_document]
        return samples

    def extract_markdown(self, json):
        output = md.table_header(('Name', 'SHA256 Digest', 'File Type'))
        for sample in json:
            output += md.table_row((
                sample['name'],
                md.url(sample['sha256_digest'], '/#/{}/{}'.format(sample['file_type'], sample['sha256_digest'])),
                sample['file_type']
            ))
        if not json:
            output += md.table_row(('-', '-', '-'))
        return output
