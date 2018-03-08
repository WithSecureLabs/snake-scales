import shutil

import r2pipe

from snake import error
from snake import scale
from snake.utils import markdown as md


# TODO: Supress r2's stderr

# pylint: disable=invalid-name

class Commands(scale.Commands):  # pylint: disable=too-many-public-methods
    def check(self):
        strings = shutil.which('radare2')
        if not strings:
            raise error.CommandWarning("binary 'radare2' not found")
        return

    @scale.command({
        'info': 'This function will return the entrypoints for the file'
    })
    def entrypoints(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('iej')

    def entrypoints_markdown(self, json):
        output = md.table_header(('Virtual Address', 'Physical Address', 'Base Address', 'Logical Address', 'Hardware Address', 'Type'))
        for d in json:
            output += md.table_row((
                '0x%08x' % d['vaddr'],
                '0x%08x' % d['paddr'],
                '0x%08x' % d['baddr'],
                '0x%08x' % d['laddr'],
                '0x%08x' % d['haddr'],
                d['type']
            ))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'This function will return the exports for the file'
    })
    def exports(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('iEj')

    def exports_markdown(self, json):
        output = md.table_header(('Virtual Address', 'Physical Address', 'Size', 'Type', 'Name'))
        for d in json:
            output += md.table_row((
                '0x%08x' % d['vaddr'],
                '0x%08x' % d['paddr'],
                '%u' % d['size'],
                d['type'],
                d['name']
            ))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'This function will return the headers for the file'
    })
    def headers(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return {'headers': r2.cmd('iHH')}

    def headers_plaintext(self, json):
        return json['headers']

    @scale.command({
        'info': 'This function will return the info for the file'
    })
    def info(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('ij')

    def info_plaintext(self, json):
        output = ''
        if 'core' in json.keys():
            for k, v in json['core'].items():
                output += k.ljust(20) + ': ' + (str(v) if v != '' else 'N/A') + '\n'
        if 'bin' in json.keys():
            for k, v in json['bin'].items():
                output += k.ljust(20) + ': ' + (str(v) if v != '' else 'N/A') + '\n'
        return output

    @scale.command({
        'info': 'This function will return the imports for the file'
    })
    def imports(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('iij')

    def imports_markdown(self, json):
        output = md.table_header(('Ordinal', 'Bind', 'Type', 'Name', 'Procedure Linkage Table'))
        for d in json:
            output += md.table_row((
                '%u' % d['ordinal'],
                d['bind'],
                d['type'],
                d['name'],
                '0x%08x' % d['plt']
            ))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'This function will return the relocations for the file'
    })
    def relocations(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('irj')

    def relocations_markdown(self, json):
        output = md.table_header(('Type', 'Virtual Address', 'Physical Address', 'Indirect Function', 'Name'))
        for d in json:
            output += md.table_row((
                d['type'],
                '0x%08x' % d['vaddr'],
                '0x%08x' % d['paddr'],
                '%s' % d['is_ifunc'],
                d['name']
            ))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'This function will return the resources for the file'
    })
    def resources(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('iRj')

    def resources_markdown(self, json):
        output = md.table_header(('Index', 'Type', 'Virtual Address', 'Size', 'Language', 'Name'))
        for d in json:
            output += md.table_row((
                '%u' % d['index'],
                d['type'],
                '0x%08x' % d['vaddr'],
                '%u' % d['size'],
                d['lang'],
                '%s' % d['name']
            ))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'This function will return the sections for the file'
    })
    def sections(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('iSj')

    def sections_markdown(self, json):
        output = md.table_header(('Virtual Address', 'Virtual Size', 'Physical Address', 'Size', 'Flags', 'Name'))
        for d in json:
            output += md.table_row((
                '0x%08x' % d['vaddr'],
                '%u' % d['vsize'],
                '0x%08x' % d['paddr'],
                '%u' % d['size'],
                d['flags'],
                d['name']
            ))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'This function will return the symbols for the file'
    })
    def symbols(self, args, file, opts):
        r2 = r2pipe.open(file.file_path, ['-2'])
        return r2.cmdj('isj')

    def symbols_markdown(self, json):
        output = md.table_header(('Size', 'Type', 'Virtual Address', 'Physical Address', 'Name'))
        for d in json:
            output += md.table_row((
                '%u' % d['size'],
                d['type'],
                '0x%08x' % d['vaddr'],
                '0x%08x' % d['paddr'],
                d['name']
            ))
        return output

    @scale.command({
        'info': 'This function will return the strings in the data sections of the file'
    })
    def strings(self, args, file, opts):
        # TODO: Use json
        r2 = r2pipe.open(file.file_path, ['-2'])
        output = r2.cmd('iz')
        return {'strings': output}

    def strings_plaintext(self, json):
        return json['strings']

    @scale.command({
        'info': 'This function will return all strings found in the file'
    })
    def all_strings(self, args, file, opts):
        # TODO: Use json
        r2 = r2pipe.open(file.file_path, ['-2'])
        output = r2.cmd('izz')
        return {'all_strings': output}

    def all_strings_plaintext(self, json):
        return json['all_strings']
