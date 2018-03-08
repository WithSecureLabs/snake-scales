from elftools.common import exceptions
from elftools.elf import descriptions
from elftools.elf import elffile

from snake import error
from snake import scale
from snake.utils import markdown as md


class Commands(scale.Commands):
    def check(self):
        pass

    @scale.command({
        'info': 'view the sections of an elf file'
    })
    def sections(self, args, file, opts):
        output = []
        with open(file.file_path, 'rb') as f:
            try:
                for section in elffile.ELFFile(f).iter_sections():
                    s = {}  # pylint: disable=invalid-name
                    if section.name == '':
                        s['name'] = '-'
                    else:
                        s['name'] = str(section.name)
                    s['address'] = str(hex(section['sh_addr']))
                    s['size'] = str(hex(section['sh_size']))
                    s['offset'] = str(hex(section['sh_offset']))
                    s['type'] = str(section['sh_type'])[4:]
                    if str(descriptions.describe_sh_flags(section['sh_flags'])) == '':
                        s['flags'] = '-'
                    else:
                        s['flags'] = str(descriptions.describe_sh_flags(section['sh_flags']))
                    output += [s]
            except exceptions.ELFError as err:
                raise error.CommandError(str(err))
        return output

    def sections_markdown(self, json):
        output = md.table_header(('Name', 'Address', 'Size', 'Offset', 'Type', 'Flags'))
        for s in json:  # pylint: disable=invalid-name
            output += md.table_row((s['name'], s['address'], s['size'], s['offset'], s['type'], s['flags']))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-', '-'))
        return output
