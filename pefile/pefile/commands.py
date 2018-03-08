from datetime import datetime
from os import path

import peutils
import pefile

from snake import db
from snake import error
from snake import scale
from snake.utils import markdown as md

# NOTE: This is a local file but will be namespaced
from snake.scales.pefile import pefunctions  # pylint: disable=import-error, no-name-in-module


class Commands(scale.Commands):
    def check(self):
        pass

    @scale.command({
        'info': 'return the pe sections for the file passed'
    })
    def sections(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path, fast_load=True)  # pylint: disable=invalid-name, no-member
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)

        output = []
        try:
            for section in pe.sections:
                if isinstance(section.Name, bytes):
                    section_name = section.Name.decode()
                else:
                    section_name = section.Name
                output += [{
                    'name': str(section_name),
                    'virtual_address': str(hex(section.VirtualAddress)),
                    'virtual_size': str(hex(section.Misc_VirtualSize)),
                    'physical_address': str(section.PointerToRawData),
                    'physical_size': str(section.SizeOfRawData),
                    'entropy': str(section.get_entropy())
                }]
        except Exception as err:
            raise error.CommandWarning('an error occurred: %s' % err)

        return output

    def sections_markdown(self, json):
        output = md.table_header(['Name', 'RVA', 'Virtual Size', 'Physical Address', 'Physical Size', 'Entropy'])
        for s in json:  # pylint: disable=invalid-name
            output += md.table_row([
                s['name'],
                s['virtual_address'],
                s['virtual_size'],
                s['physical_address'],
                s['physical_size'],
                s['entropy']
            ])
        if not json:
            md.table_row(('-', '-', '-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'return the pe imports for the file passed'
    })
    def imports(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)

        output = {}
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = []
                    name = None
                    for imp in entry.imports:
                        if not name:
                            name = entry.dll.decode('utf-8')
                        dll += [{
                            'name': imp.name.decode('utf-8') if imp.name else str(imp.name),
                            'address': hex(imp.address)
                        }]
                    if name:
                        output[name] = dll
        except Exception as err:
            raise error.CommandWarning('an error occurred: %s' % err)

        return output

    def imports_markdown(self, json):
        output = md.table_header(('DLL', 'Import', 'Address'))
        for k, v in json.items():
            i = 0
            for imp in v:
                output += md.table_row([
                    k if i == 0 else '',
                    imp['name'],
                    imp['address']
                ])
                i += 1
        if not json:
            md.table_row(('-', '-', '-'))
        return output

    @scale.command({
        'info': 'return the pe export for the file passed'
    })
    def exports(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)

        output = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                output += [{
                    'name': exp.name.decode('utf-8'),
                    'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
                }]
        return output

    def exports_markdown(self, json):
        output = md.table_header(['Export', 'Address'])
        for e in json:  # pylint: disable=invalid-name
            output += md.table_row([
                e['name'],
                e['address']
            ])
        if not json:
            output += md.table_row(('-', '-'))
        return output

    @scale.command({
        'info': 'return the pe info found for the file passed'
    })
    def info(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
            machine = pe.FILE_HEADER.Machine
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)

        if machine == 332:
            arch = 'i386'
        elif machine == 512:
            arch = 'ia64'
        elif machine == 34404:
            arch = 'amd64'
        else:
            arch = 'unknown'

        output = {
            'compile_time': str(datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp)),
            'language': str(pefunctions.code_language(pe, file.file_path)),
            'architecture': arch,
            'certificate': pefunctions.get_certificate(pe)
        }
        return output

    def info_markdown(self, json):
        output = md.table_header(['Attribute', 'Value'])
        output += md.table_row(['Compile Time:', json['compile_time']])
        output += md.table_row(['Language:', json['language']])
        output += md.table_row(['Architecture:', json['architecture']])
        output += md.table_row(['Certificate:', json['certificate']])

        return output

    @scale.autorun
    @scale.command({
        'info': 'generate imphash for file',
        'mime': 'application/x-dosexec'
    })
    def imphash(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)
        document = db.file_collection.select(file.sha256_digest)
        if 'imphash' not in document:
            imphash = str(pe.get_imphash())
            if imphash == "":
                return {"imphash": "none"}
            data = {'imphash': imphash}
            if not db.file_collection.update(file.sha256_digest, data):
                raise error.CommandWarning('Error adding imphash into file document %s' % file.sha256_digest)
        document = db.file_collection.select(file.sha256_digest)
        return {'imphash': document['imphash']}

    def imphash_plaintext(self, json):
        return json['imphash']

    @scale.autorun
    @scale.command({
        'info': 'generate pehash for file',
        'mime': 'application/x-dosexec'
    })
    def pehash(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)
        document = db.file_collection.select(file.sha256_digest)
        if 'pehash' not in document:
            pehash = pefunctions.calculate_pehash(pe)
            if 'An error occured' in pehash:
                raise error.CommandWarning('unable to calculate pehash with pefile')
            data = {'pehash': pehash}
            if not db.file_collection.update(file.sha256_digest, data):
                raise error.CommandWarning('error adding pehash into file document %s' % file.sha256_digest)
        document = db.file_collection.select(file.sha256_digest)
        return {'pehash': document['pehash']}

    def pehash_plaintext(self, json):
        return json['pehash']

    @scale.command({
        'info': 'return all the pe info found within the file passed'
    })
    def all_info(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)

        return {'info': pe.dump_info()}

    def all_info_plaintext(self, json):
        return json['info']

    @scale.command({
        'info': 'return any peid signatures found within the file passed'
    })
    def peid(self, args, file, opts):
        try:
            pe = pefile.PE(file.file_path)  # pylint: disable=invalid-name, no-member
            userdb_path = path.join(path.dirname(__file__), 'userdb.txt')
            sigs = peutils.SignatureDatabase(userdb_path)
        except Exception as err:
            raise error.CommandWarning('unable to parse with pefile: %s' % err)

        try:
            matches = sigs.match_all(pe, ep_only=True)
        except Exception:
            raise error.CommandWarning('error matching peid signatures')

        # Matches returns a list of lists, hence the stupid indexing
        output = []
        if not matches:
            pass
        elif len(matches) == 1:
            output += [str(matches[0][0])]
        else:
            for match in matches:
                output += [match[0]]
        return output

    def peid_markdown(self, json):
        output = md.table_header(['Signatures'])
        for i in json:
            output += md.table_row([i])
        if not json:
            output += md.table_row(('-'))
        return output
