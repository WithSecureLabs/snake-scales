import logging
from os import path
import subprocess
from importlib import reload
import sys, io

import olefile
from oletools import mraptor
from oletools import oledir
from oletools import oleid
from oletools import olemeta
from oletools import olevba3
from oletools.thirdparty.tablestream import tablestream

from snake import config
from snake import error
from snake import scale
from snake.utils import markdown as md


app_log = logging.getLogger("tornado.application")  # pylint: disable=invalid-name


OLEDUMP_PATH = config.scale_configs['office']['oledump_path']
if OLEDUMP_PATH and path.isfile(OLEDUMP_PATH):
    has_oledump = True  # pylint: disable=invalid-name
else:
    if OLEDUMP_PATH:
        app_log.warning("oledump disabled - optional dependencies not met: 'oledump' not found")
    else:
        app_log.warning("oledump disabled - optional dependencies not met: 'oledump_path' not set")
    has_oledump = False  # pylint: disable=invalid-name


class Commands(scale.Commands):
    def check(self):
        pass

    @scale.command({
        'info': 'view the metadata of an ole file'
    })
    def metadata(self, args, file, opts):
        try:
            meta = olefile.OleFileIO(file.file_path).get_metadata()
        except Exception:
            raise error.CommandWarning('file is not a valid ole file')

        attribs = ['codepage', 'title', 'subject', 'author', 'keywords', 'comments', 'template',
                   'last_saved_by', 'revision_number', 'total_edit_time', 'last_printed', 'create_time',
                   'last_saved_time', 'num_pages', 'num_words', 'num_chars', 'thumbnail',
                   'creating_application', 'security', 'codepage_doc', 'category', 'presentation_target',
                   'bytes', 'lines', 'paragraphs', 'slides', 'notes', 'hidden_slides', 'mm_clips',
                   'scale_crop', 'heading_pairs', 'titles_of_parts', 'manager', 'company', 'links_dirty',
                   'chars_with_spaces', 'unused', 'shared_doc', 'link_base', 'hlinks', 'hlinks_changed',
                   'version', 'dig_sig', 'content_type', 'content_status', 'language', 'doc_version']

        output = {}
        for attrib in attribs:
            if isinstance(getattr(meta, attrib), bytes):
                output[attrib] = str(getattr(meta, attrib).decode("utf-8"))
            else:
                output[attrib] = str(getattr(meta, attrib))
        return output

    def metadata_markdown(self, json):
        output = md.table_header(('Attribute', 'Value'))
        for k, v in json.items():
            output += md.table_row((k, v))
        return output

    @scale.command({
        'info': 'examine macros inside of office files'
    })
    def olevba_streams(self, args, file, opts):
        try:
            vbaparser = olevba3.VBA_Parser(file.file_path)
        except Exception:
            raise error.CommandWarning('file is not a valid ole file')

        if not vbaparser.detect_vba_macros():
            vbaparser.close()
            return "no macros found"

        macros = vbaparser.extract_all_macros()
        i = 1
        output = []
        for m in macros:  # pylint: disable=invalid-name
            output += [{
                'stream': str(i),
                'stream_path': str(m[1]),
                'vba_filename': str(m[2]),
                'code': str(m[3].decode('utf-8'))
            }]
            i += 1
        return output

    def olevba_streams_markdown(self, json):
        # NOTE: Linebreaks in markdown tables are pants and we don't allow raw
        # html so, we will have to take the ugly approach
        output = md.table_header(('Stream', 'Stream Path', 'VBA Filename', 'Code'))
        for stream in json:
            code = stream['code'].replace('\r\n\r\n', '\r\n').split('\r\n')
            output += md.table_row((
                stream['stream'],
                stream['stream_path'],
                stream['vba_filename'],
                md.code(md.sanitize(code[0]), inline=True)
            ))
            for extra in code[1:]:
                output += md.table_row(('', '', '', md.code(md.sanitize(extra), inline=True)))
        if not json:
            output += md.table_row(('-', '-', '-', '-'))
        return output

    @scale.command({
        'info': 'examine macros inside of office files'
    })
    def olevba_keywords(self, args, file, opts):
        try:
            vbaparser = olevba3.VBA_Parser(file.file_path)
        except Exception:
            raise error.CommandWarning('file is not a valid ole file')

        output = []
        if not vbaparser.detect_vba_macros():
            vbaparser.close()
            return output

        results = vbaparser.analyze_macros()
        for kw_type, keyword, description in results:
            output += [{
                'type': kw_type,
                'keyword': str(str(keyword).encode('utf-8'))[2:-1],
                'description': description
            }]
        vbaparser.close()
        return output

    def olevba_keywords_markdown(self, json):
        output = md.table_header(['Type', 'Keyword', 'Description'])
        for k in json:
            output += md.table_row([
                k['type'],
                md.code(md.sanitize(k['keyword']), inline=True),
                k['description']
            ])
        if not json:
            output += md.table_row(('-', '-', '-'))
        return output

    @scale.command({
        'info': 'view the metadata of an ole file'
    })
    def oleid(self, args, file, opts):
        try:
            oid = oleid.OleID(file.file_path)
        except Exception:
            raise error.CommandWarning('file is not a valid ole file')

        indicators = oid.check()
        output = []
        for i in indicators:
            output += [{
                'name': str(i.name),
                'value': str(i.value.decode('utf-8')) if isinstance(i.value, bytes) else str(i.value),
                'description': str(i.description)
            }]
        return output

    def oleid_markdown(self, json):
        output = md.table_header(['Name', 'Value', 'Description'])
        for i in json:
            output += md.table_row([
                i['name'],
                i['value'],
                i['description']
            ])
        if not json:
            output += md.table_row(('-', '-', '-'))
        return output

    @scale.command({
        'info': 'view a dump of the ole streams'
    })
    def oledir(self, args, file, opts):

        # Monkeypatch 1 - This is to force the script argument to the appropriate file locaiton for analysis
        def temp_args(_a, _b):
            return [file.file_path]

        # Monkeypatch 2 - This is to customise the write function of tablewriter so that the output can be collected by iostream
        def custom_write(self, a):
            a = a.replace(u"\uFFFD", '')
            print(a, end="")

        # Deoploy Monkeypatch 1
        import optparse
        get_args = optparse.OptionParser._get_args
        optparse.OptionParser._get_args = temp_args

        # Deploy MoknkeyPath 2
        oledir_old = tablestream.TableStream.write
        tablestream.TableStream.write = custom_write

        # Mokeypatch - This rediverts stdout to a stream that can be collected later for results
        sys.stdout = io.StringIO()

        try:
            oledir.main()
        except Exception:
            # Revert patched functions to originals
            optparse.OptionParser._get_args = get_args
            sys.stdout = sys.__stdout__
            tablestream.TableStream.write = oledir_old
            reload(oledir)
            raise error.CommandWarning('Dir old dump error')

        result = sys.stdout.getvalue()

        # Revert patched function to originals
        optparse.OptionParser._get_args = get_args
        sys.stdout = sys.__stdout__
        tablestream.TableStream.write = oledir_old
        reload(oledir)

        return result

    # Table generated is good as is, why change it?
    def oledir_plaintext(self, json):
        return json

    @scale.command({
        'info': 'view a metadata for ole file'
    })
    def olemeta(self, args, file, opts):

        # Monkeypatch 1 - This is to force the script argument to the appropriate file locaiton for analysis
        def temp_args(_a, _b):
            return [file.file_path]

        # Deoploy Monkeypatch 1
        import optparse
        get_args = optparse.OptionParser._get_args
        optparse.OptionParser._get_args = temp_args

        # Mokeypatch - This rediverts stdout to a stream that can be collected later for results
        sys.stdout = io.StringIO()

        try:
            olemeta.main()
        except Exception:
            # Revert patched functions to originals
            optparse.OptionParser._get_args = get_args
            sys.stdout = sys.__stdout__
            raise error.CommandWarning('Dir old dump error')

        result = sys.stdout.getvalue()

        # Revert patched function to originals
        optparse.OptionParser._get_args = get_args
        sys.stdout = sys.__stdout__
        reload(oledir)

        return result

    # Table generated is good as is, why change it?
    def olemeta_plaintext(self, json):
        return json

    @scale.command({
        'info': 'view a metadata for ole file'
    })
    def mraptor(self, args, file, opts):

        # Monkeypatch 1 - This is to force the script argument to the appropriate file locaiton for analysis
        def temp_args(_a, _b):
            return [file.file_path]

        # Deoploy Monkeypatch 1
        import optparse
        get_args = optparse.OptionParser._get_args
        optparse.OptionParser._get_args = temp_args

        # Mokeypatch - This rediverts stdout to a stream that can be collected later for results
        sys.stdout = io.StringIO()

        try:
            mraptor.main()
        except Exception:
            # Revert patched functions to originals
            optparse.OptionParser._get_args = get_args
            sys.stdout = sys.__stdout__
            raise error.CommandWarning('Dir old dump error')

        result = sys.stdout.getvalue()

        # Revert patched function to originals
        optparse.OptionParser._get_args = get_args
        sys.stdout = sys.__stdout__
        reload(oledir)

        return result

    # Table generated is good as is, why change it?
    def mraptor_plaintext(self, json):
        return json
