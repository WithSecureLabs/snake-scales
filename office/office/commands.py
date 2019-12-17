import logging
from os import path
import subprocess
from importlib import reload
import sys, io

import olefile
from oletools import oleobj
from oletools import mraptor3
from oletools import oledir
from oletools import oleid
from oletools import olemeta
from oletools import olevba3
from oletools.thirdparty.tablestream import tablestream

from snake import error
from snake import scale
from snake.utils import markdown as md

## Needed for extraction of file
import tempfile
from snake import config
from . import NAME
from snake import enums
from snake import schema
from snake import db
from snake.utils import file_storage as fs
from snake.utils import submitter



app_log = logging.getLogger("tornado.application")  # pylint: disable=invalid-name

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
            raise error.CommandWarning('file ' + str(file.file_path) + ' is not a valid ole file')

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


    # XXX - Need to handle some errors more properly (specially when no vba)

    @scale.command({
        'info': 'examine macros inside of office files'
    })
    def olevba_streams(self, args, file, opts):
        output = []
        try:
            vbaparser = olevba3.VBA_Parser(file.file_path)
        except Exception:
            raise error.CommandWarning('file ' + str(file.file_path) + ' is not a valid ole file')

        try:
            vbaparser.detect_vba_macros()
        except:
            vbaparser.close()
            raise error.CommandWarning('no macro was detected on this file')

        try:
            macros = vbaparser.extract_all_macros()
        except:
            raise error.CommandWarning('vbaparser.extract_all_macros() failed to extract macros')
        i = 1
        for m in macros:  # pylint: disable=invalid-name
            try:
                output += [{
                    'stream': str(i),
                    'stream_path': str(m[1]),
                    'vba_filename': str(m[2]),
                    'code': str(m[3].decode('utf-8'))
                }]
            except:
                output += [{
                    'stream': str(i),
                    'stream_path': str(m[1]),
                    'vba_filename': str(m[2]),
                    'code': str(m[3])
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
            raise error.CommandWarning('file ' + str(file.file_path) + ' is not a valid ole file')

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
            raise error.CommandWarning('file ' + str(file.file_path) + ' is not a valid ole file')

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



    # XXX - Need to handle some errors more properly (specially when not an ole file apparently)
    @scale.command({
        'info': 'view a dump of the ole streams'
    })
    def oledir(self, args, file, opts):

        # Monkeypatch 1 - This is to force the script argument to the appropriate file locaiton for analysis
        def temp_args(_a, _b):
            return [file.file_path]

        # Monkeypatch 2 - This is to customise the write function of tablewriter so that the output can be collected by iostream
        def custom_write(self, a):
            a = a.replace(u"\uFFFD", '\n')
            print(a, end="")

        # Deoploy Monkeypatch 1
        import optparse
        get_args = optparse.OptionParser._get_args
        optparse.OptionParser._get_args = temp_args
        res = []
        result = []

        try:
            ole = olefile.OleFileIO(file.file_path)
        except Exception:
            raise error.CommandWarning('file ' + str(file.file_path) + ' is not a valid ole file')

        # Deploy MonkeyPath 2
        for id in range(len(ole.direntries)):
           res_dict = dict()
           res_dict['id'] = id
           d = ole.direntries[id]
           if d is None:
               # this direntry is not part of the tree: either unused or an orphan
               d = ole._load_direntry(id) #ole.direntries[id]
               # print('%03d: %s *** ORPHAN ***' % (id, d.name))
               if d.entry_type == olefile.STGTY_EMPTY:
                   res_dict['Status'] = 'unused'
               else:
                   res_dict['Status'] = 'ORPHAN'
           else:
               # print('%03d: %s' % (id, d.name))
               res_dict['Status'] = '<Used>'
           if d.name.startswith('\x00'):
               # this may happen with unused entries, the name may be filled with zeroes
               res_dict['Name'] = ''
           else:
               # handle non-printable chars using repr(), remove quotes:
               res_dict['Name'] = repr(d.name)[1:-1]
           res_dict['Left']  = oledir.sid_display(d.sid_left)
           res_dict['Right'] = oledir.sid_display(d.sid_right)
           res_dict['Child'] = oledir.sid_display(d.sid_child)
           res_dict['Type'] = oledir.STORAGE_NAMES.get(d.entry_type, 'Unknown')
           res_dict['1st_Sect'] = d.isectStart
           res_dict['Size'] = d.size
           result.append(res_dict)


        # Retrieving CLSID, making the second table 
        result2 = []
        rootname = ole.get_rootentry_name()
        entry_id = 0
        clsid = ole.root.clsid
        clsid_text, clsid_color = oledir.clsid_display(clsid)
        res_dict = dict()
        res_dict['id2'] = entry_id
        res_dict['obj_tree'] = '-' 
        res_dict['Name'] = rootname
        res_dict['Size'] = '-'
        res_dict['CLSID'] = clsid_text
        result2.append(res_dict)


        # Creating macro tree, as it is sorted, obj_tree allows us to reconstruct the tree of the macros
        for entry in sorted(ole.listdir(storages=True)):
            res_dict = dict()
            obj_tree = 0
            name = entry[-1]
            # handle non-printable chars using repr(), remove quotes:
            name = repr(name)[1:-1]
            name_color = None
            obj_tree = len(entry)-1
            indented_name = "WS"*(len(entry)-1) + name
            entry_id = ole._find(entry)
            try:
                size = ole.get_size(entry)
            except:
                size = '-'
            clsid = ole.getclsid(entry)
            clsid_text, clsid_color = oledir.clsid_display(clsid)
            res_dict['id2'] = entry_id
            res_dict['obj_tree'] = obj_tree
            res_dict['Name'] = indented_name
            res_dict['Size'] = size
            res_dict['CLSID'] = clsid_text
            result2.append(res_dict)

        res.append(result)
        res.append(result2)
        # Revert patched function to originals
        ole.close()
        optparse.OptionParser._get_args = get_args
        reload(oledir)
        return res

    def oledir_markdown(self, json):
        output = md.table_header(['id', 'Status', 'Type', 'Name', 'Left', 'Right', 'Child', '1st Sec', 'Size'])
        j = 0
        if not json:
            output += md.table_row(('-', '-', '-'))
        for i in json:
            while j < len(i):
                if not 'obj_tree' in i[j]:
                    output += md.table_row([
                        str(i[j]['id']),
                        str(i[j]['Status']),
                        str(i[j]['Type']),
                        str(i[j]['Name']),
                        str(i[j]['Left']),
                        str(i[j]['Right']),
                        str(i[j]['Child']),
                        str(i[j]['1st_Sect']),
                        str(i[j]['Size']),
                        ])

                j = j + 1
        j = 0
        output += '\n'
        output += md.table_header(['id', 'Obj_tree', 'Name', 'Size', 'CLSID'])
        for i in json:
            if 'obj_tree' in str(i[j]):
                while j < len(i):
                    output += md.table_row([
                        str(i[j]['id2']),
                        str(i[j]['obj_tree']),
                        str(i[j]['Name']),
                        str(i[j]['Size']),
                        str(i[j]['CLSID']).replace('\n',' ')
                    ])
                    j = j + 1
        return output

    def oledir_plaintext(self, json):
        return json


    @scale.command({
        'info': 'extract ole objects from ole native streams'
    })

    def oleobj(self, args, file, opts):

        # Monkeypatch 1 - This is to force the script argument to the appropriate file locaiton for analysis
        def temp_args(_a, _b, _c):
            return [file.file_path]

        # Deploy Monkeypatch 1
        import optparse
        get_args = optparse.OptionParser._get_args
        optparse.OptionParser._get_args = temp_args
        output = []
        fname_prefix = oleobj.sanitize_filename(file.file_path)
        index = 1
        DUMP_CHUNK_SIZE = 4096
        result = dict()
        for ole in oleobj.find_ole(file.file_path, None):
            if ole is None:    # no ole file found
                continue

            for path_parts in ole.listdir():
                stream_path = '/'.join(path_parts)
                if path_parts[-1] == '\x01Ole10Native':
                    stream = None
                    try:
                        stream = ole.openstream(path_parts)
                        #print('extract file embedded in OLE object from stream %r:'
                        #      % stream_path)
                        #print('Parsing OLE Package')
                        opkg = oleobj.OleNativeStream(stream)
                        # leave stream open until dumping is finished
                    except Exception:
                        raise error.CommandWarning("*** Not an OLE 1.0 Object")
                        if stream is not None:
                            stream.close()
                        continue
                    if opkg.is_link:
                        raise error.CommandWarning('Object is not embedded but only linked to '
                                  '- skip')
                        continue
                    result['SHA256_AnalyzedFile'] = fname_prefix
                    result['Extracted_file.NAME'] = opkg.filename
                    result['Source_path'] = opkg.src_path
                    result['Temp_path'] = opkg.temp_path
                    if opkg.filename:
                        fname = '%s_%s' % (fname_prefix,
                                           oleobj.sanitize_filename(opkg.filename))
                    else:
                        fname = '%s_object_%03d.noname' % (fname_prefix, index)
                    try:
                        result['Saved_Filename'] = fname

                        samples = []
                        with tempfile.TemporaryDirectory(dir=path.abspath(path.expanduser(config.snake_config['cache_dir']))) as temp_dir:
                            file_path = path.join(temp_dir, fname)
                            with open(file_path, 'wb') as writer:
                                n_dumped = 0
                                next_size = min(DUMP_CHUNK_SIZE, opkg.actual_size)
                                while next_size:
                                    data = stream.read(next_size)
                                    writer.write(data)
                                    n_dumped += len(data)
                                    if len(data) != next_size:
                                        raise error.CommandWarning('Wanted to read {0}, got {1}'
                                                    .format(next_size, len(data)))
                                        break
                                    next_size = min(DUMP_CHUNK_SIZE,
                                                    opkg.actual_size - n_dumped)
                            file_schema = schema.FileSchema().load({
                                'name': fname,
                                'description': 'extracted with oleobj from ' + fname
                            })
                            
                            new_file = fs.FileStorage()
                            new_file.create(file_path)
                            new_document = submitter.submit(file_schema, enums.FileType.FILE, new_file, file, NAME)
                            new_document = schema.FileSchema().dump(schema.FileSchema().load(new_document))
                            samples += [new_document]
                            for i in samples:
                                i['name'] = fname
                            result['samples'] = samples

                    except Exception as exc:
                        raise error.CommandWarning('error dumping to {0} ({1})'
                                    .format(fname, exc))
                    finally:
                        stream.close()

                    index += 1
            output.append(result)
        return output
    
    def oleobj_markdown(self, json):
        output = "Ole obj from oletools\n"
        if not json:
            raise error.CommandWarning('No ole object was found')
        j = 0
        for i in json:
            if not i:
                raise error.CommandWarning('No ole object was found')
            output += md.bold("Found embedded file = ") + str(i['Saved_Filename']) + "\n"
            output += md.bold("Source path = ") + str(i['Source_path']) + "\n"
            output += md.bold("Temp path = ") + str(i['Temp_path']) + "\n"

            for j in i['samples']:
                # XXX - Fix me hardcoded URL
                output += md.bold("Extracted_file.URL: ") + md.url("SNAKE_URL", "/sample/" + str(j['sha256_digest'])) + '\n'
                output += md.bold("Extracted_file.DESCRIPTION: ") + str(j['description']) + '\n'
                output += md.bold("Extracted_file.MIME: ") + str(j['mime']) + '\n'
                output += md.bold("Extracted_file.SIZE: ") + str(j['size']) + '\n'
                output += md.bold("Extracted_file.MAGIC: ") + str(j['magic']) + '\n'
                output += md.bold("Extracted_file.SHA256: ") + str(j['sha256_digest']) + '\n'
        return output

    def oleobj_plaintext(self, json):
        return json


    #### Don't need this scale cause it actually uses olefile therefore same as metadata() ####
    # XXX: Delete me !!!
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

        result = { 'Result': sys.stdout.getvalue() } # To be displayed properly !!!

        # Revert patched function to originals
        optparse.OptionParser._get_args = get_args
        sys.stdout = sys.__stdout__
        reload(oledir)

        return result

    # Table generated is good as is, why change it?
    def olemeta_plaintext(self, json):
        return json


    # XXX - Need to handle some errors more properly (specially when not an ole file apparently)
    @scale.command({
        'info': 'does different regex to check for suspicious macros'
    })
    def mraptor(self, args, file, opts):

        # Monkeypatch 1 - This is to force the script argument to the appropriate file locaiton for analysis
        def temp_args(_a, _b, _c, _d):
            return [file.file_path]

        # Deploy Monkeypatch 1
        import optparse
        get_args = optparse.OptionParser._get_args
        optparse.OptionParser._get_args = temp_args

        # Monkeypatch - This rediverts stdout to a stream that can be collected later for results
        sys.stdout = io.StringIO()
        result = []

        try:
            vbaparser = olevba3.VBA_Parser(file.file_path)
        except Exception:
            raise error.CommandWarning('file ' + str(file.file_path) + ' is not a valid ole file')
        
        filetype = olevba3.TYPE2TAG[vbaparser.type]

        if not vbaparser.detect_vba_macros():
            vbaparser.close()
            raise error.CommandWarning('file does not have macros')

        try:
            vba_code_all_modules = ''
            for (subfilename, stream_path, vba_filename, vba_code) in vbaparser.extract_all_macros():
                vba_code_all_modules += vba_code + '\n'
            m = mraptor3.MacroRaptor(vba_code_all_modules)
            m.scan()
            if m.suspicious:
                result += [{
                    'Result': 'SUSPICIOUS',
                    'Flags': str(m.get_flags()),
                    'Match_on': str(m.matches)
                }]
            else:
                result += [{ 'Result': 'Macro seems fine' }]
        except Exception:
            # Revert patched functions to originals
            optparse.OptionParser._get_args = get_args
            sys.stdout = sys.__stdout__
            raise error.CommandWarning('failed to parse macros')

        # Revert patched function to originals
        optparse.OptionParser._get_args = get_args
        sys.stdout = sys.__stdout__
        reload(oledir)
        return result

    # Table generated is good as is, why change it?
    def mraptor_markdown(self, json):
        output = ""
        if not json:
            output = "No json\n"
            return output
        for i in json:
            output += md.bold("Macro is: ") + str(i['Result']) + "\n"
            output += md.bold("Flags: ") + str(i['Flags']) + "\n"
            output += md.bold("Regexps matched on: ") + str(i['Match_on']) + "\n"
        return output

    def mraptor_plaintext(self, json):
        return json
