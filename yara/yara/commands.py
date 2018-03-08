import logging
import os

import yara

from snake import config
from snake import error
from snake import fields
from snake import scale
from snake.utils import markdown as md


app_log = logging.getLogger("tornado.application")  # pylint: disable=invalid-name

RULES_PATH = config.scale_configs['yara']['rules_path']


class Commands(scale.Commands):
    def check(self):

        rule_files = []

        # Check rules_path
        if not RULES_PATH or RULES_PATH == '':
            raise error.CommandError("config variable 'rules_path' not set")
        if not os.path.exists(RULES_PATH):
            raise error.CommandError("'rules_path': '{}' does not exist".format(RULES_PATH))
        if not os.listdir(RULES_PATH):
            raise error.CommandError("'rules_path': '{}' is empty".format(RULES_PATH))
        # Loop through the rules folder and append all of the yar[a] files
        for _root, _dirs, files in os.walk(RULES_PATH):
            for f in files:
                if f.endswith('.yar') or f.endswith('.yara'):
                    rule_files.append(os.path.join(RULES_PATH, f))

        # Compile each of the new yara files
        for rule_file in rule_files:
            compiled_rule = os.path.join(RULES_PATH, os.path.splitext(os.path.basename(rule_file))[0] + '.yarac')
            if not os.path.exists(compiled_rule):
                try:
                    rule = yara.compile(rule_file)
                    rule.save(compiled_rule)
                except Exception as err:  # pylint: disable=broad-except
                    # TODO: Raising a CommandWarning breaks the module load, hence hacking in app_log direct warning temporarily
                    app_log.warning('error with yara module when compiling rule: %s', err)
                    # raise CommandWarning('error with yara module when compiling rule: %s' % err)

    @scale.command({
        'info': 'show a list of the yara rule'
    })
    def rules(self, args, file, opts):
        output = []
        # Loop through the compiled rules
        for _root, _dirs, files in os.walk(RULES_PATH):
            for f in files:
                if f.endswith('.yara') or f.endswith('.yar'):
                    output += [os.path.join(RULES_PATH, f)]
        return output

    def rules_plaintext(self, json):
        return '\n'.join(json)

    @scale.command({
        'args': {
            'rule': fields.Str(required=False)
        },
        'info': 'scan a file with the available yara rules. Allows for only a single rule to be passed'
    })
    def scan(self, args, file, opts):
        # pylint: disable=too-many-locals, too-many-branches
        compiled_rule_files = []
        output = []

        if 'rule' in args and args['rule'] != '':
            rule = args['rule']
            rule = rule.strip('.yar').strip('.yara')
            rule += '.yarac'
            path = os.path.join(RULES_PATH, rule)
            if os.path.exists(path):
                compiled_rule_files.append(path)
            else:
                raise error.CommandError('rule file does not exist')
        else:
            for _root, _dirs, files in os.walk(RULES_PATH):
                for f in files:
                    if f.endswith('.yarac'):
                        compiled_rule_files.append(os.path.join(RULES_PATH, f))

        # Load each of the compiled yara files
        for compiled_rule_file in compiled_rule_files:
            try:
                rules = yara.load(compiled_rule_file)
                matches = rules.match(file.file_path)
            except Exception:  # noqa pylint: disable=broad-except
                continue

            # Skip if no rule matches
            if not matches:
                continue

            # If the rule index doesn't exist we are likely using the yara plugin and not yara-python
            if matches[0].rule is None:
                raise error.CommandWarning('incorrect yara python plugin installed')

            # Loop through each match and append to output
            for match in matches:
                try:
                    if match.rule in config.scale_configs['yara']['blacklisted_rules']:
                        continue
                except Exception:  # noqa pylint: disable=broad-except
                    continue

                # Strings matches are stored as byte arrays, and whilst they can be converted to utf-8 strings,
                # in the case of hex values these are converted to ASCII which is not the desired output.
                # e.g:
                # b'This program cannot be run in DOS mo' = 'This program cannot be run in DOS mo'
                # b'\x40\x410x42' = @A0x42

                output += [{
                    'file': str(os.path.basename(compiled_rule_file)),
                    'rule': str(match.rule),
                    'hits': [{'hit': str(x[2])[2:-1], 'offset': str(x[0])} for x in match.strings],
                    'description': str(match.meta['description']) if 'description' in match.meta else '',
                    'author': str(match.meta['author']) if 'author' in match.meta else '',
                }]

        return output

    def scan_markdown(self, json):
        output = md.table_header(['File', 'Rule', 'String', 'Offset', 'Description', 'Author'])
        for r in json:  # pylint: disable=invalid-name
            output += md.table_row([
                md.sanitize(r['file']),
                md.bold(md.sanitize(r['rule'])),
                md.code(md.sanitize(r['hits'][0]['hit'])) if r['hits'] else '',
                md.code(md.sanitize(r['hits'][0]['offset'])) if r['hits'] else '',
                md.sanitize(r['description']),
                md.sanitize(r['author'])
            ])
            for hit in r['hits'][1:]:
                output += md.table_row(('', '', md.code(md.sanitize(hit['hit'])), md.code(md.sanitize(hit['offset'])), '', ''))
        if not json:
            output += md.table_row(('-', '-', '-', '-', '-'))
        return output
