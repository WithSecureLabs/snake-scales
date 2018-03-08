import logging
from os import path
import subprocess

from snake import config
from snake import error
from snake import scale


# TODO: THis is horendous as we have all noted!
# FIXME: Find python 3 alternatives!!!


app_log = logging.getLogger("tornado.application")  # pylint: disable=invalid-name


PDF_PARSER_PATH = config.scale_configs['pdf']['pdf_parser_path']
PDFID_PATH = config.scale_configs['pdf']['pdfid_path']
PEEPDF_PATH = config.scale_configs['pdf']['peepdf_path']

if PDF_PARSER_PATH and path.isfile(PDF_PARSER_PATH):
    has_pdf_parser = True  # pylint: disable=invalid-name
else:
    if PDF_PARSER_PATH:
        app_log.warning("pdf - pdf-parser disabled - optional dependencies not met: 'pdf-parser' not found")
    else:
        app_log.warning("pdf - pdf-parser disabled - optional dependencies not met: 'pdf_parser_path' not set")
    has_pdf_parser = False  # pylint: disable=invalid-name

if PDFID_PATH and path.isfile(PDFID_PATH):
    has_pdfid = True  # pylint: disable=invalid-name
else:
    if PDFID_PATH:
        app_log.warning("pdf - pdf-parser disabled - optional dependencies not met: 'pdfid' not found")
    else:
        app_log.warning("pdf - pdf-parser disabled - optional dependencies not met: 'pdfid_path' not set")
    has_pdfid = False  # pylint: disable=invalid-name

if PEEPDF_PATH and path.isfile(PEEPDF_PATH):
    has_peepdf = True  # pylint: disable=invalid-name
else:
    if PEEPDF_PATH:
        app_log.warning("pdf - pdf-parser disabled - optional dependencies not met: 'peepdf' not found")
    else:
        app_log.warning("pdf - pdf-parser disabled - optional dependencies not met: 'peepdf_path' not set")
    has_peepdf = False  # pylint: disable=invalid-name

if not (has_pdf_parser or has_pdfid or has_peepdf):
    raise error.CommandError("no supported pdf tools installed")


class Commands(scale.Commands):
    def check(self):
        pass

    if has_pdfid:
        @scale.command({
            'info': 'parse the file with pdfid'
        })
        def pdfid(self, args, file, opts):
            try:
                proc = subprocess.run(["python2", PDFID_PATH, file.file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as err:
                raise error.CommandWarning("an unknown error occurred when running pdfid: %s" % err)

            output = str(proc.stdout, encoding='utf-8')
            if "Not a PDF document" in output:
                raise error.CommandWarning('file is not a pdf document')
            return {'data': output}

        def pdfid_plaintext(self, json):
            return json['data']

    if has_pdf_parser:
        @scale.command({
            'info': 'parse the file with pdfparser'
        })
        def pdfparser(self, args, file, opts):
            if not str(file.magic).startswith('PDF'):
                raise error.CommandWarning('file is not a pdf document')

            try:
                proc = subprocess.run(["python2", PDF_PARSER_PATH, file.file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as err:
                raise error.CommandWarning("an unknown error occurred when running pdfparser: %s" % err)

            return {'data': str(proc.stdout, encoding='utf-8')}

        def pdfparser_plaintext(self, json):
            return json['data']

    if has_peepdf:
        @scale.command({
            'info': 'parse the file with peepdf'
        })
        def peepdf(self, args, file, opts):
            # TODO: Additional requirements are required for peepdf for further functionality
            if not str(file.magic).startswith('PDF'):
                raise error.CommandWarning('file is not a pdf document')

            try:
                proc = subprocess.run(["python2", PEEPDF_PATH, file.file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception as err:
                raise error.CommandWarning("an unknown error occurred when running peepdf: %s" % err)

            return {'data': str(proc.stdout, encoding='utf-8')}

        def peepdf_plaintext(self, json):
            return json['data']
