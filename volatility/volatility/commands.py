from os import path
import subprocess

from snake import config
from snake import db
from snake import error
from snake import fields
from snake import scale


class Commands(scale.Commands):  # pylint: disable=too-many-lines, too-many-public-methods
    def check(self):
        self.vol = None
        if config.scale_configs['volatility']['vol_path']:
            if path.exists(config.scale_configs['volatility']['vol_path']):
                self.vol = config.scale_configs['volatility']['vol_path']
        else:
            raise error.CommandError("binary 'vol.py' not found - 'vol_path' not set")
        if not self.vol:
            raise error.CommandError("binary 'vol.py' not found")

    def get_profile(self, file):
        document = db.file_collection.select(file.sha256_digest)
        if 'profile' not in document:
            self.imageinfo(None, file.sha256_digest)  # pylint: disable=no-value-for-parameter
            document = db.file_collection.select(file.sha256_digest)
            if 'profile' not in document:
                raise error.CommandError('Unable to automatically determine profile!')
        return document['profile']

    # Generic run a command, useful for most commands
    def run_command(self, file, args, vol_cmd):
        cmd = [self.vol, '-f', file.file_path, '%s' % (vol_cmd)]
        if 'profile' in args and args['profile'] != '':
            cmd += ['--profile', args['profile']]
        else:
            profile = self.get_profile(file)
            cmd += ['--profile', profile]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise error.CommandError(proc.stderr)
        return str(proc.stdout, encoding="utf-8")

    @scale.command({
        'args': {
            'hive_offset': fields.Str(required=True),
            'profile': fields.Str(required=False)
        },
        'info': 'prints out a hive'
    })
    def hivedump(self, args, file, opts):
        cmd = [self.vol, '-f', file.file_path, 'hivedump', '--hive-offset', '%s' % (args['hive_offset'])]
        if 'profile' in args and args['profile'] != '':
            cmd += ['--profile', args['profile']]
        else:
            profile = self.get_profile(file)
            cmd += ['--profile', profile]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise error.CommandError(proc.stderr)
        return {'hivedump': str(proc.stdout, encoding="utf-8")}

    def hivedump_plaintext(self, json):
        return json['hivedump']

    @scale.command({
        'info': 'search for and dump potential KDBG values'
    })
    def kdbgscan(self, args, file, opts):
        proc = subprocess.run([self.vol, '-f', file.file_path, 'kdbgscan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise error.CommandError(proc.stderr)
        return {'kdbgscan': str(proc.stdout, encoding="utf-8")}

    def kdbgscan_plaintext(self, json):
        return json['kdbgscan']

    @scale.autorun
    @scale.command({
        'info': 'identify information for the image'
    })
    def imageinfo(self, args, file, opts):
        proc = subprocess.run([self.vol, '-f', file.file_path, 'imageinfo'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise error.CommandError(proc.stderr)
        output = str(proc.stdout, encoding="utf-8")

        # Try and extract profile
        try:
            prof = output.split('\n')[0].split(':')[1]
            if 'suggestion' not in prof:
                if ',' in prof:
                    prof = prof.split(',')[0]
                data = {'profile': prof.strip()}
                if not db.file_collection.update(file.sha256_digest, data):
                    raise error.MongoError('Error adding profile into file document %s' % file.sha256_digest)
        except Exception:  # noqa pylint: disable=broad-except
            pass

        return {'imageinfo': output}

    def imageinfo_plaintext(self, json):
        return json['imageinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print AmCache information'
    })
    def amcache(self, args, file, opts):
        return {'amcache': self.run_command(file, args, 'amcache')}

    def amcache_plaintext(self, json):
        return json['amcache']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'detect API hooks in process and kernel memory'
    })
    def apihooks(self, args, file, opts):
        return {'apihooks': self.run_command(file, args, 'apihooks')}

    def apihooks_plaintext(self, json):
        return json['apihooks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print session and window station atom tables'
    })
    def atoms(self, args, file, opts):
        return {'atoms': self.run_command(file, args, 'atoms')}

    def atoms_plaintext(self, json):
        return json['atoms']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for atom tables'
    })
    def atomscan(self, args, file, opts):
        return {'atomscan': self.run_command(file, args, 'atomscan')}

    def atomscan_plaintext(self, json):
        return json['atomscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': r'prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv'
    })
    def auditpol(self, args, file, opts):
        return {'auditpol': self.run_command(file, args, 'auditpol')}

    def auditpol_plaintext(self, json):
        return json['auditpol']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump the big page pools using BigPagePoolScanner'
    })
    def bigpools(self, args, file, opts):
        return {'bigpools': self.run_command(file, args, 'bigpools')}

    def bigpools_plaintext(self, json):
        return json['bigpools']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'reads the keyboard buffer from Real Mode memory'
    })
    def bioskbd(self, args, file, opts):
        return {'bioskbd': self.run_command(file, args, 'bioskbd')}

    def bioskbd_plaintext(self, json):
        return json['bioskbd']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dumps cached domain hashes from memory'
    })
    def cachedump(self, args, file, opts):
        return {'cachedump': self.run_command(file, args, 'cachedump')}

    def cachedump_plaintext(self, json):
        return json['cachedump']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print system-wide notification routines'
    })
    def callbacks(self, args, file, opts):
        return {'callbacks': self.run_command(file, args, 'callbacks')}

    def callbacks_plaintext(self, json):
        return json['callbacks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'extract the contents of the windows clipboard'
    })
    def clipboard(self, args, file, opts):
        return {'clipboard': self.run_command(file, args, 'clipboard')}

    def clipboard_plaintext(self, json):
        return json['clipboard']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'display process command-line arguments'
    })
    def cmdline(self, args, file, opts):
        return {'cmdline': self.run_command(file, args, 'cmdline')}

    def cmdline_plaintext(self, json):
        return json['cmdline']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'extract command history by scanning for _COMMAND_HISTORY'
    })
    def cmdscan(self, args, file, opts):
        return {'cmdscan': self.run_command(file, args, 'cmdscan')}

    def cmdscan_plaintext(self, json):
        return json['cmdscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of open connections [Windows XP and 2003 Only]'
    })
    def connections(self, args, file, opts):
        return {'connections': self.run_command(file, args, 'connections')}

    def connections_plaintext(self, json):
        return json['connections']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for tcp connections'
    })
    def connscan(self, args, file, opts):
        return {'connscan': self.run_command(file, args, 'connscan')}

    def connscan_plaintext(self, json):
        return json['connscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'extract command history by scanning for _CONSOLE_INFORMATION'
    })
    def consoles(self, args, file, opts):
        return {'consoles': self.run_command(file, args, 'consoles')}

    def consoles_plaintext(self, json):
        return json['consoles']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump crash-dump information'
    })
    def crashinfo(self, args, file, opts):
        return {'crashinfo': self.run_command(file, args, 'crashinfo')}

    def crashinfo_plaintext(self, json):
        return json['crashinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'poolscaner for tagDESKTOP (desktops)'
    })
    def deskscan(self, args, file, opts):
        return {'deskscan': self.run_command(file, args, 'deskscan')}

    def deskscan_plaintext(self, json):
        return json['deskscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'show device tree'
    })
    def devicetree(self, args, file, opts):
        return {'devicetree': self.run_command(file, args, 'devicetree')}

    def devicetree_plaintext(self, json):
        return json['devicetree']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of loaded dlls for each process'
    })
    def dlllist(self, args, file, opts):
        return {'dlllist': self.run_command(file, args, 'dlllist')}

    def dlllist_plaintext(self, json):
        return json['dlllist']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'driver IRP hook detection'
    })
    def driverirp(self, args, file, opts):
        return {'driverirp': self.run_command(file, args, 'driverirp')}

    def driverirp_plaintext(self, json):
        return json['driverirp']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'associate driver objects to kernel modules'
    })
    def drivermodule(self, args, file, opts):
        return {'drivermodule': self.run_command(file, args, 'drivermodule')}

    def drivermodule_plaintext(self, json):
        return json['drivermodule']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for driver objects'
    })
    def driverscan(self, args, file, opts):
        return {'driverscan': self.run_command(file, args, 'driverscan')}

    def driverscan_plaintext(self, json):
        return json['driverscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump RSA private and public SSL keys'
    })
    def dumpcerts(self, args, file, opts):
        return {'dumpcerts': self.run_command(file, args, 'dumpcerts')}

    def dumpcerts_plaintext(self, json):
        return json['dumpcerts']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'displays information about Edit controls. (Listbox experimental.)'
    })
    def editbox(self, args, file, opts):
        return {'editbox': self.run_command(file, args, 'editbox')}

    def editbox_plaintext(self, json):
        return json['editbox']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'display process environment variables'
    })
    def envars(self, args, file, opts):
        return {'envars': self.run_command(file, args, 'envars')}

    def envars_plaintext(self, json):
        return json['envars']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print details on windows event hooks'
    })
    def eventhooks(self, args, file, opts):
        return {'eventhooks': self.run_command(file, args, 'eventhooks')}

    def eventhooks_plaintext(self, json):
        return json['eventhooks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'extract Windows Event Logs (XP/2003 only)'
    })
    def evtlogs(self, args, file, opts):
        return {'evtlogs': self.run_command(file, args, 'evtlogs')}

    def evtlogs_plaintext(self, json):
        return json['evtlogs']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for file objects'
    })
    def filescan(self, args, file, opts):
        return {'filescan': self.run_command(file, args, 'filescan')}

    def filescan_plaintext(self, json):
        return json['filescan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump the USER handle type information'
    })
    def gahti(self, args, file, opts):
        return {'gahti': self.run_command(file, args, 'gahti')}

    def gahti_plaintext(self, json):
        return json['gahti']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print installed GDI timers and callbacks'
    })
    def gditimers(self, args, file, opts):
        return {'gditimers': self.run_command(file, args, 'gditimers')}

    def gditimers_plaintext(self, json):
        return json['gditimers']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'display Global Descriptor Table'
    })
    def gdt(self, args, file, opts):
        return {'gdt': self.run_command(file, args, 'gdt')}

    def gdt_plaintext(self, json):
        return json['gdt']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'get the names of services in the Registry and return Calculated SID'
    })
    def getservicesids(self, args, file, opts):
        return {'getservicesids': self.run_command(file, args, 'getservicesids')}

    def getservicesids_plaintext(self, json):
        return json['getservicesids']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print the SIDs owning each process'
    })
    def getsids(self, args, file, opts):
        return {'getsids': self.run_command(file, args, 'getsids')}

    def getsids_plaintext(self, json):
        return json['getsids']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of open handles for each process'
    })
    def handles(self, args, file, opts):
        return {'handles': self.run_command(file, args, 'handles')}

    def handles_plaintext(self, json):
        return json['handles']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dumps passwords hashes (LM/NTLM) from memory'
    })
    def hashdump(self, args, file, opts):
        return {'hashdump': self.run_command(file, args, 'hashdump')}

    def hashdump_plaintext(self, json):
        return json['hashdump']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump hibernation file information'
    })
    def hibinfo(self, args, file, opts):
        return {'hibinfo': self.run_command(file, args, 'hibinfo')}

    def hibinfo_plaintext(self, json):
        return json['hibinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of registry hives'
    })
    def hivelist(self, args, file, opts):
        return {'hivelist': self.run_command(file, args, 'hivelist')}

    def hivelist_plaintext(self, json):
        return json['hivelist']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for registry hives'
    })
    def hivescan(self, args, file, opts):
        return {'hivescan': self.run_command(file, args, 'hivescan')}

    def hivescan_plaintext(self, json):
        return json['hivescan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'display Interrupt Descriptor Table'
    })
    def idt(self, args, file, opts):
        return {'idt': self.run_command(file, args, 'idt')}

    def idt_plaintext(self, json):
        return json['idt']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'reconstruct Internet Explorer cache / history'
    })
    def iehistory(self, args, file, opts):
        return {'iehistory': self.run_command(file, args, 'iehistory')}

    def iehistory_plaintext(self, json):
        return json['iehistory']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan for calls to imported functions'
    })
    def impscan(self, args, file, opts):
        return {'impscan': self.run_command(file, args, 'impscan')}

    def impscan_plaintext(self, json):
        return json['impscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print process job link information'
    })
    def joblinks(self, args, file, opts):
        return {'joblinks': self.run_command(file, args, 'joblinks')}

    def joblinks_plaintext(self, json):
        return json['joblinks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'search for and dump potential KPCR values'
    })
    def kpcrscan(self, args, file, opts):
        return {'kpcrscan': self.run_command(file, args, 'kpcrscan')}

    def kpcrscan_plaintext(self, json):
        return json['kpcrscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'detect unlinked DLLs'
    })
    def ldrmodules(self, args, file, opts):
        return {'ldrmodules': self.run_command(file, args, 'ldrmodules')}

    def ldrmodules_plaintext(self, json):
        return json['ldrmodules']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump (decrypted) LSA secrets from the registry'
    })
    def lsadump(self, args, file, opts):
        return {'lsadump': self.run_command(file, args, 'lsadump')}

    def lsadump_plaintext(self, json):
        return json['lsadump']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump Mach-O file format information'
    })
    def machoinfo(self, args, file, opts):
        return {'machoinfo': self.run_command(file, args, 'machoinfo')}

    def machoinfo_plaintext(self, json):
        return json['machoinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'find hidden and injected code'
    })
    def malfind(self, args, file, opts):
        return {'malfind': self.run_command(file, args, 'malfind')}

    def malfind_plaintext(self, json):
        return json['malfind']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scans for and parses potential Master Boot Records (MBRs)'
    })
    def mbrparser(self, args, file, opts):
        return {'mbrparser': self.run_command(file, args, 'mbrparser')}

    def mbrparser_plaintext(self, json):
        return json['mbrparser']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print the memory map'
    })
    def memmap(self, args, file, opts):
        return {'memmap': self.run_command(file, args, 'memmap')}

    def memmap_plaintext(self, json):
        return json['memmap']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'list desktop and thread window message hooks'
    })
    def messagehooks(self, args, file, opts):
        return {'messagehooks': self.run_command(file, args, 'messagehooks')}

    def messagehooks_plaintext(self, json):
        return json['messagehooks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scans for and parses potential MFT entries'
    })
    def mftparser(self, args, file, opts):
        return {'mftparser': self.run_command(file, args, 'mftparser')}

    def mftparser_plaintext(self, json):
        return json['mftparser']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for kernel modules'
    })
    def modscan(self, args, file, opts):
        return {'modscan': self.run_command(file, args, 'modscan')}

    def modscan_plaintext(self, json):
        return json['modscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of loaded modules'
    })
    def modules(self, args, file, opts):
        return {'modules': self.run_command(file, args, 'modules')}

    def modules_plaintext(self, json):
        return json['modules']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for mutex objects'
    })
    def mutantscan(self, args, file, opts):
        return {'mutantscan': self.run_command(file, args, 'mutantscan')}

    def mutantscan_plaintext(self, json):
        return json['mutantscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan a vista (or later) image for connections and sockets'
    })
    def netscan(self, args, file, opts):
        return {'netscan': self.run_command(file, args, 'netscan')}

    def netscan_plaintext(self, json):
        return json['netscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'list currently displayed notepad text'
    })
    def notepad(self, args, file, opts):
        return {'notepad': self.run_command(file, args, 'notepad')}

    def notepad_plaintext(self, json):
        return json['notepad']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan for Windows object type objects'
    })
    def objtypescan(self, args, file, opts):
        return {'objtypescan': self.run_command(file, args, 'objtypescan')}

    def objtypescan_plaintext(self, json):
        return json['objtypescan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'display process privileges'
    })
    def privs(self, args, file, opts):
        return {'privs': self.run_command(file, args, 'privs')}

    def privs_plaintext(self, json):
        return json['privs']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print all running processes by following the EPROCESS lists'
    })
    def pslist(self, args, file, opts):
        return {'pslist': self.run_command(file, args, 'pslist')}

    def pslist_plaintext(self, json):
        return json['pslist']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for process objects'
    })
    def psscan(self, args, file, opts):
        return {'psscan': self.run_command(file, args, 'psscan')}

    def psscan_plaintext(self, json):
        return json['psscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print process list as a tree'
    })
    def pstree(self, args, file, opts):
        return {'pstree': self.run_command(file, args, 'pstree')}

    def pstree_plaintext(self, json):
        return json['pstree']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'find hidden processes with various process listings'
    })
    def psxview(self, args, file, opts):
        return {'psxview': self.run_command(file, args, 'psxview')}

    def psxview_plaintext(self, json):
        return json['psxview']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump Qemu information'
    })
    def qemuinfo(self, args, file, opts):
        return {'qemuinfo': self.run_command(file, args, 'qemuinfo')}

    def qemuinfo_plaintext(self, json):
        return json['qemuinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'list Windows services (ala Plugx)'
    })
    def servicediff(self, args, file, opts):
        return {'servicediff': self.run_command(file, args, 'servicediff')}

    def servicediff_plaintext(self, json):
        return json['servicediff']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'list details on _MM_SESSION_SPACE (user logon sessions)'
    })
    def sessions(self, args, file, opts):
        return {'sessions': self.run_command(file, args, 'sessions')}

    def sessions_plaintext(self, json):
        return json['sessions']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints ShellBags info'
    })
    def shellbags(self, args, file, opts):
        return {'shellbags': self.run_command(file, args, 'shellbags')}

    def shellbags_plaintext(self, json):
        return json['shellbags']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'parses the Application Compatibility Shim Cache registry key'
    })
    def shimcache(self, args, file, opts):
        return {'shimcache': self.run_command(file, args, 'shimcache')}

    def shimcache_plaintext(self, json):
        return json['shimcache']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print ShutdownTime of machine from registry'
    })
    def shutdowntime(self, args, file, opts):
        return {'shutdowntime': self.run_command(file, args, 'shutdowntime')}

    def shutdowntime_plaintext(self, json):
        return json['shutdowntime']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of open sockets'
    })
    def sockets(self, args, file, opts):
        return {'sockets': self.run_command(file, args, 'sockets')}

    def sockets_plaintext(self, json):
        return json['sockets']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for tcp socket objects'
    })
    def sockscan(self, args, file, opts):
        return {'sockscan': self.run_command(file, args, 'sockscan')}

    def sockscan_plaintext(self, json):
        return json['sockscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'display SSDT entries'
    })
    def ssdt(self, args, file, opts):
        return {'ssdt': self.run_command(file, args, 'ssdt')}

    def ssdt_plaintext(self, json):
        return json['ssdt']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan for Windows services'
    })
    def svcscan(self, args, file, opts):
        return {'svcscan': self.run_command(file, args, 'svcscan')}

    def svcscan_plaintext(self, json):
        return json['svcscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for symlink objects'
    })
    def symlinkscan(self, args, file, opts):
        return {'symlinkscan': self.run_command(file, args, 'symlinkscan')}

    def symlinkscan_plaintext(self, json):
        return json['symlinkscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for thread objects'
    })
    def thrdscan(self, args, file, opts):
        return {'thrdscan': self.run_command(file, args, 'thrdscan')}

    def thrdscan_plaintext(self, json):
        return json['thrdscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'investigate _ETHREAD and _KTHREADs'
    })
    def threads(self, args, file, opts):
        return {'threads': self.run_command(file, args, 'threads')}

    def threads_plaintext(self, json):
        return json['threads']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print kernel timers and associated module DPCs'
    })
    def timers(self, args, file, opts):
        return {'timers': self.run_command(file, args, 'timers')}

    def timers_plaintext(self, json):
        return json['timers']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'recover TrueCrypt 7.1a Master Keys'
    })
    def truecryptmaster(self, args, file, opts):
        return {'truecryptmaster': self.run_command(file, args, 'truecryptmaster')}

    def truecryptmaster_plaintext(self, json):
        return json['truecryptmaster']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'TrueCrypt Cached Passphrase Finder'
    })
    def truecryptpassphrase(self, args, file, opts):
        return {'truecryptpassphrase': self.run_command(file, args, 'truecryptpassphrase')}

    def truecryptpassphrase_plaintext(self, json):
        return json['truecryptpassphrase']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'TrueCrypt Summary'
    })
    def truecryptsummary(self, args, file, opts):
        return {'truecryptsummary': self.run_command(file, args, 'truecryptsummary')}

    def truecryptsummary_plaintext(self, json):
        return json['truecryptsummary']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of unloaded modules'
    })
    def unloadedmodules(self, args, file, opts):
        return {'unloadedmodules': self.run_command(file, args, 'unloadedmodules')}

    def unloadedmodules_plaintext(self, json):
        return json['unloadedmodules']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print userassist registry keys and information'
    })
    def userassist(self, args, file, opts):
        return {'userassist': self.run_command(file, args, 'userassist')}

    def userassist_plaintext(self, json):
        return json['userassist']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump the USER handle tables'
    })
    def userhandles(self, args, file, opts):
        return {'userhandles': self.run_command(file, args, 'userhandles')}

    def userhandles_plaintext(self, json):
        return json['userhandles']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump the VAD info'
    })
    def vadinfo(self, args, file, opts):
        return {'vadinfo': self.run_command(file, args, 'vadinfo')}

    def vadinfo_plaintext(self, json):
        return json['vadinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'walk the VAD tree and display in tree format'
    })
    def vadtree(self, args, file, opts):
        return {'vadtree': self.run_command(file, args, 'vadtree')}

    def vadtree_plaintext(self, json):
        return json['vadtree']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'walk the VAD tree'
    })
    def vadwalk(self, args, file, opts):
        return {'vadwalk': self.run_command(file, args, 'vadwalk')}

    def vadwalk_plaintext(self, json):
        return json['vadwalk']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump virtualbox information'
    })
    def vboxinfo(self, args, file, opts):
        return {'vboxinfo': self.run_command(file, args, 'vboxinfo')}

    def vboxinfo_plaintext(self, json):
        return json['vboxinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints out the version information from PE images'
    })
    def verinfo(self, args, file, opts):
        return {'verinfo': self.run_command(file, args, 'verinfo')}

    def verinfo_plaintext(self, json):
        return json['verinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump VMware VMSS/VMSN information'
    })
    def vmwareinfo(self, args, file, opts):
        return {'vmwareinfo': self.run_command(file, args, 'vmwareinfo')}

    def vmwareinfo_plaintext(self, json):
        return json['vmwareinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print Desktop Windows (verbose details)'
    })
    def windows(self, args, file, opts):
        return {'windows': self.run_command(file, args, 'windows')}

    def windows_plaintext(self, json):
        return json['windows']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print Z-Order Desktop Windows Tree'
    })
    def wintree(self, args, file, opts):
        return {'wintree': self.run_command(file, args, 'wintree')}

    def wintree_plaintext(self, json):
        return json['wintree']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'pool scanner for window stations'
    })
    def wndscan(self, args, file, opts):
        return {'wndscan': self.run_command(file, args, 'wndscan')}

    def wndscan_plaintext(self, json):
        return json['wndscan']
