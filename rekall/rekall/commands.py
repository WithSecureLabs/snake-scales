from os import environ
import shutil
import subprocess

from snake import config
from snake import error
from snake import fields
from snake import scale


#  pylint: disable=invalid-name


class Commands(scale.Commands):  # pylint: disable=too-many-lines, too-many-public-methods
    def check(self):
        if not shutil.which('rekall'):
            raise error.CommandError("binary 'rekall' not found")

    # Generic run a command, useful for most commands
    def run_command(self, file, args, vol_cmd):
        if isinstance(vol_cmd, list):
            cmd = ['rekall', '-f', file.file_path]
            cmd += vol_cmd
        else:
            cmd = ['rekall', '-f', file.file_path, '%s' % (vol_cmd)]
        if config.scale_configs['rekall']['repository_path']:
            cmd += ['--repository_path', config.scale_configs['rekall']['repository_path']]
        if config.scale_configs['rekall']['cache_dir']:
            cmd += ['--cache_dir', config.scale_configs['rekall']['cache_dir']]
        env = environ.copy()
        if 'http_proxy' in config.snake_config.keys():
            env['http_proxy'] = config.snake_config['http_proxy']
            env['HTTP_PROXY'] = config.snake_config['http_proxy']
            env['https_proxy'] = config.snake_config['https_proxy']
            env['HTTPS_PROXY'] = config.snake_config['https_proxy']
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if proc.returncode != 0:
            raise error.CommandError(proc.stderr)
        return str(proc.stdout, encoding="utf-8")

    @scale.command({
        'args': {
            'hive_offset': fields.Str(required=True),
        },
        'info': 'prints out a hive'
    })
    def hivedump(self, args, file, opts):
        cmd = ['rekall', '-f', file.file_path, 'hivedump', '--hive-offset', '%s' % (args['hive_offset'])]
        if config.scale_configs['rekall']['repository_path']:
            cmd += ['--repository_path', config.scale_configs['rekall']['repository_path']]
        if config.scale_configs['rekall']['cache_dir']:
            cmd += ['--cache_dir', config.scale_configs['rekall']['cache_dir']]
        env = environ.copy()
        if 'http_proxy' in config.snake_config.keys():
            env['http_proxy'] = config.snake_config['http_proxy']
            env['HTTP_PROXY'] = config.snake_config['http_proxy']
            env['https_proxy'] = config.snake_config['https_proxy']
            env['HTTPS_PROXY'] = config.snake_config['https_proxy']
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if proc.returncode != 0:
            raise error.CommandError(proc.stderr)
        return {'hivedump': str(proc.stdout, encoding="utf-8")}

    def hivedump_plaintext(self, json):
        return json['hivedump']

    @scale.command({
        'info': 'scan for possible _KDDEBUGGER_DATA64 structures'
    })
    def kdbgscan(self, args, file, opts):
        return {'kdbgscan': self.run_command(file, args, 'kdbgscan')}

    def kdbgscan_plaintext(self, json):
        return json['kdbgscan']

    @scale.command({
        'info': 'list overview information about this image'
    })
    def imageinfo(self, args, file, opts):
        return {'imageinfo': self.run_command(file, args, 'imageinfo')}

    def imageinfo_plaintext(self, json):
        return json['imageinfo']

    @scale.command({
        'args': {
            'offset': fields.Str(required=True),
            'profile': fields.Str(required=False)
        },
        'info': 'a plugin to analyze a memory location'
    })
    def analyze_struct(self, args, file, opts):
        return {'analyze_struct': self.run_command(file, args, 'analyze_struct')}

    def analyze_struct_plaintext(self, json):
        return json['analyze_struct']

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
        'info': 'pool scanner for _RTL_ATOM_TABLE'
    })
    def atomscan(self, args, file, opts):
        return {'atomscan': self.run_command(file, args, 'atomscan')}

    def atomscan_plaintext(self, json):
        return json['atomscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'enumerate callback routines'
    })
    def callbacks(self, args, file, opts):
        return {'callback': self.run_command(file, args, 'callbacks')}

    def callbacks_plaintext(self, json):
        return json['callback']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'a cc plugin for windows'
    })
    def cc(self, args, file, opts):
        return {'cc': self.run_command(file, args, 'cc')}

    def cc_plaintext(self, json):
        return json['cc']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'checks a pe file mapped into memory for hooks'
    })
    def check_pehooks(self, args, file, opts):
        return {'check_pehook': self.run_command(file, args, 'check_pehooks')}

    def check_pehooks_plaintext(self, json):
        return json['check_pehooks']

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
        return {'connection': self.run_command(file, args, 'connections')}

    def connections_plaintext(self, json):
        return json['connection']

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
        'info': 'enumerate command consoles'
    })
    def consoles(self, args, file, opts):
        return {'consoles': self.run_command(file, args, 'consoles')}

    def consoles_plaintext(self, json):
        return json['consoles']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print information on each desktop'
    })
    def desktops(self, args, file, opts):
        return {'desktops': self.run_command(file, args, 'desktops')}

    def desktops_plaintext(self, json):
        return json['desktops']

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
            'offset': fields.Str(required=False),
            'profile': fields.Str(required=False)
        },
        'info': 'disassemble the given offset'
    })
    def dis(self, args, file, opts):
        return {'dis': self.run_command(file, args, 'dis')}

    def dis_plaintext(self, json):
        return json['dis']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints a list of dll modules mapped into each process'
    })
    def dlllist(self, args, file, opts):
        return {'dlllist': self.run_command(file, args, 'dlllist')}

    def dlllist_plaintext(self, json):
        return json['dlllist']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump the windows DNS resolver cache'
    })
    def dns_cache(self, args, file, opts):
        return {'dns_cache': self.run_command(file, args, 'dns_cache')}

    def dns_cache_plaintext(self, json):
        return json['dns_cache']

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
        'info': 'scan for driver objects _DRIVER_OBJECT'
    })
    def driverscan(self, args, file, opts):
        return {'driverscan': self.run_command(file, args, 'driverscan')}

    def driverscan_plaintext(self, json):
        return json['driverscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scans the physical memory for DTB values'
    })
    def dtbscan(self, args, file, opts):
        return {'dtbscan': self.run_command(file, args, 'dtbscan')}

    def dtbscan_plaintext(self, json):
        return json['dtbscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print details on windows event hooks'
    })
    def eventhooks(self, args, file, opts):
        return {'eventhook': self.run_command(file, args, 'eventhooks')}

    def eventhooks_plaintext(self, json):
        return json['eventhooks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'extract Windows Event Logs (XP/2003 only)'
    })
    def evtlogs(self, args, file, opts):
        return {'evtlog': self.run_command(file, args, 'evtlogs')}

    def evtlogs_plaintext(self, json):
        return json['evtlogs']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan Physical memory for _FILE_OBJECT pool allocations'
    })
    def filescan(self, args, file, opts):
        return {'filescan': self.run_command(file, args, 'filescan')}

    def filescan_plaintext(self, json):
        return json['filescan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'a plugin to search for the Directory Table Base for windows system'
    })
    def find_dtb(self, args, file, opts):
        return {'find_dtb': self.run_command(file, args, 'find_dtb')}

    def find_dtb_plaintext(self, json):
        return json['find_dtb']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'none'
    })
    def fls(self, args, file, opts):
        return {'fls': self.run_command(file, args, 'fls')}

    def fls_plaintext(self, json):
        return json['fls']

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
        'info': 'get the names of services in the Registry and return Calculated SID'
    })
    def getservicesids(self, args, file, opts):
        return {'getservicesid': self.run_command(file, args, 'getservicesids')}

    def getservicesids_plaintext(self, json):
        return json['getservicesids']

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
        'info': 'print list of registry hives on the system'
    })
    def hives(self, args, file, opts):
        return {'hives': self.run_command(file, args, 'hives')}

    def hives_plaintext(self, json):
        return json['hives']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'detect EAT hooks in process and kernel memory'
    })
    def hooks_eat(self, args, file, opts):
        return {'hooks_eat': self.run_command(file, args, 'hooks_eat')}

    def hooks_eat_plaintext(self, json):
        return json['hooks_eat']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'detect IAT/EAT hooks in process and kernel memory'
    })
    def hooks_iat(self, args, file, opts):
        return {'hooks_iat': self.run_command(file, args, 'hooks_iat')}

    def hooks_iat_plaintext(self, json):
        return json['hooks_iat']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'detect API hooks in process and kernel memory'
    })
    def hooks_inline(self, args, file, opts):
        return self.run_command(file, args, 'hooks_inline')

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
        'info': 'a plugin to print all KPCR blocks'
    })
    def kpcr(self, args, file, opts):
        return {'kpcr': self.run_command(file, args, 'kpcr')}

    def kpcr_plaintext(self, json):
        return json['kpcr']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'detect unlinked DLLs'
    })
    def ldrmodules(self, args, file, opts):
        return {'ldrmodule': self.run_command(file, args, 'ldrmodules')}

    def ldrmodules_plaintext(self, json):
        return json['ldrmodules']

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
        'info': 'calculates the memory regions mapped by a process'
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
        return {'messagehook': self.run_command(file, args, 'messagehooks')}

    def messagehooks_plaintext(self, json):
        return json['messagehooks']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'extract and decrypt passwords from the LSA Security Service'
    })
    def mimikatz(self, args, file, opts):
        return {'mimikatz': self.run_command(file, args, 'mimikatz')}

    def mimikatz_plaintext(self, json):
        return json['mimikatz']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan Physical memory for _LDR_DATA_TABLE_ENTRY objects'
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
        'info': 'scan for mutant objects _KMUTANT'
    })
    def mutantscan(self, args, file, opts):
        return {'mutantscan': self.run_command(file, args, 'mutantscan')}

    def mutantscan_plaintext(self, json):
        return json['mutantscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan a Vista, 2008 or Windows 7 image for connections and sockets'
    })
    def netscan(self, args, file, opts):
        return {'netscan': self.run_command(file, args, 'netscan')}

    def netscan_plaintext(self, json):
        return json['netscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print the active network connections'
    })
    def netstat(self, args, file, opts):
        return {'netstat': self.run_command(file, args, 'netstat')}

    def netstat_plaintext(self, json):
        return json['netstat']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'visualize the kernel object tree'
    })
    def object_tree(self, args, file, opts):
        return {'object_tree': self.run_command(file, args, 'object_tree')}

    def object_tree_plaintext(self, json):
        return json['object_tree']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'displays all object Types on the system'
    })
    def object_types(self, args, file, opts):
        return {'object_types': self.run_command(file, args, 'object_types')}

    def object_types_plaintext(self, json):
        return json['object_types']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'report all the active pagefiles'
    })
    def pagefiles(self, args, file, opts):
        return {'pagefiles': self.run_command(file, args, 'pagefiles')}

    def pagefiles_plaintext(self, json):
        return json['pagefiles']

    @scale.command({
        'args': {
            'offset': fields.Str(required=True),
            'profile': fields.Str(required=False)
        },
        'info': 'resolves a physical address to a virtual addrress in a process'
    })
    def pas2vas(self, args, file, opts):
        return {'pas2vas': self.run_command(file, args, 'pas2vas')}

    def pas2vas_plaintext(self, json):
        return json['pas2vas']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print information about a PE binary'
    })
    def peinfo(self, args, file, opts):
        return {'peinfo': self.run_command(file, args, 'peinfo')}

    def peinfo_plaintext(self, json):
        return json['peinfo']

    @scale.command({
        'args': {
            'pfn': fields.Str(required=True),
            'profile': fields.Str(required=False)
        },
        'info': 'prints information about an address from the PFN database'
    })
    def pfn(self, args, file, opts):
        return {'pfn': self.run_command(file, args, 'pfn')}

    def pfn_plaintext(self, json):
        return json['pfn']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints the boot physical memory map'
    })
    def phys_map(self, args, file, opts):
        return {'phys_map': self.run_command(file, args, 'phys_map')}

    def phys_map_plaintext(self, json):
        return json['phys_map']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'enumerate pool tag usage statistics'
    })
    def pool_tracker(self, args, file, opts):
        return {'pool_tracker': self.run_command(file, args, 'pool_tracker')}

    def pool_tracker_plaintext(self, json):
        return json['pool_tracker']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints information about system pools'
    })
    def pools(self, args, file, opts):
        return {'pools': self.run_command(file, args, 'pools')}

    def pools_plaintext(self, json):
        return json['pools']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print a registry key, and its subkeys and values'
    })
    def printkey(self, args, file, opts):
        return {'printkey': self.run_command(file, args, 'printkey')}

    def printkey_plaintext(self, json):
        return json['printkey']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints process privileges'
    })
    def privileges(self, args, file, opts):
        return {'privileges': self.run_command(file, args, 'privileges')}

    def privileges_plaintext(self, json):
        return json['privileges']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'dump detailed information about a running process'
    })
    def procinfo(self, args, file, opts):
        return {'procinfo': self.run_command(file, args, 'procinfo')}

    def procinfo_plaintext(self, json):
        return json['procinfo']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'list processes for windows'
    })
    def pslist(self, args, file, opts):
        return {'pslist': self.run_command(file, args, 'pslist')}

    def pslist_plaintext(self, json):
        return json['pslist']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan Physical memory for _EPROCESS pool allocations'
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
            'offset': fields.Str(required=True),
            'profile': fields.Str(required=False)
        },
        'info': 'converts a physical address to a virtual address'
    })
    def ptov(self, args, file, opts):
        return {'ptov': self.run_command(file, args, 'psxview')}

    def ptov_plaintext(self, json):
        return json['ptov']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan all physical memory and report page owners'
    })
    def rammap(self, args, file, opts):
        return {'rammap': self.run_command(file, args, 'rammap')}

    def rammap_plaintext(self, json):
        return json['rammap']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'enumerate all services'
    })
    def services(self, args, file, opts):
        return {'services': self.run_command(file, args, 'services')}

    def services_plaintext(self, json):
        return json['services']

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
        'info': 'dump RSA private and public SSL keys from the physical address space'
    })
    def simple_certscan(self, args, file, opts):
        return {'simple_certscan': self.run_command(file, args, 'simple_certscan')}

    def simple_certscan_plaintext(self, json):
        return json['simple_certscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of open sockets [Windows XP only]'
    })
    def sockets(self, args, file, opts):
        return {'sockets': self.run_command(file, args, 'sockets')}

    def sockets_plaintext(self, json):
        return json['sockets']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'enumerate the SSDT'
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
        'info': 'scan for symbolic link objects'
    })
    def symlinkscan(self, args, file, opts):
        return {'symlinkscan': self.run_command(file, args, 'symlinkscan')}

    def symlinkscan_plaintext(self, json):
        return json['symlinkscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'scan physical memory for _ETHREAD objects'
    })
    def thrdscan(self, args, file, opts):
        return {'thrdscan': self.run_command(file, args, 'thrdscan')}

    def thrdscan_plaintext(self, json):
        return json['thrdscan']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'enumerate threads'
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
        'info': 'return current time, as known to the kernel'
    })
    def times(self, args, file, opts):
        return {'times': self.run_command(file, args, 'times')}

    def times_plaintext(self, json):
        return json['times']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print the SIDs owning each process token'
    })
    def tokens(self, args, file, opts):
        return {'tokens': self.run_command(file, args, 'tokens')}

    def tokens_plaintext(self, json):
        return json['tokens']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'print list of recently unloaded modules'
    })
    def unloaded_modules(self, args, file, opts):
        return {'unloaded_modules': self.run_command(file, args, 'unloaded_modules')}

    def unloaded_modules_plaintext(self, json):
        return json['unloaded_modules']

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
        'info': 'enumerate all users of this system'
    })
    def users(self, args, file, opts):
        return {'users': self.run_command(file, args, 'users')}

    def users_plaintext(self, json):
        return json['users']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'enumerate all blocks cached in the cache manager'
    })
    def vacbs(self, args, file, opts):
        return {'vacbs': self.run_command(file, args, 'vacbs')}

    def vacbs_plaintext(self, json):
        return json['vacbs']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'concise dump of the VAD'
    })
    def vad(self, args, file, opts):
        return {'vad': self.run_command(file, args, 'vad')}

    def vad_plaintext(self, json):
        return json['vad']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'inspect each page in the VAD and report its status'
    })
    def vadmap(self, args, file, opts):
        return {'vadmap': self.run_command(file, args, 'vadmap')}

    def vadmap_plaintext(self, json):
        return json['vadmap']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'try to determine the versions for all kernel drivers'
    })
    def version_modules(self, args, file, opts):
        return {'version_modules': self.run_command(file, args, 'version_modules')}

    def version_modules_plaintext(self, json):
        return json['version_modules']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'prints the Windows Kernel Virtual Address Map'
    })
    def virt_map(self, args, file, opts):
        return {'virt_map': self.run_command(file, args, 'virt_map')}

    def virt_map_plaintext(self, json):
        return json['virt_map']

    @scale.command({
        'args': {
            'name': fields.Str(required=True),
            'profile': fields.Str(required=False)
        },
        'info': 'prints information about the virtual to physical translation'
    })
    def vtop(self, args, file, opts):
        return {'vtop': self.run_command(file, args, 'vtop')}

    def vtop_plaintext(self, json):
        return json['vtop']

    @scale.command({
        'args': {
            'profile': fields.Str(required=False)
        },
        'info': 'automatically detect win32k struct layout'
    })
    def win32k_autodetect(self, args, file, opts):
        return {'win32k_autodetect': self.run_command(file, args, 'win32k_autodetect')}

    def win32k_autodetect_plaintext(self, json):
        return json['win32k_autodetect']
