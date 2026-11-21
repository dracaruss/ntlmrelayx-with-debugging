# ntlmrelayx Relay Trace

Colored, plain-English diagnostics for ntlmrelayx NTLM relay attempts. Tells you exactly why a relay failed instead of making you guess from raw LDAP result codes.

Built for Impacket **v0.14.0-dev** (commit `main` as of November 2026).

## What It Does

When you run ntlmrelayx with these files in place, every relay attempt prints a step-by-step trace to your terminal showing what happened and why. You will see the captured identity, which NTLM flags were stripped, whether the client advertised channel binding, the LDAP bind result code, and the decoded Windows sub-status (SEC_E_BAD_BINDINGS, SEC_E_LOGON_DENIED, SEC_E_MESSAGE_ALTERED, etc.) with an explanation of what each one means in context.

## Files

There are three files total. One is new, and two are patched copies of upstream Impacket files with a handful of added lines each.

**relaytrace.py** is the instrumentation module. It has zero Impacket imports and only uses `sys` and `re` from the standard library, so it cannot cause version conflicts. This is the only new file.

**ldaprelayclient.py** is the upstream LDAP relay client with six added lines that call relaytrace at the right moments: after NTLM flag manipulation, after parsing the auth token identity and AV pairs, and after the LDAP bind response arrives. All upstream functionality is preserved, including the LDAP signing bypass, shadow credentials, RBCD writes, and NegoEx detection.

**smbrelayserver.py** is the upstream SMB relay server with hooks in both the SMBv2 and SMBv1 authentication paths. Each path gets an `auth_captured`, `forwarding`, and `mic_dropped` call when the AUTHENTICATE message arrives, plus a success or failure indicator after the relay completes. All upstream functionality is preserved, including `applyReauthBypassNegotiate` and the reauth bypass system.

## Installation

Copy the three files into your Impacket source tree, replacing the two existing files and adding the new one.

```
cp relaytrace.py           /path/to/impacket/impacket/examples/ntlmrelayx/utils/relaytrace.py
cp ldaprelayclient.py      /path/to/impacket/impacket/examples/ntlmrelayx/clients/ldaprelayclient.py
cp smbrelayserver.py       /path/to/impacket/impacket/examples/ntlmrelayx/servers/smbrelayserver.py
```

If you installed Impacket with `pip install -e .` (editable mode), the changes take effect immediately. Otherwise, reinstall with `pip install .` from the Impacket root.

Back up the originals first if you want a clean revert path.

## Usage

No new flags or options. Just run ntlmrelayx as you normally would. The trace output appears automatically alongside the standard Impacket logging.

```
ntlmrelayx.py -t ldaps://10.0.0.11 -smb2support --remove-mic
```

The trace lines are prefixed with colored tags: `[>] STEP`, `[+] OK`, `[!] WARN`, `[-] FAIL`, and `[*] INFO`. Colors work in modern terminals on both Linux and Windows. If your terminal does not support ANSI escapes, the output still works but without color.

## Reverting

Delete `relaytrace.py` and restore the two original files from your backup or from a clean Impacket checkout. No other files are modified.
