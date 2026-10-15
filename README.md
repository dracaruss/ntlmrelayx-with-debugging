# ntlmrelayx relay tracing (relaytrace)

Plain-English, colored diagnostics for SMB to LDAP(S) relay attempts in
impacket's ntlmrelayx. It answers, per relay attempt: was the auth captured,
was the MIC dropped, were SIGN/SEAL flags stripped, was the bind accepted,
and if it was refused, WHY (the NTLM sub-status the stock tool throws away).

This is instrumentation only. It adds no attack logic and changes no behavior.


## Files you touch (3 total)

`ntlmrelayx.py` is NOT one of them. It is the script you run and it stays
unchanged. Everything below lives in the installed impacket package, under
the editable clone once you install it.

| File | Location (under the impacket package) | Action |
|------|----------------------------------------|--------|
| relaytrace.py | impacket/impacket/examples/ntlmrelayx/utils/ | ADD (new file) |
| ldaprelayclient.py | impacket/impacket/examples/ntlmrelayx/clients/ | REPLACE with edited copy |
| smbrelayserver.py | impacket/impacket/examples/ntlmrelayx/servers/ | HAND-PATCH in place |


## Fresh install into a clean venv
git clone https://github.com/fortra/impacket.git
cd impacket
python -m pip install -e .

Run from inside your impacket clone (the folder with setup.py):

    # On Windows
    python -m venv .relayz
    .\.relayz\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    python -m pip install -e .


    # On Linux
    python3 -m venv .relayz
    source .relayz/bin/activate
    python -m pip install --upgrade pip
    python -m pip install -e .

The editable install (-e) makes the clone the live code, so the files you
edit in the clone are exactly the ones that run. No copying into site-packages.

Verify:

    pip show impacket          # must NOT say 0.10.0
    ntlmrelayx.py -h           # must list --remove-sign-seal


## Placing the files
1. Copy relaytrace.py into impacket/examples/ntlmrelayx/utils/
2. Back up the original, then replace the client:
       copy impacket\examples\ntlmrelayx\clients\ldaprelayclient.py ldaprelayclient.py.bak
   then drop the edited ldaprelayclient.py over it.
3. Copy smbrelayserver.py to /home/abacode/impacket/impacket/examples/ntlmrelayx/servers/smbrelayserver.py

## The flags (what you actually pass to ntlmrelayx)

These are stock ntlmrelayx flags, not added by relaytrace. The tracing fires
regardless of which you use.

| Flag | Meaning |
|------|---------|
| -t ldaps://HOST | Relay target. Use ldaps:// for the LDAPS (636) path. |
| -smb2support | Accept SMB2/3 from the coerced client. Keep it on. |
| --remove-mic | Strip the MIC (CVE-2019-1040). Only lands on a DC UNPATCHED for the June 2019 fix. |
| --remove-sign-seal | Strip SIGN/SEAL negotiate flags (CVE-2025-33073 path). Reflection-oriented. |
| --escalate-user USER | ACL attack: grant USER rights via the relayed bind. |
| --delegate-access | RBCD: configure delegation on the relayed computer account. |
| -debug | Verbose impacket logging, independent of relaytrace output. |


## Reading the output

- `[*] INFO  Captured auth from <ip> as <acct> (NTLMv2, MIC present)`
  The auth arrived and was parsed. MIC present/absent is the victim's message.
- `[!] WARN  MIC stripped ...` or `[*] INFO  MIC left intact`
  Whether --remove-mic acted before forwarding.
- `[!] WARN  Cleared NTLM negotiate flags 0x... `
  Which SIGN/SEAL flags were removed.
- `[+] OK    Bind ACCEPTED ...`  the relay authenticated.
- `[-] FAIL  Bind REFUSED (resultCode N, ...)` with a decoded sub-status:
    - 8009030c SEC_E_LOGON_DENIED: credentials refused. Between two DCs this
      usually means MIC removal was detected (target patched vs CVE-2019-1040).
    - 8009030f SEC_E_MESSAGE_ALTERED: the message was seen as tampered; MIC
      integrity check fired.
    - 80090346 SEC_E_BAD_BINDINGS: channel binding mismatch; target enforces
      LDAPS channel binding (set to Always). A "When Supported" DC does not
      return this.

If you see "no sub-status parsed," paste one failing run; the field name in
your ldap3 build may differ and the decoder can be pointed at it.


## Revert

Restore the two .bak files and delete relaytrace.py. Nothing else changed.
