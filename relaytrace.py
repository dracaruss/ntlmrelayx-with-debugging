# relaytrace.py
# Plain-English, colored diagnostics for SMB to LDAP(S) relay in ntlmrelayx.
# Instrumentation only. No attack logic, no impacket imports, so it cannot
# cause a version conflict. Delete this file + restore backups to revert.

import sys
import re

# --- color setup (works in modern Windows terminals and *nix) ----------------
_COLOR = True
try:
    import colorama
    colorama.init()
except Exception:
    if sys.platform == "win32":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            _COLOR = False

RESET, BOLD = "\033[0m", "\033[1m"
RED, GRN, YEL, BLU, CYN, GRY = (
    "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[36m", "\033[90m"
)

def _c(color, text):
    return f"{color}{text}{RESET}" if _COLOR else str(text)

def _tag(symbol, color, label, msg):
    print(f"{_c(color, symbol)} {_c(BOLD, label):<6} {msg}")

def step(msg): _tag("[>]", CYN, "STEP", msg)
def good(msg): _tag("[+]", GRN, "OK",   msg)
def warn(msg): _tag("[!]", YEL, "WARN", msg)
def bad(msg):  _tag("[-]", RED, "FAIL", msg)
def info(msg): _tag("[*]", BLU, "INFO", msg)

# --- captured authentication -------------------------------------------------

def auth_captured(src_ip, account, ntlm_version, mic_present):
    info(f"Captured auth from {_c(BOLD, src_ip)} as {_c(BOLD, account)} "
         f"({ntlm_version}, MIC {'present' if mic_present else 'absent'})")

def forwarding(target, account):
    step(f"Forwarding NTLM to {_c(BOLD, target)} as {_c(BOLD, account)}")

# --- message manipulation before forwarding ----------------------------------

def mic_dropped(did_drop):
    if did_drop:
        warn("MIC stripped from AUTHENTICATE (CVE-2019-1040 path). "
             "If the target is patched, it will reject this.")
    else:
        info("MIC left intact (no --remove-mic).")

def signseal_stripped(flags_before, flags_after):
    cleared = flags_before & ~flags_after
    if cleared:
        warn(f"Cleared NTLM negotiate flags 0x{cleared:08x} "
             f"(0x{flags_before:08x} -> 0x{flags_after:08x}). "
             "SIGN/SEAL removal only survives when the MIC does not cover it.")
    else:
        info("No sign/seal flags changed.")

# --- AV_PAIR inspection (version-independent, parses the bytes directly) ------
# This is the proof layer: it reads what the client actually sent so we do not
# have to guess why the DC answered the way it did.

AV_EOL             = 0x0000
AV_FLAGS           = 0x0006
AV_TARGET_NAME     = 0x0009
AV_CHANNEL_BINDINGS = 0x000a

def parse_av_pairs(ntlmv2_response):
    """Walk the AV_PAIR TLVs out of an NTLMv2 response blob ('ntlm' field).
    NTLMv2 response = NTProofStr(16) + temp; temp header before AV pairs is
    1+1+6+8+8+4 = 28 bytes, so AV pairs start at offset 44.
    Returns {av_id: value_bytes}, or {} if it cannot parse (e.g. NTLMv1)."""
    out = {}
    try:
        data = ntlmv2_response[16 + 28:]
        i = 0
        while i + 4 <= len(data):
            av_id = int.from_bytes(data[i:i + 2], "little")
            av_len = int.from_bytes(data[i + 2:i + 4], "little")
            i += 4
            if av_id == AV_EOL:
                break
            out[av_id] = data[i:i + av_len]
            i += av_len
    except Exception:
        return {}
    return out

def auth_posture(ntlm_response):
    """Print the client's actual posture from the AV pairs. This is what
    confirms (or refutes) why a 'When Supported' DC enforced channel binding."""
    pairs = parse_av_pairs(ntlm_response)
    if not pairs:
        info("Could not parse AV pairs (not NTLMv2, or malformed). "
             "Posture unknown; rely on the bind sub-status below.")
        return

    cbt = pairs.get(AV_CHANNEL_BINDINGS)
    if cbt is None:
        info("Channel-binding AV pair: ABSENT. Client advertised no CBT, so a "
             "'When Supported' DC should NOT enforce binding. A BAD_BINDINGS "
             "result here would mean the DC is set to 'Always'.")
    else:
        nonzero = any(b != 0 for b in cbt)
        kind = "non-zero value" if nonzero else "all-zero value"
        info(f"Channel-binding AV pair: PRESENT ({kind}, {len(cbt)} bytes). "
             "The client carried channel-binding info, so a 'When Supported' DC "
             "will evaluate it and can reject with BAD_BINDINGS even though it is "
             "not set to 'Always'. This is the likely cause when nxc shows "
             "'When Supported'.")

    flags = pairs.get(AV_FLAGS)
    if flags and len(flags) >= 4:
        mic_bit = (int.from_bytes(flags[:4], "little") & 0x02) != 0
        info(f"MsvAvFlags MIC bit: {'SET (client included a MIC)' if mic_bit else 'not set'}")

    tname = pairs.get(AV_TARGET_NAME)
    if tname:
        try:
            info(f"Target name the client authenticated to (MsvAvTargetName): "
                 f"{tname.decode('utf-16-le', 'replace')}")
        except Exception:
            pass

def token_identity(account_string):
    """Confirm the real identity carried in the token actually being sent,
    so the '(user)' label seen elsewhere is shown to be cosmetic."""
    info(f"Token identity parsed from the blob being sent: {_c(BOLD, account_string)} "
         "(confirms the real auth, not a placeholder, is forwarded)")

# --- LDAP bind result decode (the part the stock tool throws away) ------------

_SUBSTATUS = {
    "8009030c": ("SEC_E_LOGON_DENIED",
                 "Credentials rejected outright. Between two DCs this most often means "
                 "your MIC removal was detected (target patched against CVE-2019-1040)."),
    "8009030f": ("SEC_E_MESSAGE_ALTERED",
                 "The target saw the NTLM message had been altered. The MIC integrity "
                 "check fired, so your MIC drop or flag strip was caught."),
    "80090346": ("SEC_E_BAD_BINDINGS",
                 "Channel binding rejected. The DC evaluated a channel-binding token and "
                 "it did not match its TLS channel. This fires on 'Always', and ALSO on "
                 "'When Supported' when the relayed client advertised channel binding "
                 "(see the Channel-binding AV pair line above for which case this is). "
                 "Stripping SIGN/SEAL does not help: the binding evidence lives in the "
                 "NTLMv2 response, sealed by the machine key you do not have."),
    "80090308": ("SEC_E_INVALID_TOKEN",
                 "Malformed NTLM token, often a flag combination the server rejects."),
    "8009030e": ("SEC_E_NO_CREDENTIALS",
                 "No usable credentials were present in the token."),
    "80090311": ("SEC_E_NO_AUTHENTICATING_AUTHORITY",
                 "Server could not reach an authority to validate the identity."),
}

def decode_substatus(diagnostic_message):
    if not diagnostic_message:
        return None
    m = re.search(r"data\s+([0-9a-fA-F]{6,8})", diagnostic_message)
    return m.group(1).lower() if m else None

def bind_result(result_dict):
    """Pass an ldap3 Connection result dict:
       keys include 'result' (int), 'description' (str), 'message' (str)."""
    code = result_dict.get("result")
    desc = result_dict.get("description", "")
    diag = result_dict.get("message", "") or ""
    if code == 0:
        good(f"Bind ACCEPTED (resultCode 0, {desc}). Relay authenticated.")
        return True
    bad(f"Bind REFUSED (resultCode {code}, {desc}).")
    sub = decode_substatus(diag)
    if sub and sub in _SUBSTATUS:
        name, meaning = _SUBSTATUS[sub]
        bad(f"  sub-status 0x{sub} {name}")
        print(f"       {_c(GRY, meaning)}")
    elif sub:
        warn(f"  sub-status 0x{sub} is unmapped. Raw: {diag.strip()}")
    else:
        warn(f"  no sub-status parsed. Raw diagnostic: {diag.strip()}")
    return False
