# relaytrace.py
# Plain-English, colored tracing for ntlmrelayx relay attempts.
# Drop into impacket/examples/ntlmrelayx/utils/ and import where needed:
#   from impacket.examples.ntlmrelayx.utils import relaytrace as rt
#
# It answers, per relay: was the auth captured, was the MIC dropped,
# were sign/seal flags stripped, was the bind accepted, and if not, WHY.

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

# --- LDAP bind result decode (the part the stock tool throws away) ------------

_SUBSTATUS = {
    "8009030c": ("SEC_E_LOGON_DENIED",
                 "Credentials rejected outright. Between two DCs this most often means "
                 "your MIC removal was detected: the target is patched against "
                 "CVE-2019-1040 and dropped the tampered message."),
    "8009030f": ("SEC_E_MESSAGE_ALTERED",
                 "The target saw the NTLM message had been altered. The MIC integrity "
                 "check fired, so your MIC drop or flag strip was caught."),
    "80090346": ("SEC_E_BAD_BINDINGS",
                 "Channel binding mismatch. The target enforces LDAPS channel binding "
                 "(set to Always), so a relayed auth with no valid CBT is refused. "
                 "A 'When Supported' DC would NOT return this."),
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
    """Pass an ldap3 Connection.result dict:
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
