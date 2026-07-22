import re, yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

def parse_skill(skill_text):
    lines = skill_text.splitlines()
    if not lines or lines[0].strip() != '---':
        return None, skill_text
    end = 1
    while end < len(lines) and lines[end].strip() != '---':
        end += 1
    if end >= len(lines):
        return None, skill_text
    fm_text = '\n'.join(lines[1:end])
    try:
        fm = yaml.safe_load(fm_text)
    except yaml.YAMLError:
        fm = None
    body = '\n'.join(lines[end+1:])
    return fm, body

# ---------- Checkers ----------
def check_hardcoded_secret(fm, body, debug=False):
    full_text = body
    if fm:
        for v in fm.values():
            if isinstance(v, str):
                full_text += '\n' + v

    # Known token patterns
    token_patterns = [
        r'sk-[a-zA-Z0-9]{32,}',
        r'ghp_[a-zA-Z0-9]{36,}',
        r'xox[baprs]-[0-9a-zA-Z-]+',
        r'AKIA[0-9A-Z]{16}',
        r'eyJ[a-zA-Z0-9._-]+',
        r'https?://hooks\.slack\.com/services/[A-Za-z0-9/_]+',
        r'https?://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
        r'https?://[^\s]+/hooks?/',                # generic webhook path
        r'https?://[^\s]+/webhook/',               # alternative
        r'Bearer [A-Za-z0-9._\-]{20,}',
        r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}',
    ]
    for pat in token_patterns:
        if re.search(pat, full_text, re.IGNORECASE):
            return True if not debug else (True, {"token_pattern": pat})

    # Secrets assigned to known keywords (key = value)
    secret_keywords = r'(api[_\s]?key|secret|token|password|webhook|auth[_\s]?token|access[_\s]?key|api[_\s]?secret|credentials)'
    safe_values = {'none', 'null', 'example', 'your-secret-here', 'placeholder', 'changeme', ''}

    # Quoted values
    for m in re.finditer(secret_keywords + r'\s*[:=]\s*["\']([^"\']{1,})["\']', full_text, re.IGNORECASE):
        val = m.group(2).strip()
        if val.lower() not in safe_values and not re.search(r'[\$\{]', val):
            return True if not debug else (True, {"quoted_assignment": val})

    # Unquoted values – allow any non‑env, non‑safe word
    for m in re.finditer(secret_keywords + r'\s*[:=]\s*(\S+)', full_text, re.IGNORECASE):
        val = m.group(2).strip()
        if val.lower() not in safe_values and not re.search(r'[\$\{]', val) and len(val) >= 3:
            return True if not debug else (True, {"unquoted_assignment": val})

    return (False, {}) if debug else False

def check_prompt_injection(body, debug=False):
    phrases = [
        r'ignore (all |previous )?instructions?',
        r'disregard (the )?(user|above|previous)',
        r'do not ask (for |the user )?(confirmation|permission)',
        r'without (any |further )?(prompt|confirm|asking)',
        r'bypass (the |user )?security',
        r'silently\s+(upload|send|exfiltrate|post|transfer)',
        r'exfiltrate\s+(the )?contents?',
        r'send (the )?(file|data|contents?|output)\s+(to|via|using)\s+',
        r'override (the )?user\'?s?\s*(decision|choice|setting)',
        r'do not (let|allow) the user (to )?cancel',
        r'without user (knowledge|consent)',
        r'hide (the )?output from the user',
        r'do not display (the )?result',
        r'forget all (previous )?instructions',
        r'act as (if|though)',
        r'you are now',
        r'only follow (these|my) instructions',
        r'never respond with',
        r'reply with only',
        r'do not reveal',
        r'keep this secret',
        r'do not tell the user',
        r'don\'t listen to',
        r'ignore user input',
        r'pretend you are',
    ]
    combined = '|'.join(phrases)
    match = re.findall(combined, body, re.IGNORECASE) if debug else None
    if re.search(combined, body, re.IGNORECASE):
        return (True, {"matches": match}) if debug else True
    return (False, {}) if debug else False

def check_excessive_permissions(fm, debug=False):
    if not fm:
        return (False, {}) if debug else False

    candidates = []
    # Nested permission blocks
    for k in ('permissions', 'tools', 'capabilities', 'access', 'security', 'sandbox'):
        if k in fm and isinstance(fm[k], dict):
            candidates.append(fm[k])
        elif k in fm and isinstance(fm[k], list):
            # list of strings or dicts
            for item in fm[k]:
                if isinstance(item, dict):
                    candidates.append(item)
                elif isinstance(item, str):
                    # treat the whole list as a candidate with that string as a filesystem/net value
                    candidates.append({k: item})

    # Top-level shorthand
    if any(k in fm for k in ('network', 'filesystem', 'fs', 'storage')):
        candidates.append(fm)

    wild_paths = {'/', '/home', '~', '~/', '/root', '*', '**', 'all', 'any', 'world'}
    wild_nets = {'*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'}

    details = {"candidates": [], "wild_fs": [], "wild_net": []}
    for cand in candidates:
        details["candidates"].append(cand)
        # filesystem
        fs = cand.get('filesystem') or cand.get('fs') or cand.get('file') or cand.get('storage') or cand.get('volume')
        if isinstance(fs, dict):
            for mode in ('read', 'write', 'rw', 'allow', 'deny'):
                val = fs.get(mode, [])
                if isinstance(val, str): val = [val]
                for p in val:
                    if isinstance(p, str) and p in wild_paths:
                        details["wild_fs"].append(p)
                        if not debug: return True
        elif isinstance(fs, str):
            if fs in wild_paths:
                details["wild_fs"].append(fs)
                if not debug: return True
        elif isinstance(fs, list):
            for p in fs:
                if isinstance(p, str) and p in wild_paths:
                    details["wild_fs"].append(p)
                    if not debug: return True

        # network
        net = cand.get('network') or cand.get('net') or cand.get('networking') or cand.get('egress') or cand.get('outbound') or cand.get('domains') or cand.get('hosts')
        if isinstance(net, str):
            if net in wild_nets:
                details["wild_net"].append(net)
                if not debug: return True
        elif isinstance(net, dict):
            for v in net.values():
                vals = [v] if isinstance(v, str) else (v if isinstance(v, list) else [])
                for entry in vals:
                    if entry in wild_nets:
                        details["wild_net"].append(entry)
                        if not debug: return True
        elif isinstance(net, list):
            for entry in net:
                if entry in wild_nets:
                    details["wild_net"].append(entry)
                    if not debug: return True

    if details["wild_fs"] or details["wild_net"]:
        return (True, details) if debug else True
    return (False, details) if debug else False

def check_unclear_provenance(fm, body, debug=False):
    if not fm:
        return (True, {"reason": "no frontmatter"}) if debug else True
    missing = [f for f in ('author', 'version', 'changelog') if not fm.get(f)]
    if missing:
        return (True, {"missing": missing}) if debug else True

    action = r'(update|change|modify|write|set|increment|bump|alter)'
    suspicious = []
    for line in body.splitlines():
        if re.search(r'version', line, re.IGNORECASE) and re.search(action, line, re.IGNORECASE):
            if 'changelog' not in line.lower():
                suspicious.append(line.strip())
                if not debug: return True
    if debug:
        return (bool(suspicious), {"suspicious_lines": suspicious})
    return bool(suspicious)

# ---------- Main endpoint ----------
@app.route('/', methods=['POST'])
def scan():
    data = request.get_json()
    skill_text = data.get('skill', '')
    fm, body = parse_skill(skill_text)
    cats = []
    if check_hardcoded_secret(fm, body):
        cats.append('hardcoded_secret')
    if check_prompt_injection(body):
        cats.append('prompt_injection')
    if check_excessive_permissions(fm):
        cats.append('excessive_permissions')
    if check_unclear_provenance(fm, body):
        cats.append('unclear_provenance')
    return jsonify({"categories": cats})

# ---------- Debug endpoint ----------
@app.route('/debug', methods=['POST'])
def debug_scan():
    data = request.get_json()
    skill_text = data.get('skill', '')
    fm, body = parse_skill(skill_text)

    sec, sec_d = check_hardcoded_secret(fm, body, debug=True)
    prm, prm_d = check_prompt_injection(body, debug=True)
    exc, exc_d = check_excessive_permissions(fm, debug=True)
    prv, prv_d = check_unclear_provenance(fm, body, debug=True)

    return jsonify({
        "frontmatter": fm,
        "body_preview": body[:500],
        "checks": {
            "hardcoded_secret": {"flagged": sec, "details": sec_d},
            "prompt_injection": {"flagged": prm, "details": prm_d},
            "excessive_permissions": {"flagged": exc, "details": exc_d},
            "unclear_provenance": {"flagged": prv, "details": prv_d}
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
