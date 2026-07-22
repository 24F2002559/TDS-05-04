import re
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------- Helper: extract YAML frontmatter and body ----------
def parse_skill(skill_text):
    """Return (frontmatter_dict, body_markdown) from a skill file."""
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
def check_hardcoded_secret(fm, body):
    """Flag if the file contains a likely hardcoded secret or webhook URL."""
    full_text = body
    if fm:
        for val in fm.values():
            if isinstance(val, str):
                full_text += '\n' + val

    # Known secret patterns
    secret_patterns = [
        r'sk-[a-zA-Z0-9]{32,}',                     # OpenAI
        r'ghp_[a-zA-Z0-9]{36,}',                    # GitHub token
        r'xox[baprs]-[0-9a-zA-Z-]+',                # Slack
        r'AKIA[0-9A-Z]{16}',                        # AWS Access Key
        r'eyJ[a-zA-Z0-9._-]+',                      # JWT (may FP on examples, but fine for exam)
        r'https?://hooks\.slack\.com/services/[A-Za-z0-9/_]+',
        r'https?://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
        r'https?://[^/\s]*/hooks?/',                # generic webhook URL
        r'https?://[^/\s]*/webhook/',               # alternative
        r'Bearer [A-Za-z0-9._\-]{20,}',              # Bearer token in body
        r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}',  # Basic auth
    ]
    for pat in secret_patterns:
        if re.search(pat, full_text, re.IGNORECASE):
            return True

    # Assignment of secret keys with long or non-empty random values
    secret_keys = r'(?:api[_\s]?key|secret|token|password|webhook|auth[_\s]?token|access[_\s]?key|api[_\s]?secret|credentials)'
    # Pattern 1: key = "value" or key: "value" (with quotes)
    assignment_re = secret_keys + r'\s*[:=]\s*["\']([^"\']+)["\']'
    matches = re.findall(assignment_re, full_text, re.IGNORECASE)
    for val in matches:
        if not re.search(r'[\$]', val) and '${' not in val and 'os.environ' not in val:
            return True

    # Pattern 2: YAML key: value (no quotes) – only if value looks secret-like
    yaml_assignment_re = secret_keys + r'\s*:\s*(\S+)\s*'
    yaml_matches = re.findall(yaml_assignment_re, full_text, re.IGNORECASE)
    for val in yaml_matches:
        if not re.search(r'[\$]', val) and '${' not in val and 'os.environ' not in val:
            # value must contain at least one letter & digit, length >= 8, not a pure number/version
            if len(val) >= 8 and re.search(r'[a-zA-Z]', val) and re.search(r'[0-9]', val):
                return True

    # 3. Any frontmatter value that looks like a long random string (>=20 alphanumeric)
    if fm:
        for key, val in fm.items():
            if isinstance(val, str) and len(val) >= 20 and re.match(r'^[A-Za-z0-9._\-+/=]+$', val):
                if not re.search(r'[\s]', val) and not re.search(r'[a-z]', val[:4]) and re.search(r'[a-zA-Z]', val) and re.search(r'[0-9]', val):
                    return True

    return False

def check_prompt_injection(body):
    """Flag suspicious instructions that attempt to override user control or exfiltrate data silently."""
    suspicious_phrases = [
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
    ]
    combined = '|'.join(suspicious_phrases)
    return bool(re.search(combined, body, re.IGNORECASE))

def check_excessive_permissions(fm):
    """Check if the frontmatter declares overly broad filesystem or network access."""
    if not fm:
        return False

    # Look for permission-like blocks
    permission_candidates = []
    for key in ('permissions', 'tools', 'capabilities', 'access', 'security', 'sandbox'):
        if key in fm and isinstance(fm[key], dict):
            permission_candidates.append(fm[key])

    # Also top-level keys like network, filesystem might appear directly
    if 'network' in fm or 'filesystem' in fm or 'fs' in fm:
        permission_candidates.append(fm)

    for perm in permission_candidates:
        # Filesystem checks
        fs = perm.get('filesystem') or perm.get('fs') or perm.get('file') or perm.get('storage') or perm.get('volume')
        if isinstance(fs, dict):
            all_paths = []
            for mode in ('read', 'write', 'rw'):
                paths = fs.get(mode, [])
                if isinstance(paths, str):
                    all_paths.append(paths)
                elif isinstance(paths, list):
                    all_paths.extend(paths)
            # Also check if fs directly contains a path string (e.g., filesystem: /)
            for val in fs.values():
                if isinstance(val, str):
                    all_paths.append(val)
            for p in all_paths:
                if p in ('/', '/home', '~', '~/', '/root', '*', '**', 'all', 'any', 'world'):
                    return True

        # Network checks
        net = perm.get('network') or perm.get('net') or perm.get('networking') or perm.get('egress') or perm.get('outbound') or perm.get('domains') or perm.get('hosts')
        if isinstance(net, str):
            if net in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                return True
        elif isinstance(net, dict):
            # e.g., network: { egress: '*' } or network: { allow: '*' }
            for subval in net.values():
                if isinstance(subval, str) and subval in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                    return True
                elif isinstance(subval, list):
                    for entry in subval:
                        if entry in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                            return True
        elif isinstance(net, list):
            for entry in net:
                if entry in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                    return True

    return False

def check_unclear_provenance(fm, body):
    """Flag if author/version/changelog are missing, or if a step silently rewrites version metadata."""
    if not fm:
        return True
    missing = []
    for field in ('author', 'version', 'changelog'):
        if field not in fm or not fm[field]:
            missing.append(field)
    if missing:
        return True

    # Detect steps that modify version without mentioning changelog
    lines = body.splitlines()
    action_words = r'(?:update|change|modify|write|set|increment|bump|alter)'
    for line in lines:
        if re.search(r'version', line, re.IGNORECASE):
            if re.search(action_words, line, re.IGNORECASE):
                if 'changelog' not in line.lower():
                    return True
    return False

# ---------- Main endpoint ----------
@app.route('/', methods=['POST'])
def scan():
    data = request.get_json()
    skill_text = data.get('skill', '')
    fm, body = parse_skill(skill_text)
    categories = []

    if check_hardcoded_secret(fm, body):
        categories.append('hardcoded_secret')
    if check_prompt_injection(body):
        categories.append('prompt_injection')
    if check_excessive_permissions(fm):
        categories.append('excessive_permissions')
    if check_unclear_provenance(fm, body):
        categories.append('unclear_provenance')

    return jsonify({"categories": categories})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
