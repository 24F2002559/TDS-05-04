import re
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------- Helper: extract YAML frontmatter and body ----------
def parse_skill(skill_text):
    """Return (frontmatter_dict, body_markdown) from a skill file."""
    lines = skill_text.splitlines()
    if not lines or lines[0].strip() != '---':
        return None, skill_text  # no frontmatter
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
        # also look in string values of frontmatter
        for val in fm.values():
            if isinstance(val, str):
                full_text += '\n' + val

    # Common secret patterns (prefixes)
    secret_patterns = [
        r'sk-[a-zA-Z0-9]{32,}',             # OpenAI
        r'ghp_[a-zA-Z0-9]{36,}',            # GitHub token
        r'xox[baprs]-[0-9a-zA-Z-]+',        # Slack
        r'AKIA[0-9A-Z]{16}',                # AWS Access Key
        r'eyJ[a-zA-Z0-9._-]+',              # JWT (might FP, so cautious)
        r'https?://hooks\.slack\.com/services/[A-Za-z0-9/_]+',  # Slack webhook
        r'https?://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+', # Discord webhook
        r'sk-[a-zA-Z0-9]{32,}',             # generic sk-
        r'[a-z0-9]{32,}',                   # long hex string (too generic, skip)
    ]
    for pat in secret_patterns:
        if re.search(pat, full_text):
            return True
    # Also check for assignments like "API_KEY = '...'" with long random string
    # that doesn't reference env var.
    assignment_re = r'(?:api_key|secret|token|password|webhook)\s*[:=]\s*["\']([^"\']{20,})["\']'
    matches = re.findall(assignment_re, full_text, re.IGNORECASE)
    for val in matches:
        if not re.search(r'\$', val) and not '${' in val and not 'os.environ' in val:
            return True
    return False

def check_prompt_injection(body):
    """Flag suspicious instructions that attempt to override user control or exfiltrate data silently."""
    # Phrases common in prompt injection
    suspicious_phrases = [
        r'ignore (all |previous )?instructions?',
        r'disregard (the )?(user|above)',
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
    ]
    combined = '|'.join(suspicious_phrases)
    return bool(re.search(combined, body, re.IGNORECASE))

def check_excessive_permissions(fm):
    """Check if the frontmatter declares overly broad filesystem/network access."""
    if not fm:
        return False
    # Look for a 'permissions' or 'tools' field
    perms = fm.get('permissions') or fm.get('tools') or fm.get('capabilities')
    if not isinstance(perms, dict):
        return False
    fs = perms.get('filesystem') or perms.get('fs') or perms.get('file')
    network = perms.get('network') or perms.get('net')
    if isinstance(fs, dict):
        read_paths = fs.get('read', [])
        write_paths = fs.get('write', [])
        all_paths = read_paths + write_paths
        for p in all_paths:
            if p in ('/', '/home', '~', '~/', '/root', '*'):
                return True
    if isinstance(network, (str, list)):
        if network == '*' or network == '0.0.0.0/0' or network == 'any' or network == 'all':
            return True
        if isinstance(network, list):
            for entry in network:
                if entry in ('*', '0.0.0.0/0', 'any', 'all'):
                    return True
    return False

def check_unclear_provenance(fm, body):
    """Flag if author/version/changelog are missing, or if a step silently rewrites version metadata."""
    if not fm:
        return True  # no frontmatter at all → provenance unclear
    missing = []
    for field in ('author', 'version', 'changelog'):
        if field not in fm or not fm[field]:
            missing.append(field)
    if missing:
        return True
    # Check for hidden version modification steps
    # Look for instructions containing "version" and "update"/"write" without "changelog"
    lines = body.splitlines()
    for line in lines:
        if re.search(r'version', line, re.IGNORECASE):
            if re.search(r'update|change|modify|write|set', line, re.IGNORECASE):
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
