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
def check_hardcoded_secret(fm, body, debug=False):
    """Flag if the file contains a likely hardcoded secret or webhook URL.
       If debug=True, returns (bool, dict with details)."""
    details = {}
    full_text = body
    if fm:
        for val in fm.values():
            if isinstance(val, str):
                full_text += '\n' + val

    # Known secret patterns
    secret_patterns = {
        'openai_key': r'sk-[a-zA-Z0-9]{32,}',
        'github_token': r'ghp_[a-zA-Z0-9]{36,}',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z-]+',
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'jwt': r'eyJ[a-zA-Z0-9._-]+',
        'slack_webhook': r'https?://hooks\.slack\.com/services/[A-Za-z0-9/_]+',
        'discord_webhook': r'https?://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
        'generic_webhook': r'https?://[^/\s]*/hooks?/',
        'bearer_token': r'Bearer [A-Za-z0-9._\-]{20,}',
        'basic_auth': r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}',
    }
    matched_patterns = []
    for name, pat in secret_patterns.items():
        if re.search(pat, full_text, re.IGNORECASE):
            matched_patterns.append(name)
            if not debug: return True   # early exit for normal scan

    # Assignment detection
    secret_keys = r'(?:api[_\s]?key|secret|token|password|webhook|auth[_\s]?token|access[_\s]?key|api[_\s]?secret|credentials)'
    # Pattern 1: quoted values
    assignment_re = secret_keys + r'\s*[:=]\s*["\']([^"\']+)["\']'
    assignment_matches = re.findall(assignment_re, full_text, re.IGNORECASE)
    detailed_assignments = []
    for val in assignment_matches:
        if not re.search(r'[\$]', val) and '${' not in val and 'os.environ' not in val:
            detailed_assignments.append(('quoted', val))
            if not debug: return True

    # Pattern 2: unquoted values that look secret-like
    yaml_assignment_re = secret_keys + r'\s*:\s*(\S+)\s*'
    yaml_matches = re.findall(yaml_assignment_re, full_text, re.IGNORECASE)
    for val in yaml_matches:
        if not re.search(r'[\$]', val) and '${' not in val and 'os.environ' not in val:
            if len(val) >= 8 and re.search(r'[a-zA-Z]', val) and re.search(r'[0-9]', val):
                detailed_assignments.append(('unquoted', val))
                if not debug: return True

    # 3. Random-looking long strings in frontmatter values
    random_fm_vals = []
    if fm:
        for key, val in fm.items():
            if isinstance(val, str) and len(val) >= 20 and re.match(r'^[A-Za-z0-9._\-+/=]+$', val):
                if not re.search(r'[\s]', val) and not re.search(r'[a-z]', val[:4]) and re.search(r'[a-zA-Z]', val) and re.search(r'[0-9]', val):
                    random_fm_vals.append((key, val))
                    if not debug: return True

    if debug:
        details['matched_patterns'] = matched_patterns
        details['assignment_matches'] = detailed_assignments
        details['random_fm_vals'] = random_fm_vals
        return bool(matched_patterns or detailed_assignments or random_fm_vals), details
    return False

def check_prompt_injection(body, debug=False):
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
    matches = re.findall(combined, body, re.IGNORECASE) if debug else None
    flagged = bool(re.search(combined, body, re.IGNORECASE))
    if debug:
        return flagged, {'matches': matches}
    return flagged

def check_excessive_permissions(fm, debug=False):
    if not fm:
        return False

    permission_candidates = []
    for key in ('permissions', 'tools', 'capabilities', 'access', 'security', 'sandbox'):
        if key in fm and isinstance(fm[key], dict):
            permission_candidates.append(fm[key])

    if 'network' in fm or 'filesystem' in fm or 'fs' in fm:
        permission_candidates.append(fm)

    details = {'permission_candidates': permission_candidates, 'broad_fs': [], 'broad_net': []}
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
            for val in fs.values():
                if isinstance(val, str):
                    all_paths.append(val)
            for p in all_paths:
                if p in ('/', '/home', '~', '~/', '/root', '*', '**', 'all', 'any', 'world'):
                    details['broad_fs'].append(p)
                    if not debug: return True

        # Network checks
        net = perm.get('network') or perm.get('net') or perm.get('networking') or perm.get('egress') or perm.get('outbound') or perm.get('domains') or perm.get('hosts')
        if isinstance(net, str):
            if net in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                details['broad_net'].append(net)
                if not debug: return True
        elif isinstance(net, dict):
            for subval in net.values():
                if isinstance(subval, str) and subval in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                    details['broad_net'].append(subval)
                    if not debug: return True
                elif isinstance(subval, list):
                    for entry in subval:
                        if entry in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                            details['broad_net'].append(entry)
                            if not debug: return True
        elif isinstance(net, list):
            for entry in net:
                if entry in ('*', '0.0.0.0/0', 'any', 'all', 'world', 'internet'):
                    details['broad_net'].append(entry)
                    if not debug: return True

    flagged = bool(details['broad_fs'] or details['broad_net'])
    if debug:
        return flagged, details
    return flagged

def check_unclear_provenance(fm, body, debug=False):
    if not fm:
        return True
    missing = []
    for field in ('author', 'version', 'changelog'):
        if field not in fm or not fm[field]:
            missing.append(field)
    if missing:
        if debug:
            return True, {'missing_fields': missing}
        return True

    # Detect steps that modify version without mentioning changelog
    action_words = r'(?:update|change|modify|write|set|increment|bump|alter)'
    suspicious_lines = []
    for line in body.splitlines():
        if re.search(r'version', line, re.IGNORECASE):
            if re.search(action_words, line, re.IGNORECASE):
                if 'changelog' not in line.lower():
                    suspicious_lines.append(line.strip())
                    if not debug: return True
    if debug:
        return bool(suspicious_lines), {'suspicious_lines': suspicious_lines}
    return bool(suspicious_lines)

# ---------- Grader endpoint ----------
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

# ---------- Debug endpoint (not used by grader) ----------
@app.route('/debug', methods=['POST'])
def debug_scan():
    data = request.get_json()
    skill_text = data.get('skill', '')
    fm, body = parse_skill(skill_text)

    hard_secret, secret_details = check_hardcoded_secret(fm, body, debug=True)
    prompt_inj, prompt_details = check_prompt_injection(body, debug=True)
    excessive, excess_details = check_excessive_permissions(fm, debug=True)
    unclear_prov, prov_details = check_unclear_provenance(fm, body, debug=True)

    return jsonify({
        "frontmatter": fm,
        "body_preview": body[:500],   # first 500 chars
        "checks": {
            "hardcoded_secret": {
                "flagged": hard_secret,
                "details": secret_details
            },
            "prompt_injection": {
                "flagged": prompt_inj,
                "details": prompt_details
            },
            "excessive_permissions": {
                "flagged": excessive,
                "details": excess_details
            },
            "unclear_provenance": {
                "flagged": unclear_prov,
                "details": prov_details
            }
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
