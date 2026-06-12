import os
import re

roles = ['vuln_forest', 'vuln_ia_surface', 'vuln_kerberos', 'vuln_lateral', 'vuln_linux', 'vuln_network_protocols']
roles_dir = '/home/sanchit/DVWA/ansible/roles'
docs_dir = '/home/sanchit/DVWA/docs'

# Patterns to search for tags
tag_patterns = [
    re.compile(r'\b[A-Z]{2,4}-\d+\b'),
    re.compile(r'\bESC\d+\b')
]

extracted_tags = {}  # tag -> set of (role, filepath)

for role in roles:
    role_path = os.path.join(roles_dir, role)
    for root, dirs, files in os.walk(role_path):
        for file in files:
            if file.endswith(('.yml', '.j2', '.py')):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Find ranges like DF-042..048
                        ranges = re.findall(r'\b([A-Z]{2,4})-(\d+)\.\.(\d+)\b', content)
                        for prefix, start, end in ranges:
                            start_val = int(start)
                            end_val = int(end)
                            for val in range(start_val, end_val + 1):
                                tag = f"{prefix}-{val:03d}"
                                extracted_tags.setdefault(tag, set()).add((role, filepath))
                                
                        for pattern in tag_patterns:
                            for tag in pattern.findall(content):
                                extracted_tags.setdefault(tag, set()).add((role, filepath))
                except Exception as e:
                    print(f"Error reading {filepath}: {e}")

# Also check for other specific strings in kerberos (like RC4-only)
# Let's see if there are any others.
print(f"Total unique tags extracted from code: {len(extracted_tags)}")
for tag in sorted(extracted_tags.keys()):
    occurrences = list(extracted_tags[tag])
    # print(f"  {tag} -> found in {occurrences[0][0]} ({os.path.basename(occurrences[0][1])})")

# Let's search the docs directory for occurrences of these tags
documented_tags = {} # tag -> list of (doc_file, line_number, line_content)
for root, dirs, files in os.walk(docs_dir):
    for file in files:
        if file.endswith('.md'):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        for tag in extracted_tags:
                            # Search for exact tag
                            if tag in line:
                                documented_tags.setdefault(tag, []).append((file, i, line.strip()))
            except Exception as e:
                print(f"Error reading doc {filepath}: {e}")

print("\n--- Summary of Documentation Status ---")
for tag in sorted(extracted_tags.keys()):
    docs = documented_tags.get(tag, [])
    if docs:
        print(f"{tag}: Documented in {[d[0] for d in docs]}")
    else:
        print(f"{tag}: UNDOCUMENTED")
