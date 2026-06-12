import os
import re

roles_dir = "/home/sanchit/DVWA/ansible/roles"
docs_dir = "/home/sanchit/DVWA/docs"

target_roles = [
    "vuln_persistence",
    "vuln_privesc",
    "vuln_recon",
    "vuln_traffic_sim",
    "vuln_victim_exec",
    "vuln_web_apps"
]

# Patterns to match vulnerability tags
# Matches e.g., PE-001, PE-CVE-2021-36934, PER-025, etc.
tag_pattern = re.compile(r'\b(?:IA|REC|ENUM|CRED|LAT|PE|PER|DF)-(?:CVE-\d{4}-\d+|\d+)\b', re.IGNORECASE)

extracted_tags = {} # tag -> list of (role, filepath, line_num, line_content)

# 1. Scan roles
for role in target_roles:
    role_path = os.path.join(roles_dir, role)
    if not os.path.exists(role_path):
        print(f"Warning: Role path {role_path} does not exist.")
        continue
    for root, dirs, files in os.walk(role_path):
        for file in files:
            file_path = os.path.join(root, file)
            # Skip binary files if any
            if file.endswith(('.png', '.jpg', '.exe', '.zip', '.tar.gz', '.iso')):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for idx, line in enumerate(f, 1):
                        matches = tag_pattern.findall(line)
                        for match in matches:
                            normalized = match.upper()
                            if normalized not in extracted_tags:
                                extracted_tags[normalized] = []
                            extracted_tags[normalized].append((role, os.path.relpath(file_path, roles_dir), idx, line.strip()))
            except Exception as e:
                print(f"Error reading {file_path}: {e}")

print(f"Found {len(extracted_tags)} unique vulnerability tags in specified roles.")

# 2. Scan docs
docs_files = []
for root, dirs, files in os.walk(docs_dir):
    for file in files:
        if file.endswith('.md'):
            docs_files.append(os.path.join(root, file))

docs_matches = {} # tag -> list of (doc_relative_path, line_num, line_content)
docs_headers = {} # tag -> list of (doc_relative_path, line_num, header_text)

header_pattern = re.compile(r'^#+\s+(.*)', re.IGNORECASE)

for doc_path in docs_files:
    rel_path = os.path.relpath(doc_path, docs_dir)
    try:
        with open(doc_path, 'r', encoding='utf-8', errors='ignore') as f:
            for idx, line in enumerate(f, 1):
                # Check for headers that might contain the tag
                header_match = header_pattern.match(line)
                
                # Check for tags on this line
                for tag in extracted_tags.keys():
                    escaped_tag = re.escape(tag)
                    tag_regex = re.compile(r'\b' + escaped_tag + r'\b', re.IGNORECASE)
                    if tag_regex.search(line):
                        if tag not in docs_matches:
                            docs_matches[tag] = []
                        docs_matches[tag].append((rel_path, idx, line.strip()))
                        
                        if header_match:
                            if tag not in docs_headers:
                                docs_headers[tag] = []
                            docs_headers[tag].append((rel_path, idx, line.strip()))
    except Exception as e:
        print(f"Error reading doc {doc_path}: {e}")

# 3. Classify tags
classification = {
    "fully_documented": [],
    "partially_documented": [],
    "undocumented": []
}

for tag in sorted(extracted_tags.keys()):
    has_header = tag in docs_headers
    has_mention = tag in docs_matches
    
    if has_header:
        classification["fully_documented"].append(tag)
    elif has_mention:
        classification["partially_documented"].append(tag)
    else:
        classification["undocumented"].append(tag)

print("\n--- CLASSIFICATION SUMMARY ---")
print(f"Fully Documented ({len(classification['fully_documented'])}): {classification['fully_documented']}")
print(f"Partially Documented ({len(classification['partially_documented'])}): {classification['partially_documented']}")
print(f"Undocumented ({len(classification['undocumented'])}): {classification['undocumented']}")

# Write detailed analysis to a temp file in our directory
import json
output_data = {
    "extracted_tags": extracted_tags,
    "docs_matches": docs_matches,
    "docs_headers": docs_headers,
    "classification": classification
}
# Save into the same explorer directory
with open("/home/sanchit/DVWA/.agents/explorer_m1_c/scan_results.json", "w") as out:
    json.dump(output_data, out, indent=2)
print("\nResults written to /home/sanchit/DVWA/.agents/explorer_m1_c/scan_results.json")
