#!/usr/bin/env python3
import os
import re
import sys

def find_project_root():
    # The script is in scripts/check_docs.py, so project root is one level up.
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def scan_yml_files(roles_dir):
    # Regexes:
    # 1. (?:IA|REC|ENUM|CRED|LAT|PE|PER|DF|NET|CLO|SRV|WEB)-(?:CVE-\d{4}-\d+|\d+)
    # 2. B\d
    # 3. Redis|Memcached|MongoDB|MySQL|WebApp
    # All are case-insensitive.
    pattern1 = re.compile(r'\b(?:IA|REC|ENUM|CRED|LAT|PE|PER|DF|NET|CLO|SRV|WEB)-(?:CVE-\d{4}-\d+|\d+)\b', re.IGNORECASE)
    pattern2 = re.compile(r'\bB\d\b', re.IGNORECASE)
    pattern3 = re.compile(r'\b(?:Redis|Memcached|MongoDB|MySQL|WebApp)\b', re.IGNORECASE)
    
    found_tags = set()
    
    # Walk the roles directory
    for root, dirs, files in os.walk(roles_dir):
        # We only care about vuln_* subdirectories under roles/
        parts = root.split(os.sep)
        if 'roles' in parts:
            roles_idx = parts.index('roles')
            # Check if there is a folder after 'roles' and if it starts with 'vuln_'
            if roles_idx + 1 < len(parts) and parts[roles_idx + 1].startswith('vuln_'):
                for file in files:
                    if file.endswith('.yml'):
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                        except Exception as e:
                            print(f"[!] Error reading {filepath}: {e}")
                            continue
                        
                        # Find all matches
                        matches1 = pattern1.findall(content)
                        matches2 = pattern2.findall(content)
                        matches3 = pattern3.findall(content)
                        
                        # Normalize the tags:
                        for m in matches1:
                            found_tags.add(m.upper())
                        for m in matches2:
                            found_tags.add(m.upper())
                        for m in matches3:
                            m_lower = m.lower()
                            if m_lower == 'redis':
                                found_tags.add('Redis')
                            elif m_lower == 'memcached':
                                found_tags.add('Memcached')
                            elif m_lower == 'mongodb':
                                found_tags.add('MongoDB')
                            elif m_lower == 'mysql':
                                found_tags.add('MySQL')
                            elif m_lower == 'webapp':
                                found_tags.add('WebApp')
                            else:
                                found_tags.add(m)
                                
    return found_tags

def scan_md_files(docs_dir):
    md_contents = {}
    for root, dirs, files in os.walk(docs_dir):
        for file in files:
            if file.endswith('.md'):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        md_contents[filepath] = f.read()
                except Exception as e:
                    print(f"[!] Error reading {filepath}: {e}")
    return md_contents

def check_tag_documented(tag, md_contents):
    tag_lower = tag.lower()
    
    # 1. Header pattern: starts with # followed by spaces, and containing the tag as a whole word
    header_pattern = re.compile(rf'^#+\s+.*?\b{re.escape(tag_lower)}\b', re.IGNORECASE | re.MULTILINE)
    
    # 2. Bold/List pattern: starts with list item, then bold tag (e.g. - **IA-001**)
    bold_pattern = re.compile(rf'^\s*[-*+]\s+\*\*{re.escape(tag_lower)}\*\*', re.IGNORECASE | re.MULTILINE)
    
    # 3. Table row pattern: e.g. | IA-001 |
    table_pattern = re.compile(rf'^\|\s*{re.escape(tag_lower)}\s*\|', re.IGNORECASE | re.MULTILINE)
    
    # 4. Details summary pattern: e.g. <summary>IA-001</summary>
    summary_pattern = re.compile(rf'<summary>.*?\b{re.escape(tag_lower)}\b', re.IGNORECASE | re.MULTILINE)
    
    for filepath, content in md_contents.items():
        has_header = header_pattern.search(content)
        has_bold = bold_pattern.search(content)
        has_table = table_pattern.search(content)
        has_summary = summary_pattern.search(content)
        
        if has_header or has_bold or has_table or has_summary:
            explanation_ok = False
            commands_ok = False
            
            if has_header:
                match = header_pattern.search(content)
                start_pos = match.end()
                next_header_pattern = re.compile(r'^#+\s+', re.MULTILINE)
                next_match = next_header_pattern.search(content, start_pos)
                end_pos = next_match.start() if next_match else len(content)
                
                section = content[start_pos:end_pos].strip()
                
                if len(section) > 20:
                    explanation_ok = True
                if '```' in section:
                    commands_ok = True
            else:
                # Fallback check around the tag
                tag_idx = content.lower().find(tag_lower)
                if tag_idx != -1:
                    snippet = content[max(0, tag_idx - 100):min(len(content), tag_idx + 300)]
                    if len(snippet) > 50:
                        explanation_ok = True
                    if '```' in snippet or '`' in snippet:
                        commands_ok = True
                        
            return True, filepath, explanation_ok, commands_ok
            
    return False, None, False, False

def validate_mermaid_diagrams(md_contents):
    mermaid_errors = {}
    
    for filepath, content in md_contents.items():
        errors = []
        lines = content.splitlines()
        in_block = False
        open_line = 0
        backticks_count = 0
        
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not in_block:
                # Check for opening block
                match = re.match(r'^(`{3,})mermaid\b', stripped)
                if match:
                    in_block = True
                    open_line = idx
                    backticks_count = len(match.group(1))
            else:
                # Check for closing block
                if stripped == '`' * backticks_count:
                    in_block = False
                elif re.match(r'^(`{3,})mermaid\b', stripped):
                    errors.append(f"Unclosed Mermaid block from line {open_line} before new block at line {idx}")
                    open_line = idx
                    backticks_count = len(re.match(r'^(`{3,})mermaid\b', stripped).group(1))
                    
        if in_block:
            errors.append(f"Unclosed Mermaid block from line {open_line} at end of file")
            
        if errors:
            mermaid_errors[filepath] = errors
            
    return mermaid_errors

def main():
    project_root = find_project_root()
    roles_dir = os.path.join(project_root, 'ansible', 'roles')
    docs_dir = os.path.join(project_root, 'docs')
    
    print("==================================================")
    print("Documentation & Vulnerability Tag Verification Tool")
    print("==================================================")
    print(f"Project root: {project_root}")
    print(f"Scanning roles under: {roles_dir}")
    print(f"Scanning documentation under: {docs_dir}\n")
    
    if not os.path.exists(roles_dir):
        print(f"[-] Roles directory does not exist: {roles_dir}")
        sys.exit(1)
    if not os.path.exists(docs_dir):
        print(f"[-] Docs directory does not exist: {docs_dir}")
        sys.exit(1)
        
    # 1. Scan roles
    print("[*] Scanning Ansible roles for vulnerability tags...")
    found_tags = scan_yml_files(roles_dir)
    print(f"[+] Found {len(found_tags)} unique vulnerability tags in task files.")
    
    # 2. Scan docs
    print("[*] Reading documentation files...")
    md_contents = scan_md_files(docs_dir)
    print(f"[+] Loaded {len(md_contents)} markdown files.")
    
    # 3. Check documentation
    documented_tags = []
    undocumented_tags = []
    
    print("[*] Verifying tag coverage in documentation...")
    for tag in sorted(found_tags):
        is_doc, doc_file, has_exp, has_cmd = check_tag_documented(tag, md_contents)
        rel_path = os.path.relpath(doc_file, project_root) if doc_file else None
        
        status_parts = []
        if has_exp:
            status_parts.append("explanation")
        if has_cmd:
            status_parts.append("commands")
            
        status_str = f" ({', '.join(status_parts)})" if status_parts else ""
        
        if is_doc:
            documented_tags.append((tag, rel_path, status_str))
        else:
            undocumented_tags.append(tag)
            
    # Calculate coverage
    total_tags = len(found_tags)
    num_doc = len(documented_tags)
    
    if total_tags > 0:
        coverage = (num_doc / total_tags) * 100
    else:
        coverage = 100.0
        
    print("\n==================================================")
    print("Vulnerability Tag Coverage Report")
    print("==================================================")
    print(f"Total Unique Tags Found in Roles: {total_tags}")
    print(f"Documented Tags:                 {num_doc}")
    print(f"Undocumented Tags:               {len(undocumented_tags)}")
    print(f"Coverage Percentage:             {coverage:.2f}%")
    print("==================================================")
    
    print("\n[+] Documented Tags:")
    for tag, filepath, status in documented_tags:
        print(f"  - {tag:<10} in {filepath}{status}")
        
    if undocumented_tags:
        print("\n[-] Undocumented Tags:")
        for tag in undocumented_tags:
            print(f"  - {tag}")
    else:
        print("\n[+] No undocumented tags! Perfect documentation coverage.")
        
    # 4. Mermaid syntax validation
    print("\n[*] Validating Mermaid diagrams in markdown files...")
    mermaid_errors = validate_mermaid_diagrams(md_contents)
    
    has_mermaid_errors = False
    if mermaid_errors:
        has_mermaid_errors = True
        print("[-] Mermaid Syntax Errors Found:")
        for filepath, errors in sorted(mermaid_errors.items()):
            rel_path = os.path.relpath(filepath, project_root)
            print(f"  In {rel_path}:")
            for err in errors:
                print(f"    - {err}")
    else:
        print("[+] Mermaid syntax validation passed successfully.")
        
    print("\n==================================================")
    
    # 5. Exit code decision
    # Coverage must be > 95%
    coverage_ok = coverage > 95.0
    if not coverage_ok:
        print(f"[-] Verification failed: Tag coverage is {coverage:.2f}% (required > 95.0%)")
    if has_mermaid_errors:
        print("[-] Verification failed: Mermaid syntax errors present in documentation.")
        
    if coverage_ok and not has_mermaid_errors:
        print("[+] Verification SUCCESS! Coverage is > 95% and all Mermaid diagrams are valid.")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
