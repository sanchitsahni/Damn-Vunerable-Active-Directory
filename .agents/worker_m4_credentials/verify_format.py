import re

filepath = "/home/sanchit/DVWA/docs/03-credential-access.md"

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()

# Find all headings starting with ### CRED- or ### CLO-
pattern = r"### (CRED-\d+|CLO-\d+)\s*—\s*(.*)"
matches = list(re.finditer(pattern, content))

print(f"Total matching headings found: {len(matches)}")

expected_tags = []
for i in range(1, 131):
    expected_tags.append(f"CRED-{i:03d}")
for i in range(1, 96):
    expected_tags.append(f"CLO-{i:03d}")

found_tags = {}
for m in matches:
    tag = m.group(1)
    title = m.group(2).strip()
    found_tags[tag] = title

# Check for missing expected tags
missing = [t for t in expected_tags if t not in found_tags]
if missing:
    print(f"ERROR: Missing tags: {missing}")
else:
    print("All expected tags are present!")

# Check format for each found tag block
# A block is from the match to the next match or to the end of the credential list (or the next '---' or another heading)
for idx, m in enumerate(matches):
    tag = m.group(1)
    start_pos = m.start()
    end_pos = matches[idx+1].start() if idx+1 < len(matches) else len(content)
    block_text = content[start_pos:end_pos]
    
    # Check sections
    missing_sections = []
    for section in ["**What it is:**", "**Why it works here:**", "**Tools:**", "**Steps:**", "**Detection:**", "**Prevention:**"]:
        if section not in block_text:
            missing_sections.append(section)
            
    if missing_sections:
        print(f"Tag {tag} ({found_tags[tag]}) is missing sections: {missing_sections}")

print("Verification complete.")
