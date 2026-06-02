# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re

# Standard header
HEADER_LINES = [
    "Copyright 2026 Google LLC",
    "",
    "Licensed under the Apache License, Version 2.0 (the \"License\");",
    "you may not use this file except in compliance with the License.",
    "You may obtain a copy of the License at",
    "",
    "    https://www.apache.org/licenses/LICENSE-2.0",
    "",
    "Unless required by applicable law or agreed to in writing, software",
    "distributed under the License is distributed on an \"AS IS\" BASIS,",
    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
    "See the License for the specific language governing permissions and",
    "limitations under the License."
]

def get_comment_syntax(extension):
    if extension in ['.py', '.sh', '.yaml', '.yml', '.tf', 'Dockerfile', '.rb', '.pl']:
        return '#', ''
    elif extension in ['.ts', '.tsx', '.js', '.css', '.java', '.c', '.cpp', '.h', '.proto']:
        return '/*', ' */'
    return None, None

def format_header(extension):
    prefix, suffix = get_comment_syntax(extension)
    if not prefix:
        return None
    
    out = []
    if prefix == '/*':
        out.append("/*")
        for line in HEADER_LINES:
            out.append(f" * {line}" if line else " *")
        out.append(" */")
        return "\n".join(out) + "\n\n"
        
    for line in HEADER_LINES:
        if line:
            out.append(f"{prefix} {line}")
        else:
            out.append(prefix)
            
    return "\n".join(out) + "\n\n"

def process_file(filepath):
    # Skip generated files
    if "pb2" in filepath or "generated" in filepath:
        return

    _, ext = os.path.splitext(filepath)
    filename = os.path.basename(filepath)
    if filename.startswith('Dockerfile'):
        ext = 'Dockerfile'
        
    formatted_header = format_header(ext)
    if not formatted_header:
        return

    with open(filepath, 'r') as f:
        lines = f.readlines()

    # Special handling for shebang
    start_idx = 0
    if lines and lines[0].startswith('#!'):
        start_idx = 1
        # Skip empty lines after shebang
        while start_idx < len(lines) and not lines[start_idx].strip():
            start_idx += 1

    header_end_idx = start_idx
    
    if "nemo_actions.py" in filepath:
        # Find where docstring starts
        docstring_idx = -1
        for i, line in enumerate(lines):
            if '"""' in line or "'''" in line:
                docstring_idx = i
                break
        if docstring_idx != -1:
            header_end_idx = docstring_idx
    else:
        # Generic header detection: skip all comment lines at the top that look like headers
        i = start_idx
        while i < len(lines):
            line = lines[i].strip()
            if not line:
                i += 1
                continue
            if line.startswith('#') or line.startswith('//'):
                i += 1
                header_end_idx = i
            elif line.startswith('/*'):
                # Skip until end of block
                while i < len(lines) and '*/' not in lines[i]:
                    i += 1
                i += 1
                header_end_idx = i
            else:
                break

    # Reconstruct
    remaining_lines = lines[header_end_idx:]
    
    # Strip leading empty lines from remaining
    while remaining_lines and not remaining_lines[0].strip():
        remaining_lines.pop(0)
        
    final_content = ""
    if start_idx > 0 and lines[0].startswith('#!'):
        final_content += lines[0]
        if not lines[0].endswith('\n'):
            final_content += '\n'
        
    final_content += formatted_header + "".join(remaining_lines)
    
    with open(filepath, 'w') as f:
        f.write(final_content)
    print(f"Updated {filepath}")

def main():
    exclude_dirs = {'.venv', 'venv', '.git', '.idea', '.vscode', 'node_modules', '__pycache__', 'dist', 'build', 'plans', 'compliance', 'mcp-servers', 'assets'}
    
    # Root level files
    root_files = [f for f in os.listdir('.') if os.path.isfile(f)]
    for file in root_files:
        if file.endswith(('.py', '.sh', '.yaml', '.yml', '.tf', '.ts', '.tsx', '.js', '.css', '.proto')) or file.startswith('Dockerfile'):
            process_file(file)

    # Walk through target directories
    target_dirs = ['src', 'infra', 'deployment', 'scripts', 'config', 'tests', '.github']
    
    for target_dir in target_dirs:
        if not os.path.exists(target_dir):
            continue
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if file.endswith(('.py', '.sh', '.yaml', '.yml', '.tf', '.ts', '.tsx', '.js', '.css', '.proto')) or file.startswith('Dockerfile'):
                    process_file(os.path.join(root, file))

if __name__ == '__main__':
    main()
