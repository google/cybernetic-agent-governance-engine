#!/usr/bin/env python3
import os
import json

paths = [
    '/Users/larsahlfors/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json',
    '/Users/larsahlfors/Library/Application Support/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json',
    '/Users/larsahlfors/Library/Application Support/Cursor/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json'
]

source_configs = [
    '/Users/larsahlfors/.gemini/antigravity/mcp_config.json',
    '/Users/larsahlfors/.gemini/antigravity-ide/mcp_config.json'
]

def fix_configs():
    # 1. Load source config
    config_data = {}
    for src in source_configs:
        if os.path.exists(src):
            try:
                with open(src, 'r') as f:
                    data = json.load(f)
                    # Merge mcpServers
                    if 'mcpServers' in data:
                        if 'mcpServers' not in config_data:
                            config_data['mcpServers'] = {}
                        config_data['mcpServers'].update(data['mcpServers'])
            except Exception as e:
                print(f"Error reading {src}: {e}")

    if not config_data or 'mcpServers' not in config_data:
        print("Could not load any source MCP config data.")
        return

    # Create filtered version for Roo Code / Cline (no google-developer-knowledge)
    filtered_mcp_servers = {}
    for name, server_cfg in config_data.get('mcpServers', {}).items():
        if name != 'google-developer-knowledge':
            filtered_mcp_servers[name] = server_cfg

    filtered_config = {'mcpServers': filtered_mcp_servers}

    # 2. Fix the target files
    for path in paths:
        dir_name = os.path.dirname(path)
        
        # Check if directory or file exists (lstat to handle broken links)
        try:
            link_exists = False
            try:
                os.lstat(path)
                link_exists = True
            except FileNotFoundError:
                pass

            if link_exists:
                print(f"Removing existing file/link: {path}")
                os.unlink(path)

            # Ensure parent directory exists
            if not os.path.exists(dir_name):
                os.makedirs(dir_name, exist_ok=True)

            print(f"Writing filtered config to: {path}")
            with open(path, 'w') as f:
                json.dump(filtered_config, f, indent=2)
                f.write('\n')
        except Exception as e:
            print(f"Error processing {path}: {e}")

if __name__ == '__main__':
    fix_configs()
