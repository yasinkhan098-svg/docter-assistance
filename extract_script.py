
import os

html_path = r'e:\Developer\alag docter\New folder\deploy\public\index.html'
js_path = r'e:\Developer\alag docter\New folder\deploy\public\main_script_extracted.js'

with open(html_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Lines are 1-indexed in my previous view_file calls.
# Line 2881 to 12130 (inside the <script> tag)
# In 0-indexing, that's [2880:12130]
script_lines = lines[2880:12130]

with open(js_path, 'w', encoding='utf-8') as f:
    f.writelines(script_lines)

print(f"Extracted {len(script_lines)} lines to {js_path}")
