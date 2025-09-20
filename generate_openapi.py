import ast
import os
import json

class WhitelistVisitor(ast.NodeVisitor):
    def __init__(self):
        self.whitelists = []

    def visit_FunctionDef(self, node):
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call) and 
                isinstance(dec.func, ast.Attribute) and 
                dec.func.attr == 'whitelist' and 
                isinstance(dec.func.value, ast.Name) and 
                dec.func.value.id == 'frappe'
            ) or (
                isinstance(dec, ast.Name) and dec.id == 'whitelist'
            ):
                allow_guest = False
                if isinstance(dec, ast.Call) and dec.keywords:
                    for kw in dec.keywords:
                        if kw.arg == 'allow_guest' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            allow_guest = True
                # Extract parameters and their types
                params = []
                for arg in node.args.args:
                    if arg.arg != 'self':
                        param_type = 'string'  # Default type
                        if arg.annotation:
                            if isinstance(arg.annotation, ast.Name):
                                param_type = arg.annotation.id.lower()
                            elif isinstance(arg.annotation, ast.Subscript):
                                param_type = 'array' if isinstance(arg.annotation.value, ast.Name) and arg.annotation.value.id == 'list' else 'string'
                        params.append({'name': arg.arg, 'type': param_type})
                # Infer response from docstring or assume JSON
                docstring = ast.get_docstring(node) or ''
                response_schema = {"type": "object", "description": "JSON response"}
                if ':return:' in docstring.lower():
                    response_desc = docstring.split(':return:')[-1].strip().split('\n')[0]
                    response_schema["description"] = response_desc
                self.whitelists.append({
                    'name': node.name,
                    'file': '',
                    'line': node.lineno,
                    'allow_guest': allow_guest,
                    'docstring': docstring,
                    'parameters': params,
                    'response': response_schema
                })
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef):
                self.visit(child)

def parse_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=file_path)
        visitor = WhitelistVisitor()
        visitor.visit(tree)
        for wl in visitor.whitelists:
            wl['file'] = file_path
        ast_data = {
            'file': file_path,
            'whitelisted_methods': visitor.whitelists,
            'ast_dump': ast.dump(tree, indent=2)
        }
        return ast_data
    except (UnicodeDecodeError, SyntaxError):
        print(f"Skipping {file_path}: Unable to parse")
        return None


def get_module_path(root, file_path):
    # Get relative path and remove .py extension
    rel_path = os.path.relpath(file_path, root)
    if rel_path.endswith('.py'):
        rel_path = rel_path[:-3]  # Remove .py extension
    # Convert to module path
    module_path = rel_path.replace(os.sep, '.')
    # Split the path and remove the app name (first segment) if present
    path_parts = module_path.split('.')
    if len(path_parts) > 1:  # Ensure there's at least one segment after app name
        module_path = '.'.join(path_parts[1:])  # Skip the first part (app name)
    elif path_parts:  # Fallback to the first part if no deeper structure
        module_path = path_parts[0]
    else:
        module_path = ''  # Empty if invalid
    return module_path if module_path else 'default_module'  # Default to avoid empty paths
    
def build_openapi(root, functions):
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Frappe API", "version": "1.0.0"},
        "paths": {},
        "components": {
            "securitySchemes": {
                "basicAuth": {
                    "type": "http",
                    "scheme": "basic"
                }
            }
        },
        "security": [{"basicAuth": []}]
    }
    for ast_data in functions:
        for wl in ast_data['whitelisted_methods']:
            module = get_module_path(root, ast_data['file'])
            path = f"/api/method/{module}.{wl['name']}"
            operation = {
                "post": {
                    "summary": wl['docstring'].split('\n')[0] if wl['docstring'] else '',
                    "parameters": [
                        {
                            "name": param['name'],
                            "in": "query",
                            "schema": {"type": param['type']}
                        } for param in wl['parameters']
                    ],
                    "responses": {
                        "200": {
                            "description": wl['response']['description'],
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        }
                    },
                    "x-allow-guest": wl['allow_guest']
                }
            }
            if not wl['allow_guest']:
                operation["post"]["security"] = [{"basicAuth": []}]
            spec["paths"][path] = operation
    return spec

root_dir = './apps'
excluded = ['hooks.py', 'setup.py', '__init__.py', 'patches.py']
output_file = 'openapi.json'
openapi_spec_file =  'apps/swagger/swagger/www/swagger.json'

# Initialize or read existing JSON file for AST data
try:
    with open(output_file, 'r') as f:
        data = json.load(f)
    if not isinstance(data, list):
        data = []
except (FileNotFoundError, json.JSONDecodeError):
    data = []

# Collect AST and whitelisted methods
for dirpath, _, filenames in os.walk(root_dir):
    for fname in filenames:
        if fname.endswith('.py') and fname not in excluded:
            file_path = os.path.join(dirpath, fname)
            ast_data = parse_file(file_path)
            if ast_data:
                data.append(ast_data)

# Write updated AST data to file
with open(output_file, 'w') as f:
    json.dump(data, f, indent=4)

# Generate and write OpenAPI spec
openapi_spec = build_openapi(root_dir, data)
with open(openapi_spec_file, 'w') as f:
    json.dump(openapi_spec, f, indent=4)

# Print whitelisted methods with parameters and response
for entry in data:
    for method in entry['whitelisted_methods']:
        guest = " (allow_guest=True)" if method['allow_guest'] else ""
        params = ", ".join(f"{p['name']}:{p['type']}" for p in method['parameters'])
        print(f"Method: {method['name']}{guest} in {method['file']} at line {method['line']}")
        print(f"  Parameters: {params or 'None'}")
        print(f"  Response: {method['response']['description']}")
