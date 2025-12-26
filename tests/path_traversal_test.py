#!/usr/bin/env python3
"""
Test file with Path Traversal and File Handling vulnerabilities
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""

import os
import pickle
import yaml
import json

class FileHandler:
    def read_user_file(self, filename):
        # VULNERABILITY: Path Traversal - no sanitization
        with open(filename, 'r') as f:
            return f.read()
    
    def write_log(self, log_dir, log_name, content):
        # VULNERABILITY: Path Traversal - directory concatenation
        log_path = log_dir + "/" + log_name
        with open(log_path, 'w') as f:
            f.write(content)
    
    def load_config(self, config_name):
        # VULNERABILITY: Path Traversal - user-controlled path
        config_path = f"/etc/app/configs/{config_name}"
        with open(config_path, 'r') as f:
            return f.read()
    
    def delete_temp_file(self, temp_id):
        # VULNERABILITY: Path Traversal - file deletion
        file_path = "/tmp/" + temp_id
        os.remove(file_path)
    
    def serve_static_file(self, requested_file):
        # VULNERABILITY: Path Traversal - web file serving
        base_dir = "/var/www/static"
        file_path = os.path.join(base_dir, requested_file)
        with open(file_path, 'rb') as f:
            return f.read()

class DataSerializer:
    def load_user_data(self, data_file):
        # VULNERABILITY: Insecure Deserialization - pickle
        with open(data_file, 'rb') as f:
            return pickle.load(f)
    
    def save_session(self, session_data, session_id):
        # VULNERABILITY: Insecure Deserialization - pickle dump
        filename = f"/tmp/session_{session_id}.pkl"
        with open(filename, 'wb') as f:
            pickle.dump(session_data, f)
    
    def load_yaml_config(self, config_file):
        # VULNERABILITY: YAML deserialization - unsafe load
        with open(config_file, 'r') as f:
            return yaml.load(f)
    
    def process_user_input(self, user_data):
        # VULNERABILITY: eval() on user input
        result = eval(user_data)
        return result
    
    def execute_code(self, code_string):
        # VULNERABILITY: exec() on user input
        exec(code_string)

class TemplateRenderer:
    def render_template(self, template_name, context):
        # VULNERABILITY: Path Traversal in template loading
        template_path = f"templates/{template_name}"
        with open(template_path, 'r') as f:
            template = f.read()
        
        # VULNERABILITY: eval in template rendering
        for key, value in context.items():
            template = template.replace(f"{{{{{key}}}}}", str(eval(value)))
        
        return template
    
    def include_file(self, include_path):
        # VULNERABILITY: Arbitrary file inclusion
        with open(include_path, 'r') as f:
            return f.read()

class FileUploader:
    def save_upload(self, uploaded_file, filename):
        # VULNERABILITY: No file type validation
        upload_dir = "/var/uploads"
        file_path = os.path.join(upload_dir, filename)
        with open(file_path, 'wb') as f:
            f.write(uploaded_file)
    
    def process_archive(self, archive_path):
        # VULNERABILITY: Zip slip - no path validation during extraction
        import zipfile
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall("/tmp/extracted")
