import argparse
import logging
import os
import re
import sys
from typing import List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Analyze web application code for CSRF token implementation.")
    parser.add_argument("source_code_path", help="Path to the source code directory or file.")
    parser.add_argument("--token_name", default="csrf_token", help="Name of the CSRF token (default: csrf_token).")
    parser.add_argument("--form_field", default="csrf_token", help="Name of the CSRF form field (default: csrf_token).")
    parser.add_argument("--exclude", nargs='+', default=[], help="List of files or directories to exclude.")

    return parser


def is_token_generation_present(code: str, token_name: str) -> bool:
    """
    Checks if CSRF token generation logic is present in the code.

    Args:
        code: The code snippet to analyze.
        token_name: The name of the CSRF token variable.

    Returns:
        bool: True if token generation is found, False otherwise.
    """
    # Look for patterns like token = generate_token() or token = os.urandom(24)
    patterns = [
        rf"{token_name}\s*=\s*([a-zA-Z0-9_]+\.)?generate[_]*token\s*\(.*\)",
        rf"{token_name}\s*=\s*secrets\.token_hex\s*\(.*\)",  # Check secrets module (Python 3.6+)
        rf"{token_name}\s*=\s*os\.urandom\s*\(.*\)",
        rf"{token_name}\s*=\s*uuid\.uuid4\s*\(.*\)"
    ]
    for pattern in patterns:
        if re.search(pattern, code):
            return True

    return False


def is_token_validation_present(code: str, token_name: str, form_field: str) -> bool:
    """
    Checks if CSRF token validation logic is present in the code.

    Args:
        code: The code snippet to analyze.
        token_name: The name of the CSRF token variable.
        form_field: The name of the form field containing the CSRF token.

    Returns:
        bool: True if token validation is found, False otherwise.
    """
    # Look for patterns like if request.form['csrf_token'] != session['csrf_token']:
    # Or if request.POST.get('csrf_token') != session['csrf_token']:
    patterns = [
        rf"if\s+request\.(form|POST)\s*\[['\"]{form_field}['\"]\].*!=\s*{token_name}.*",  # Check form submissions
        rf"if\s+request\.(form|POST)\.get\s*\(['\"]{form_field}['\"]\].*!=\s*{token_name}.*", # Check form submissions with get
        rf"if\s+session\s*\[['\"]{token_name}['\"]\].*!=\s*request\.(form|POST)\s*\[['\"]{form_field}['\"]].*",
        rf"if\s+session\s*\[['\"]{token_name}['\"]\].*!=\s*request\.(form|POST)\.get\s*\(['\"]{form_field}['\"]].*"
    ]

    for pattern in patterns:
        if re.search(pattern, code):
            return True

    return False


def analyze_file(file_path: str, token_name: str, form_field: str) -> Tuple[bool, bool]:
    """
    Analyzes a single file for CSRF token generation and validation.

    Args:
        file_path: The path to the file to analyze.
        token_name: The name of the CSRF token.
        form_field: The name of the form field containing the CSRF token.

    Returns:
        Tuple[bool, bool]: A tuple containing two booleans:
            - True if token generation is found, False otherwise.
            - True if token validation is found, False otherwise.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return False, False
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return False, False

    generation_found = is_token_generation_present(code, token_name)
    validation_found = is_token_validation_present(code, token_name, form_field)

    return generation_found, validation_found


def analyze_directory(dir_path: str, token_name: str, form_field: str, exclude: List[str]) -> Tuple[bool, bool]:
    """
    Analyzes all Python files in a directory (recursively) for CSRF token generation and validation.

    Args:
        dir_path: The path to the directory to analyze.
        token_name: The name of the CSRF token.
        form_field: The name of the form field containing the CSRF token.
        exclude: A list of files and directories to exclude from analysis.

    Returns:
        Tuple[bool, bool]: A tuple containing two booleans:
            - True if token generation is found in at least one file, False otherwise.
            - True if token validation is found in at least one file, False otherwise.
    """
    generation_found = False
    validation_found = False

    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)

                # Check if the file or directory should be excluded
                if any(os.path.normpath(os.path.join(dir_path, ex)) == os.path.normpath(file_path) or os.path.normpath(os.path.join(dir_path, ex)) in os.path.normpath(file_path) for ex in exclude):
                    logging.info(f"Skipping excluded file: {file_path}")
                    continue

                gen, val = analyze_file(file_path, token_name, form_field)
                generation_found = generation_found or gen
                validation_found = validation_found or val

    return generation_found, validation_found


def main():
    """
    Main function to drive the CSRF token analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    source_code_path = args.source_code_path
    token_name = args.token_name
    form_field = args.form_field
    exclude = args.exclude

    # Validate token_name and form_field
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", token_name) or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", form_field):
        logging.error("Invalid token_name or form_field.  Must start with a letter or underscore and contain only alphanumeric characters and underscores.")
        sys.exit(1)

    if os.path.isfile(source_code_path):
        generation_found, validation_found = analyze_file(source_code_path, token_name, form_field)
    elif os.path.isdir(source_code_path):
        generation_found, validation_found = analyze_directory(source_code_path, token_name, form_field, exclude)
    else:
        logging.error(f"Invalid source code path: {source_code_path}")
        sys.exit(1)

    if generation_found:
        logging.info("CSRF token generation logic found.")
    else:
        logging.warning("CSRF token generation logic NOT found.")

    if validation_found:
        logging.info("CSRF token validation logic found.")
    else:
        logging.warning("CSRF token validation logic NOT found.")


if __name__ == "__main__":
    # Usage examples:
    # python main.py my_web_app.py
    # python main.py my_web_app_directory --token_name custom_token --form_field custom_field
    # python main.py my_web_app_directory --exclude utils.py helpers.py
    main()