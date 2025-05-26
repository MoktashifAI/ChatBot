import os
import json
from typing import Tuple

def extract_text_from_txt(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def extract_text_from_json(file_path: str) -> str:
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        data = json.load(f)
    def recurse(obj):
        if isinstance(obj, dict):
            return ' '.join([recurse(v) for v in obj.values()])
        elif isinstance(obj, list):
            return ' '.join([recurse(v) for v in obj])
        else:
            return str(obj)
    return recurse(data)

def extract_text_from_pdf(file_path: str) -> str:
    try:
        from PyPDF2 import PdfReader
        reader = PdfReader(file_path)
        text = ''
        for page in reader.pages:
            text += page.extract_text() or ''
        return text
    except ImportError:
        raise RuntimeError("PyPDF2 is required for PDF parsing. Please install it.")

def extract_text_from_docx(file_path: str) -> str:
    try:
        import docx
        doc = docx.Document(file_path)
        return '\n'.join([para.text for para in doc.paragraphs])
    except ImportError:
        raise RuntimeError("python-docx is required for Word document parsing. Please install it.")

# --- Vuln TXT Parsing Helper ---
def parse_vuln_txt(text: str):
    """Parse a nuclei/format vuln.txt file into a list of findings (dicts)."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith('['):
            continue
        # Example: [swagger-api] [http] [info] http://localhost:3000/api-docs/swagger.json [paths="/api-docs/swagger.json"]
        parts = []
        curr = ''
        in_bracket = False
        for c in line:
            if c == '[':
                in_bracket = True
                curr = ''
            elif c == ']':
                in_bracket = False
                parts.append(curr.strip())
                curr = ''
            elif in_bracket:
                curr += c
            elif not in_bracket and c == ' ':
                continue
            elif not in_bracket:
                curr += c
        # After brackets, get the rest (e.g., URL and extras)
        rest = line
        for p in parts:
            rest = rest.replace(f'[{p}]', '', 1)
        rest = rest.strip()
        url = ''
        extras = ''
        if rest:
            url_split = rest.split(' ', 1)
            url = url_split[0]
            if len(url_split) > 1:
                extras = url_split[1]
        finding = {
            'tags': parts,
            'url': url,
            'extras': extras
        }
        findings.append(finding)
    return findings
# --- END Vuln TXT Parsing Helper ---

def extract_text(file_path: str) -> Tuple[str, str]:
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.txt':
        return extract_text_from_txt(file_path), 'txt'
    elif ext == '.json':
        return extract_text_from_json(file_path), 'json'
    elif ext == '.pdf':
        return extract_text_from_pdf(file_path), 'pdf'
    elif ext in ['.docx', '.doc']:
        return extract_text_from_docx(file_path), 'docx'
    else:
        raise ValueError(f"Unsupported file type: {ext}")

# --- Chunking Helper ---
def chunk_text(text: str, max_chars: int = 2000):
    """
    Split text into chunks of up to max_chars, attempting to split at line boundaries.
    Returns a list of text chunks.
    """
    lines = text.splitlines(keepends=True)
    chunks = []
    current_chunk = ''
    for line in lines:
        if len(current_chunk) + len(line) > max_chars:
            chunks.append(current_chunk)
            current_chunk = ''
        current_chunk += line
    if current_chunk:
        chunks.append(current_chunk)
    return chunks
# --- END Chunking Helper ---
