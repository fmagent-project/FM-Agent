import re


_SECTION_MARKER_RE = re.compile(r'^\s*(?:(?://+|#+|--+|%+)\s*)?\[(SPEC|INFO)\]\s*$')
_SPLIT_MARKER_RE = re.compile(r'^\s*\[SPLIT\]\s*$', re.MULTILINE)


class FunctionSpecMap(dict):
    def __init__(self):
        super().__init__()
        self.signatures = {}

    def add_entry(self, function_name, signature, spec):
        self[function_name] = spec
        self.signatures[function_name] = signature

    def __str__(self):
        formatted_entries = []
        for function_name, spec in self.items():
            signature = self.signatures.get(function_name, function_name)
            if spec:
                formatted_entries.append(f"{signature}\n{spec}")
            else:
                formatted_entries.append(signature)
        return "\n\n".join(formatted_entries)


def _strip_section_comment_prefix(line):
    return re.sub(r'^(\s*)//+ ?', r'\1', line)


def _extract_marked_section(lines, marker):
    start_idx = None
    end_idx = None
    collected_lines = []

    for index, line in enumerate(lines):
        marker_match = _SECTION_MARKER_RE.match(line)
        if marker_match and marker_match.group(1) == marker:
            if start_idx is None:
                start_idx = index
            else:
                end_idx = index
                break
            continue

        if start_idx is not None and end_idx is None:
            collected_lines.append(_strip_section_comment_prefix(line))

    section_text = '\n'.join(collected_lines).strip() if end_idx is not None else ""
    return section_text, start_idx, end_idx


def _extract_function_name(signature_line):
    match = re.search(r'([A-Za-z_][A-Za-z0-9_]*)\s*\(', signature_line)
    return match.group(1) if match else None


def _parse_info_section(section_text):
    if not section_text.strip() or section_text.strip() == "(no callees)":
        return FunctionSpecMap()

    knowledge_map = FunctionSpecMap()
    entries = _SPLIT_MARKER_RE.split(section_text)

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue

        entry_lines = [line.rstrip() for line in entry.splitlines() if line.strip()]
        if not entry_lines:
            continue

        function_name = _extract_function_name(entry_lines[0])
        if function_name is None:
            continue

        knowledge_map.add_entry(
            function_name,
            entry_lines[0],
            '\n'.join(entry_lines[1:]).strip(),
        )

    return knowledge_map


def _remove_func_comments(code):
    result = []
    index = 0
    in_block_comment = False
    in_string = False
    string_delimiter = ""
    line_start = True

    while index < len(code):
        char = code[index]
        next_char = code[index + 1] if index + 1 < len(code) else ""

        if in_block_comment:
            if char == '*' and next_char == '/':
                in_block_comment = False
                index += 2
                continue
            if char == '\n':
                result.append(char)
                line_start = True
            index += 1
            continue

        if in_string:
            result.append(char)
            if char == '\\' and index + 1 < len(code):
                result.append(code[index + 1])
                index += 2
                continue
            if char == string_delimiter:
                in_string = False
            line_start = char == '\n'
            index += 1
            continue

        if char in ('"', "'"):
            in_string = True
            string_delimiter = char
            result.append(char)
            line_start = False
            index += 1
            continue

        if char == '/' and next_char == '*':
            in_block_comment = True
            index += 2
            continue

        if char == '/' and next_char == '/':
            index += 2
            while index < len(code) and code[index] != '\n':
                index += 1
            continue

        if char == '#' and not line_start:
            while index < len(code) and code[index] != '\n':
                index += 1
            continue

        result.append(char)
        if char == '\n':
            line_start = True
        elif not char.isspace():
            line_start = False
        index += 1

    cleaned_lines = [line for line in ''.join(result).split('\n') if line.strip()]
    return '\n'.join(cleaned_lines)

def parse_input_function(file_path):
    """
    Parse a file with three parts:
    1. func: remaining lines after the closing [INFO] block, with comments removed
    2. nl_spec: lines between two standalone [SPEC] marker lines
    3. knowledge: a map from function name to spec parsed from the [INFO] block
    
    Returns:
        tuple: (func, nl_spec, knowledge)
    """
    with open(file_path, 'r') as file:
        content = file.read()

    lines = content.splitlines()

    nl_spec, _, spec_end_idx = _extract_marked_section(lines, "SPEC")
    knowledge_text, _, info_end_idx = _extract_marked_section(lines, "INFO")
    knowledge = _parse_info_section(knowledge_text)

    # func: after the closing [INFO] marker if present, else after [SPEC], else all
    func = ""
    if info_end_idx is not None:
        func = '\n'.join(lines[info_end_idx + 1:]).lstrip('\n')
    elif spec_end_idx is not None:
        func = '\n'.join(lines[spec_end_idx + 1:]).lstrip('\n')
    else:
        func = content

    func = _remove_func_comments(func)

    # Add line numbers to each line in func
    func_lines = func.split('\n')
    numbered_lines = [f"Line {i+1}: {line}" for i, line in enumerate(func_lines)]
    func = '\n'.join(numbered_lines)

    return func, nl_spec, knowledge
