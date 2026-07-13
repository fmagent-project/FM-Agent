from src.spec_storage import (
    format_spec_for_reasoner,
    info_to_function_spec_map,
    read_info,
    read_spec,
)


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
    Parse an implementation and its two adjacent structured metadata files.
    
    Returns:
        tuple: (func, nl_spec, knowledge)
    """
    with open(file_path, 'r') as file:
        content = file.read()
    spec_data = read_spec(file_path)
    info_data = read_info(file_path)
    func = _remove_func_comments(content)

    # Add line numbers to each line in func
    func_lines = func.split('\n')
    numbered_lines = [f"Line {i+1}: {line}" for i, line in enumerate(func_lines)]
    func = '\n'.join(numbered_lines)

    return (
        func,
        format_spec_for_reasoner(spec_data),
        info_to_function_spec_map(info_data),
    )
