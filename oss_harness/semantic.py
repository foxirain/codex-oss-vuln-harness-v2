from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from oss_harness.models import SymbolHint

GENERIC_FUNCTION_PATTERNS = {
    'javascript': re.compile(r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?\([^\)]*\)\s*=>|([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?:async\s*)?function\s*\(", re.MULTILINE),
    'go': re.compile(r'^\s*func\s+(?:\([^\)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.MULTILINE),
    'rust': re.compile(r'^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.MULTILINE),
    'java': re.compile(r'^\s*(?:public|private|protected)?\s*(?:static\s+)?[A-Za-z0-9_<>,\[\]\?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.MULTILINE),
    'php': re.compile(r'function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', re.MULTILINE),
    'ruby': re.compile(r'^\s*def\s+([A-Za-z_][A-Za-z0-9_\?\!]*)', re.MULTILINE),
    'c_cpp': re.compile(r'^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{', re.MULTILINE),
}

GENERIC_ENTRYPOINT_PATTERNS = {
    'javascript': [re.compile(r'\b(app|router)\.(get|post|put|patch|delete|use)\s*\('), re.compile(r'@Controller\(|@Get\(|@Post\(')],
    'go': [re.compile(r'\b(router\.(GET|POST|PUT|PATCH|DELETE)|http\.HandleFunc|HandleFunc\()')],
    'rust': [re.compile(r'\b(route|Router::new|HttpServer::new|get\(|post\()')],
    'java': [re.compile(r'@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)')],
    'php': [re.compile(r'Route::(get|post|put|patch|delete|match)')],
    'ruby': [re.compile(r'\b(get|post|put|patch|delete)\s+[\'\"]|resources\s+:')],
}

SINK_PATTERNS = [
    ('command execution', re.compile(r'\b(exec|spawn|system|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|subprocess\.|os\.system|std::process::Command|shell_exec|passthru)\b')),
    ('deserialization', re.compile(r'\b(pickle\.loads|yaml\.load|serde_json::from_str|ObjectInputStream|unserialize|YAML\.load|bincode::deserialize|eval\()')),
    ('filesystem', re.compile(r'\b(readFile|writeFile|std::fs::|Files\.(read|write)|file_get_contents|File\.(read|write)|fopen|unlink|open\()')),
    ('memory-sensitive', re.compile(r'\b(unsafe|memcpy|strcpy|reinterpret_cast|transmute|from_raw_parts|malloc|free|new\s|delete\s)')),
    ('outbound request', re.compile(r'\b(requests\.|httpx\.|fetch\(|axios\.|got\(|urllib\.request|reqwest::|http\.Client|Net::HTTP)')),
]

REQUEST_PATTERNS = [
    re.compile(r'\b(request|req)\.(args|json|form|files|get_json|body|params|query|headers)\b'),
    re.compile(r'\b(HttpServletRequest|MultipartFile|Json<|Path<|Query<|HttpRequest|params\[|\$_(GET|POST|REQUEST|FILES))\b'),
]


@dataclass(slots=True)
class SemanticFile:
    symbols: list[SymbolHint] = field(default_factory=list)
    summaries: list[str] = field(default_factory=list)
    entrypoint_lines: list[int] = field(default_factory=list)
    sink_lines: list[int] = field(default_factory=list)
    request_lines: list[int] = field(default_factory=list)


def build_semantic_index(repo_root: Path, language_map: dict[str, str], max_files: int = 2500) -> dict[str, SemanticFile]:
    index: dict[str, SemanticFile] = {}
    for rel_path in sorted(language_map)[:max_files]:
        language = language_map[rel_path]
        file_path = repo_root / rel_path
        try:
            text = file_path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        if language == 'python':
            index[rel_path] = _analyze_python(text)
        else:
            index[rel_path] = _analyze_generic(language, text)
    return index


def _analyze_python(text: str) -> SemanticFile:
    result = SemanticFile()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return result
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            tags: set[str] = set()
            score = 0
            for decorator in node.decorator_list:
                decorator_text = ast.unparse(decorator) if hasattr(ast, 'unparse') else ''
                lowered = decorator_text.lower()
                if any(token in lowered for token in ('route', 'get', 'post', 'put', 'patch', 'delete', 'router.', 'app.')):
                    tags.add('entrypoint')
                    score += 8
                    result.entrypoint_lines.append(node.lineno)
            call_names: list[str] = []
            for inner in ast.walk(node):
                if isinstance(inner, ast.Call):
                    name = _python_call_name(inner.func)
                    if name:
                        call_names.append(name)
                        lowered = name.lower()
                        if any(token in lowered for token in ('exec', 'system', 'subprocess', 'popen', 'pickle.loads', 'yaml.load', 'render_template_string', 'requests.', 'httpx.', 'open')):
                            score += 3
                            tags.add('sink')
                            result.sink_lines.append(getattr(inner, 'lineno', node.lineno))
                if isinstance(inner, ast.Attribute):
                    attr = inner.attr.lower()
                    if attr in {'args', 'json', 'form', 'files', 'headers'}:
                        score += 2
                        tags.add('request')
                        result.request_lines.append(getattr(inner, 'lineno', node.lineno))
            if any(name in call_names for name in ('authorize', 'is_admin', 'check_permission')):
                tags.add('authz')
                score += 2
            result.symbols.append(
                SymbolHint(
                    name=node.name,
                    kind='function',
                    line_start=node.lineno,
                    line_end=getattr(node, 'end_lineno', node.lineno),
                    score=score,
                    tags=sorted(tags),
                )
            )
        elif isinstance(node, ast.ClassDef):
            class_tags: set[str] = set()
            if any(getattr(base, 'id', '').endswith('View') or getattr(base, 'attr', '').endswith('View') for base in node.bases):
                class_tags.add('handler')
            result.symbols.append(
                SymbolHint(
                    name=node.name,
                    kind='class',
                    line_start=node.lineno,
                    line_end=getattr(node, 'end_lineno', node.lineno),
                    score=2 if class_tags else 0,
                    tags=sorted(class_tags),
                )
            )
    result.symbols.sort(key=lambda item: (-item.score, item.line_start, item.name))
    if result.entrypoint_lines:
        result.summaries.append(f'python entrypoint-like symbols: {len(result.entrypoint_lines)}')
    if result.sink_lines:
        result.summaries.append(f'python sink calls: {len(result.sink_lines)}')
    if result.request_lines:
        result.summaries.append(f'python request accesses: {len(result.request_lines)}')
    return result


def _python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_call_name(node.value)
        return f'{base}.{node.attr}'.strip('.')
    return ''


def _analyze_generic(language: str, text: str) -> SemanticFile:
    result = SemanticFile()
    func_pattern = GENERIC_FUNCTION_PATTERNS.get(language)
    line_count = text.count('\n') + 1
    if func_pattern:
        for match in func_pattern.finditer(text):
            name = next((group for group in match.groups() if group), '') if match.groups() else match.group(1)
            if not name:
                continue
            line_start = text.count('\n', 0, match.start()) + 1
            line_end = min(line_start + 24, line_count)
            tags: set[str] = set()
            score = 0
            snippet = text[match.start(): match.start() + 600]
            if any(pattern.search(snippet) for pattern in GENERIC_ENTRYPOINT_PATTERNS.get(language, [])):
                tags.add('entrypoint')
                score += 7
                result.entrypoint_lines.append(line_start)
            for sink_name, sink_pattern in SINK_PATTERNS:
                if sink_pattern.search(snippet):
                    tags.add(sink_name)
                    score += 3
                    result.sink_lines.append(line_start)
            if any(pattern.search(snippet) for pattern in REQUEST_PATTERNS):
                tags.add('request')
                score += 2
                result.request_lines.append(line_start)
            result.symbols.append(SymbolHint(name=name, kind='function', line_start=line_start, line_end=line_end, score=score, tags=sorted(tags)))
    for pattern in GENERIC_ENTRYPOINT_PATTERNS.get(language, []):
        for match in pattern.finditer(text):
            result.entrypoint_lines.append(text.count('\n', 0, match.start()) + 1)
    for _, sink_pattern in SINK_PATTERNS:
        for match in sink_pattern.finditer(text):
            result.sink_lines.append(text.count('\n', 0, match.start()) + 1)
    for pattern in REQUEST_PATTERNS:
        for match in pattern.finditer(text):
            result.request_lines.append(text.count('\n', 0, match.start()) + 1)
    result.symbols.sort(key=lambda item: (-item.score, item.line_start, item.name))
    if result.entrypoint_lines:
        result.summaries.append(f'{language} entrypoint-like hits: {len(result.entrypoint_lines)}')
    if result.sink_lines:
        result.summaries.append(f'{language} sink-like hits: {len(result.sink_lines)}')
    if result.request_lines:
        result.summaries.append(f'{language} request-like hits: {len(result.request_lines)}')
    return result
