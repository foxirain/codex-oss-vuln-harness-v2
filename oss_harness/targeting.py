from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from pathlib import Path

from oss_harness.external import load_crash_signal_index, load_external_signal_index
from oss_harness.sbom import load_sbom_signal_index
from oss_harness.graph import build_import_graph
from oss_harness.history import collect_git_history_signals
from oss_harness.models import Candidate, ExternalSignal, LanguageStat, Signal
from oss_harness.semantic import build_semantic_index
from oss_harness.policy import policy_list

COMMON_EXCLUDE_DIRS = {
    '.git', '.github', '.venv', '.next', '.nuxt', '.tox', '.mypy_cache', '.pytest_cache',
    '__pycache__', 'build', 'dist', 'coverage', 'node_modules', 'vendor', 'third_party',
    'third-party', 'deps', 'target', 'tmp', 'out',
}

DEFAULT_EXCLUDED_FILE_PATTERNS = [
    re.compile(r'(^|/)(tests?|spec|specs|fixtures|examples?|samples?|demo|benchmarks?)(/|$)', re.IGNORECASE),
    re.compile(r'(^|/)(generated|gen|mock|mocks|vendor|dist|coverage)(/|$)', re.IGNORECASE),
    re.compile(r'(_test|_unittest|unittest|\.test|\.spec|\.min)\.', re.IGNORECASE),
]

FRAMEWORK_MARKERS = {
    'fastapi': [r'\bFastAPI\b', r'from fastapi import', r'fastapi\.'],
    'django': [r'from django\.', r'\bdjango\.urls\b', r'urlpatterns\s*='],
    'flask': [r'from flask import', r'\bFlask\(', r'blueprint'],
    'express': [r'require\([\'"]express[\'"]\)', r'from express import', r'\bexpress\('],
    'nestjs': [r'@Controller\(', r'@Injectable\(', r'@Module\('],
    'spring': [r'@RestController', r'@RequestMapping', r'@GetMapping'],
    'gin': [r'gin\.Default\(', r'gin\.New\('],
    'echo': [r'echo\.New\('],
    'actix': [r'actix_web', r'HttpServer::new'],
    'axum': [r'axum::', r'Router::new'],
    'rails': [r'class .*Controller < ApplicationController', r'Rails\.application\.routes'],
    'laravel': [r'Route::(get|post|put|patch|delete)', r'Illuminate\\'],
}

REPO_FILES = {
    'python': ['pyproject.toml', 'requirements.txt', 'setup.py'],
    'javascript': ['package.json', 'pnpm-lock.yaml', 'yarn.lock'],
    'go': ['go.mod'],
    'rust': ['Cargo.toml'],
    'java': ['pom.xml', 'build.gradle', 'settings.gradle'],
    'php': ['composer.json'],
    'ruby': ['Gemfile'],
}

LANGUAGE_RULES = {
    'python': {
        'extensions': {'.py'},
        'path_rules': [('/api/', 11, 'API routing layer'), ('/routes/', 10, 'route handler directory'), ('/views/', 9, 'request handler directory'), ('/auth', 8, 'authentication boundary'), ('/upload', 9, 'file ingestion boundary'), ('/parser', 8, 'parser boundary')],
        'patterns': [
            ('route_decorator', r'@(app|router|bp|blueprint)\.(get|post|put|patch|delete|route)|@route', 10, 'request entrypoint decorator'),
            ('request_access', r'\b(request|req)\.(args|json|form|files|get_json|headers)\b|\bQuery\(|\bBody\(', 8, 'user-controlled request data'),
            ('subprocess', r'\b(subprocess\.(Popen|run|call|check_output)|os\.system)\b', 10, 'command execution sink'),
            ('deserialization', r'\b(pickle\.loads|yaml\.load\(|marshal\.loads|eval\(|exec\()', 10, 'unsafe code or object loading'),
            ('filesystem', r'\b(open\(|send_file\(|FileResponse\(|shutil\.(unpack_archive|rmtree|copyfile))', 7, 'filesystem sink near attacker input'),
            ('template_sink', r'\b(render_template_string|jinja2\.Template|Markup\()', 8, 'template injection or XSS sink'),
            ('ssrf_sink', r'\b(requests\.(get|post|request)|httpx\.(get|post|request)|urllib\.request)\b', 7, 'outbound request sink'),
        ],
    },
    'javascript': {
        'extensions': {'.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'},
        'path_rules': [('/api/', 11, 'API routing layer'), ('/routes/', 10, 'route handler directory'), ('/controllers/', 9, 'controller boundary'), ('/middleware/', 7, 'middleware boundary'), ('/upload', 9, 'file ingestion boundary')],
        'patterns': [
            ('express_route', r'\b(app|router)\.(get|post|put|patch|delete|use)\s*\(', 10, 'HTTP route registration'),
            ('request_access', r'\b(req|request)\.(body|query|params|headers|files)\b|\bctx\.request\b', 8, 'user-controlled request data'),
            ('command_exec', r'\b(child_process\.(exec|execSync|spawn|spawnSync)|exec\(|spawn\()', 10, 'command execution sink'),
            ('filesystem', r'\b(fs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)|sendFile\()', 7, 'filesystem sink near attacker input'),
            ('deserialization', r'\b(eval\(|Function\(|vm\.runIn(New)?Context|serialize-javascript|yaml\.load)\b', 9, 'unsafe evaluation or deserialization'),
            ('ssrf_sink', r'\b(fetch\(|axios\.(get|post|request)|got\()', 7, 'outbound request sink'),
        ],
    },
    'go': {
        'extensions': {'.go'},
        'path_rules': [('/api/', 11, 'API routing layer'), ('/handlers/', 10, 'request handler directory'), ('/grpc/', 8, 'gRPC boundary'), ('/transport/', 8, 'transport boundary'), ('/auth', 8, 'authentication boundary')],
        'patterns': [
            ('http_handler', r'\b(http\.HandleFunc|HandleFunc\(|router\.(GET|POST|PUT|PATCH|DELETE)|gin\.(Default|New)\(|echo\.New\()', 10, 'HTTP entrypoint'),
            ('request_access', r'\b(r|req)\.(URL|Form|PostForm|MultipartForm|Header)\b|ShouldBind(JSON|Query|Body)|BindJSON\(', 8, 'user-controlled request data'),
            ('command_exec', r'\b(exec\.Command|syscall\.Exec)\b', 10, 'command execution sink'),
            ('filesystem', r'\b(os\.(Open|OpenFile|Create|WriteFile|ReadFile)|ioutil\.(ReadFile|WriteFile))\b', 7, 'filesystem sink near attacker input'),
            ('unsafe', r'\bunsafe\.|reflect\.(NewAt|SliceHeader)|binary\.Read\(', 8, 'unsafe memory or parser boundary'),
        ],
    },
    'rust': {
        'extensions': {'.rs'},
        'path_rules': [('/api/', 11, 'API routing layer'), ('/handlers/', 10, 'request handler directory'), ('/ffi', 9, 'FFI boundary'), ('/parser', 8, 'parser boundary'), ('/auth', 8, 'authentication boundary')],
        'patterns': [
            ('http_route', r'\b(route|Router::new|App::new|HttpServer::new|get\(|post\(|put\()', 9, 'HTTP entrypoint'),
            ('request_access', r'\b(Json<|Path<|Query<|Multipart|HttpRequest|web::Data<)\b', 7, 'user-controlled request data'),
            ('command_exec', r'\b(std::process::Command|Command::new)\b', 10, 'command execution sink'),
            ('filesystem', r'\b(std::fs::(read|read_to_string|write|File::open|OpenOptions))\b', 7, 'filesystem sink near attacker input'),
            ('unsafe', r'\bunsafe\b|from_utf8_unchecked|transmute|slice::from_raw_parts', 9, 'unsafe or memory-sensitive code'),
            ('deserialization', r'\b(serde_json::from_str|serde_yaml::from_str|bincode::deserialize)\b', 7, 'deserialization boundary'),
        ],
    },
    'c_cpp': {
        'extensions': {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hh'},
        'path_rules': [('/http', 8, 'network-facing module'), ('/server', 8, 'server-facing module'), ('/parser', 9, 'parser boundary'), ('/proto', 7, 'protocol boundary'), ('/auth', 8, 'authentication boundary')],
        'patterns': [
            ('network_input', r'\b(recv|recvfrom|read|accept|SSL_read|uv_read_start)\b', 8, 'external input boundary'),
            ('dangerous_copy', r'\b(strcpy|strcat|sprintf|vsprintf|gets|memcpy|memmove|snprintf)\b', 9, 'buffer movement or formatting sink'),
            ('command_exec', r'\b(system|popen|execl|execve|CreateProcess[A-Z]?)\b', 10, 'command execution sink'),
            ('alloc_free', r'\b(malloc|calloc|realloc|free|new\s|delete\s)\b', 6, 'memory lifetime surface'),
            ('unsafe_cast', r'\([^\)]*\*\)\s*[A-Za-z_]|reinterpret_cast<|static_cast<', 7, 'type or size conversion boundary'),
        ],
    },
    'java': {
        'extensions': {'.java', '.kt'},
        'path_rules': [('/controller/', 10, 'controller layer'), ('/graphql', 10, 'GraphQL resolver surface'), ('/servlet', 9, 'servlet boundary'), ('/upload', 9, 'file ingestion boundary'), ('/auth', 8, 'authentication boundary')],
        'patterns': [
            ('request_mapping', r'@(RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)', 10, 'HTTP entrypoint'),
            ('request_access', r'@(RequestBody|RequestParam|PathVariable)|HttpServletRequest|MultipartFile', 8, 'user-controlled request data'),
            ('command_exec', r'\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder\()', 10, 'command execution sink'),
            ('filesystem', r'\b(Files\.(read|write)|new File\(|Paths\.get\()', 7, 'filesystem sink near attacker input'),
            ('deserialization', r'\b(ObjectInputStream|readObject\(|Yaml\.load|SpelExpressionParser)\b', 9, 'unsafe deserialization or expression execution'),
        ],
    },
    'php': {
        'extensions': {'.php'},
        'path_rules': [('/controller', 10, 'controller layer'), ('/routes', 10, 'route file'), ('/upload', 9, 'file ingestion boundary'), ('/auth', 8, 'authentication boundary')],
        'patterns': [
            ('route', r'Route::(get|post|put|patch|delete|match)|->middleware\(', 10, 'HTTP entrypoint'),
            ('request_access', r'\$(request|req)->(input|file|query|post|get)|\$_(GET|POST|REQUEST|FILES)', 8, 'user-controlled request data'),
            ('command_exec', r'\b(shell_exec|exec|passthru|proc_open|system)\b', 10, 'command execution sink'),
            ('filesystem', r'\b(file_get_contents|file_put_contents|fopen|move_uploaded_file|unlink)\b', 7, 'filesystem sink near attacker input'),
            ('deserialization', r'\b(unserialize|eval|include|require)(_once)?\b', 9, 'unsafe code loading or deserialization'),
        ],
    },
    'ruby': {
        'extensions': {'.rb'},
        'path_rules': [('/controllers/', 10, 'controller layer'), ('/graphql', 10, 'GraphQL resolver surface'), ('/jobs/', 7, 'background job boundary'), ('/auth', 8, 'authentication boundary')],
        'patterns': [
            ('route', r'\b(get|post|put|patch|delete)\s+[\'\"]|resources\s+:', 10, 'HTTP entrypoint'),
            ('request_access', r'\bparams\[|request\.(params|body|headers)', 8, 'user-controlled request data'),
            ('command_exec', r'\b(system\(|Open3\.|spawn\(|exec\()', 10, 'command execution sink'),
            ('filesystem', r'\b(File\.(read|write|open)|send_file|Tempfile\.)', 7, 'filesystem sink near attacker input'),
            ('deserialization', r'\b(YAML\.load|Marshal\.load|ERB\.new|eval\()', 9, 'unsafe deserialization or template execution'),
        ],
    },
}


LANGUAGE_ALIASES = {
    'c': 'c_cpp',
    'c++': 'c_cpp',
    'cpp': 'c_cpp',
    'cc': 'c_cpp',
    'c/c++': 'c_cpp',
    'native': 'c_cpp',
    'native code': 'c_cpp',
    'protocol buffers': 'c_cpp',
    'protobuf': 'c_cpp',
    'python c extension': 'python',
    'python extension': 'python',
    'python bindings': 'python',
    'swig interface code': 'python',
    'swig': 'python',
    'php c extension': 'php',
    'php extension': 'php',
    'node': 'javascript',
    'node.js': 'javascript',
    'typescript': 'javascript',
    'golang': 'go',
}

GLOBAL_PATTERNS = [
    ('authz_check', r'\b(auth|authorize|permission|capab|acl|is_admin|role)\b', 3, 'authorization-sensitive code'),
    ('crypto_or_token', r'\b(jwt|token|session|oauth|cookie|signed)\b', 3, 'session or token handling'),
    ('archive_or_extract', r'\b(zip|tar|extract|archive)\b', 4, 'archive handling often hides path traversal'),
]


def load_json_config(path: Path | None) -> dict:
    if path is None:
        return {}
    return json.loads(path.read_text(encoding='utf-8'))


def discover_candidates(repo_root: Path, policy: dict, limit: int, config: dict | None = None, external_signal_path: Path | None = None, crash_dir: Path | None = None, sbom_path: Path | None = None) -> tuple[list[Candidate], list[LanguageStat]]:
    config = config or {}
    language_override = policy_list(policy, 'languages')
    detected_languages = _detect_languages(repo_root)
    active_languages = _select_languages(detected_languages, language_override)
    include_prefixes = _canonicalize_policy_paths(repo_root, _normalize_prefixes(policy_list(policy, 'include_paths'), config.get('include_paths', [])))
    exclude_prefixes = _canonicalize_policy_paths(repo_root, _normalize_prefixes(policy_list(policy, 'exclude_paths'), config.get('exclude_paths', [])))
    ignore_patterns = _canonicalize_policy_paths(repo_root, _normalize_prefixes(policy_list(policy, 'ignore_patterns')))
    policy_entrypoints = [entry.lower() for entry in policy_list(policy, 'entry_points')]
    focus_terms = [item.lower() for item in policy_list(policy, 'focus_areas')]
    hot_paths = _canonicalize_policy_paths(repo_root, [item.lower() for item in policy_list(policy, 'hot_paths')])
    preferred_sinks = [item.lower() for item in policy_list(policy, 'preferred_sinks')]
    framework_hints = {item.lower() for item in policy_list(policy, 'framework_hints')}
    max_signals_per_file = int(config.get('max_signals_per_file', 12))

    repo_context = _detect_repo_context(repo_root, active_languages, framework_hints)
    language_map: dict[str, str] = {}
    external_index = load_external_signal_index(external_signal_path)
    crash_index = load_crash_signal_index(repo_root, crash_dir)
    git_index = collect_git_history_signals(repo_root)
    sbom_index = load_sbom_signal_index(repo_root, sbom_path)
    for file_path in repo_root.rglob('*'):
        if not file_path.is_file():
            continue
        rel_text = str(file_path.relative_to(repo_root)).replace('\\', '/')
        if _should_skip_path(rel_text, include_prefixes, exclude_prefixes, ignore_patterns):
            continue
        language = _language_for_path(file_path, active_languages)
        if language:
            language_map[rel_text] = language
    graph_index = build_import_graph(repo_root, language_map)
    semantic_index = build_semantic_index(repo_root, language_map)

    candidates: list[Candidate] = []
    for file_path in repo_root.rglob('*'):
        if not file_path.is_file():
            continue
        rel_text = str(file_path.relative_to(repo_root)).replace('\\', '/')
        if _should_skip_path(rel_text, include_prefixes, exclude_prefixes, ignore_patterns):
            continue
        language = _language_for_path(file_path, active_languages)
        if not language:
            continue
        candidate = _score_file(
            repo_root=repo_root,
            file_path=file_path,
            rel_path=rel_text,
            language=language,
            repo_context=repo_context,
            graph_index=graph_index,
            semantic_index=semantic_index,
            git_index=git_index,
            external_index=external_index,
            crash_index=crash_index,
            sbom_index=sbom_index,
            policy_entrypoints=policy_entrypoints,
            focus_terms=focus_terms,
            hot_paths=hot_paths,
            preferred_sinks=preferred_sinks,
            max_signals_per_file=max_signals_per_file,
        )
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(key=lambda item: (-item.score, str(item.path)))
    language_stats = [
        LanguageStat(language=name, file_count=count, extensions=sorted(LANGUAGE_RULES[name]['extensions']))
        for name, count in detected_languages.items()
        if count > 0
    ]
    language_stats.sort(key=lambda item: (-item.file_count, item.language))
    return candidates[:limit], language_stats


def _detect_languages(repo_root: Path) -> Counter[str]:
    counts: Counter[str] = Counter()
    for file_path in repo_root.rglob('*'):
        if not file_path.is_file():
            continue
        rel_text = str(file_path.relative_to(repo_root)).replace('\\', '/')
        if _matches_excluded_pattern(rel_text):
            continue
        language = _language_for_path(file_path, set(LANGUAGE_RULES))
        if language:
            counts[language] += 1
    return counts


def _select_languages(detected_languages: Counter[str], override: list[str] | set[str]) -> set[str]:
    if override:
        selected = {normalized for name in override if (normalized := _normalize_language_name(name)) in LANGUAGE_RULES}
        return selected or set(LANGUAGE_RULES)
    if detected_languages:
        return {name for name, count in detected_languages.items() if count > 0}
    return set(LANGUAGE_RULES)


def _normalize_language_name(name: str) -> str:
    normalized = name.strip().strip('`').strip().lower()
    if not normalized:
        return ''
    return LANGUAGE_ALIASES.get(normalized, normalized)


def _normalize_prefixes(*groups: list[str]) -> list[str]:
    prefixes: list[str] = []
    for group in groups:
        for item in group:
            normalized = item.strip().strip('`').strip()
            if normalized:
                prefixes.append(normalized.strip('/').replace('\\', '/'))
    return prefixes


def _canonicalize_policy_paths(repo_root: Path, items: list[str]) -> list[str]:
    repo_prefix = str(repo_root.expanduser().resolve()).replace('\\', '/').rstrip('/') + '/'
    normalized_items: list[str] = []
    for item in items:
        normalized = item.strip().strip('`').strip().replace('\\', '/')
        if not normalized:
            continue
        if normalized.startswith(repo_prefix):
            normalized = normalized[len(repo_prefix):]
        else:
            normalized = normalized.lstrip('/')
        normalized_items.append(normalized)
    return normalized_items


def _should_skip_path(rel_path: str, include_prefixes: list[str], exclude_prefixes: list[str], ignore_patterns: list[str]) -> bool:
    lowered = rel_path.lower()
    if any(part in COMMON_EXCLUDE_DIRS for part in lowered.split('/')):
        return True
    if _matches_excluded_pattern(lowered):
        return True
    if any(_matches_path_pattern(lowered, pattern) for pattern in ignore_patterns):
        return True
    if include_prefixes and not any(_matches_path_pattern(lowered, pattern) for pattern in include_prefixes):
        return True
    if any(_matches_path_pattern(lowered, pattern) for pattern in exclude_prefixes):
        return True
    return False


def _matches_path_pattern(rel_path: str, pattern: str) -> bool:
    candidate = pattern.strip().strip('`').strip().replace('\\', '/').lower()
    if not candidate:
        return False
    if any(token in candidate for token in '*?[]'):
        return fnmatch.fnmatch(rel_path, candidate)
    prefix = candidate.rstrip('/')
    return rel_path == prefix or rel_path.startswith(prefix + '/')


def _matches_excluded_pattern(rel_path: str) -> bool:
    return any(pattern.search(rel_path) for pattern in DEFAULT_EXCLUDED_FILE_PATTERNS)


def _language_for_path(file_path: Path, active_languages: set[str]) -> str:
    suffix = file_path.suffix.lower()
    if suffix == '.i':
        if 'python' in active_languages:
            return 'python'
        if 'c_cpp' in active_languages:
            return 'c_cpp'
    for name in active_languages:
        if suffix in LANGUAGE_RULES[name]['extensions']:
            return name
    return ''


def _retention_reason(*, score: int, signals: list[Signal], external_signals: list[ExternalSignal], hot_path_hits: int, entrypoint_hits: int, focus_hits: int, in_degree: int, out_degree: int, semantic_meta: object | None) -> str:
    if score >= 10 or len(signals) >= 2:
        return ''
    profile = _external_signal_profile(external_signals)
    if _has_strong_external_signal(external_signals):
        if profile['crash_like']:
            return 'crash or sanitizer evidence should preserve this candidate despite sparse inline signatures'
        if profile['advisory_like']:
            return 'advisory or CVE-adjacent evidence should preserve this candidate despite sparse inline signatures'
        return 'strong external evidence should preserve this candidate despite sparse inline signatures'
    if hot_path_hits and (profile['total_weight'] >= 6 or in_degree >= 2 or out_degree >= 6):
        return 'policy-prioritized file reinforced by graph or external evidence'
    if entrypoint_hits >= 2 or (entrypoint_hits and profile['source_count'] >= 2):
        return 'policy-declared attack surface reinforced by independent evidence'
    if focus_hits >= 2 and (profile['source_count'] >= 1 or in_degree >= 2):
        return 'policy focus area reinforced by graph or external evidence'
    if profile['source_count'] >= 2 and profile['total_weight'] >= 9:
        return 'multiple independent external signal families justify retention'
    if in_degree >= 3 or out_degree >= 8:
        return 'graph-central file should be retained for review'
    if semantic_meta is not None and getattr(semantic_meta, 'entrypoint_lines', None):
        return 'semantic entrypoint evidence outweighs sparse regex hits'
    if semantic_meta is not None and getattr(semantic_meta, 'sink_lines', None) and (external_signals or in_degree >= 2):
        return 'semantic sink evidence combined with graph or external support'
    return ''


def _has_strong_external_signal(external_signals: list[ExternalSignal]) -> bool:
    profile = _external_signal_profile(external_signals)
    if profile['crash_like'] >= 1 and profile['crash_weight'] >= 8:
        return True
    if profile['advisory_like'] >= 1 and profile['advisory_weight'] >= 7:
        return True
    if profile['source_count'] >= 2 and profile['total_weight'] >= 10:
        return True
    if profile['max_weight'] >= 10:
        return True
    return False


def _external_signal_profile(external_signals: list[ExternalSignal]) -> dict[str, int]:
    crash_sources = {'crash', 'sanitizer', 'oss-fuzz', 'clusterfuzz', 'syzbot'}
    advisory_sources = {'advisory', 'cve', 'issue', 'pr', 'hardening'}
    git_sources = {'git'}
    source_buckets: set[str] = set()
    total_weight = 0
    max_weight = 0
    crash_like = 0
    advisory_like = 0
    git_like = 0
    crash_weight = 0
    advisory_weight = 0
    git_weight = 0
    for signal in external_signals:
        weight = int(signal.weight)
        total_weight += weight
        max_weight = max(max_weight, weight)
        source_buckets.add(signal.source)
        if signal.source in crash_sources:
            crash_like += 1
            crash_weight += weight
        elif signal.source in advisory_sources:
            advisory_like += 1
            advisory_weight += weight
        elif signal.source in git_sources:
            git_like += 1
            git_weight += weight
    return {
        'source_count': len(source_buckets),
        'total_weight': total_weight,
        'max_weight': max_weight,
        'crash_like': crash_like,
        'advisory_like': advisory_like,
        'git_like': git_like,
        'crash_weight': crash_weight,
        'advisory_weight': advisory_weight,
        'git_weight': git_weight,
    }


def _detect_repo_context(repo_root: Path, active_languages: set[str], framework_hints: set[str]) -> dict:
    frameworks: set[str] = set(framework_hints)
    repo_signals: list[ExternalSignal] = []
    for language in active_languages:
        for marker in REPO_FILES.get(language, []):
            candidate = repo_root / marker
            if candidate.exists():
                repo_signals.append(ExternalSignal(source='repo', weight=3, summary=f'manifest:{marker}', metadata={'language': language}))
    sampled_files = 0
    for file_path in repo_root.rglob('*'):
        if sampled_files >= 200:
            break
        if not file_path.is_file():
            continue
        sampled_files += 1
        try:
            text = file_path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        for framework, patterns in FRAMEWORK_MARKERS.items():
            if framework in frameworks:
                continue
            if any(re.search(pattern, text) for pattern in patterns):
                frameworks.add(framework)
    for framework in sorted(frameworks):
        repo_signals.append(ExternalSignal(source='repo', weight=4, summary=f'framework:{framework}', metadata={'framework': framework}))
    return {'frameworks': sorted(frameworks), 'repo_signals': repo_signals}


def _score_file(*, repo_root: Path, file_path: Path, rel_path: str, language: str, repo_context: dict, graph_index: dict[str, dict[str, object]], semantic_index: dict[str, object], git_index: dict[str, list[ExternalSignal]], external_index: dict[str, list[ExternalSignal]], crash_index: dict[str, list[ExternalSignal]], sbom_index: dict[str, list[ExternalSignal]], policy_entrypoints: list[str], focus_terms: list[str], hot_paths: list[str], preferred_sinks: list[str], max_signals_per_file: int) -> Candidate | None:
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return None

    rules = LANGUAGE_RULES[language]
    score = 0
    reasons: list[str] = []
    path_signals: list[str] = []
    lowered_path = rel_path.lower()
    frameworks = set(repo_context.get('frameworks', []))
    external_signals: list[ExternalSignal] = []
    graph_meta = graph_index.get(rel_path, {})
    semantic_meta = semantic_index.get(rel_path)
    in_degree = int(graph_meta.get('in_degree', 0))
    out_degree = int(graph_meta.get('out_degree', 0))
    if in_degree >= 2:
        weight = min(8, 2 + in_degree)
        score += weight
        external_signals.append(ExternalSignal(source='graph', weight=weight, summary=f'internal call/import fan-in: {in_degree}', metadata={'in_degree': in_degree}))
        reasons.append(f'graph:fan_in (+{weight}) imported or referenced by many internal files')
    if out_degree >= 5:
        weight = min(5, out_degree // 2)
        score += weight
        external_signals.append(ExternalSignal(source='graph', weight=weight, summary=f'internal fan-out: {out_degree}', metadata={'out_degree': out_degree}))
        reasons.append(f'graph:fan_out (+{weight}) broad dependency surface')
    for signal in git_index.get(rel_path, []):
        external_signals.append(signal)
        score += signal.weight
        reasons.append(f'external:{signal.source} (+{signal.weight}) {signal.summary}')
    for signal in external_index.get(rel_path, []):
        external_signals.append(signal)
        score += signal.weight
        reasons.append(f'external:{signal.source} (+{signal.weight}) {signal.summary}')
    for signal in crash_index.get(rel_path, []):
        external_signals.append(signal)
        score += signal.weight
        reasons.append(f'external:{signal.source} (+{signal.weight}) {signal.summary}')
    for signal in sbom_index.get(rel_path, []):
        external_signals.append(signal)
        score += signal.weight
        reasons.append(f'external:{signal.source} (+{signal.weight}) {signal.summary}')

    for needle, weight, rationale in rules['path_rules']:
        if needle.strip('/') and needle.lower() in f'/{lowered_path}':
            score += weight
            path_signals.append(needle)
            reasons.append(f'path:{needle} (+{weight}) {rationale}')

    hot_path_hits = 0
    for hot_path in hot_paths:
        if hot_path and _matches_path_pattern(lowered_path, hot_path):
            score += 8
            hot_path_hits += 1
            reasons.append(f'policy_hot_path:{hot_path} (+8) explicitly prioritized by policy')

    entrypoint_hits = 0
    for entry in policy_entrypoints:
        token = entry.strip('/').lower()
        if token and token in lowered_path:
            score += 7
            entrypoint_hits += 1
            reasons.append(f'policy_entrypoint:{entry} (+7) policy-declared attack surface')

    focus_hits = 0
    for term in focus_terms:
        token = term.lower()
        if token and token in lowered_path:
            score += 4
            focus_hits += 1
            reasons.append(f'policy_focus:{term} (+4) policy-declared focus area')

    compiled_patterns = [(name, re.compile(pattern), weight, rationale) for name, pattern, weight, rationale in [*rules['patterns'], *GLOBAL_PATTERNS]]
    signals: list[Signal] = []
    attack_surfaces: set[str] = set()
    sink_kinds: set[str] = set()
    framework_hints: set[str] = set()
    entrypoint_markers: set[str] = set()
    repo_signal_budget = 0

    if frameworks:
        for framework in frameworks:
            if framework in lowered_path:
                score += 3
                framework_hints.add(framework)
                reasons.append(f'framework_hint:{framework} (+3) repo or path suggests framework-specific surface')

    if semantic_meta is not None:
        if semantic_meta.entrypoint_lines:
            semantic_weight = min(10, 3 + len(semantic_meta.entrypoint_lines))
            score += semantic_weight
            reasons.append(f'semantic:entrypoints (+{semantic_weight}) function-level entrypoint evidence')
            attack_surfaces.add('request entrypoint')
        if semantic_meta.request_lines and semantic_meta.sink_lines:
            semantic_weight = min(9, 2 + min(len(semantic_meta.request_lines), len(semantic_meta.sink_lines)))
            score += semantic_weight
            reasons.append(f'semantic:flow_proximity (+{semantic_weight}) request-like usage co-located with sink-like usage')
        if semantic_meta.summaries:
            reasons.extend(f'semantic:{summary}' for summary in semantic_meta.summaries[:3])

    lines = content.splitlines()
    for index, line in enumerate(lines, start=1):
        lowered_line = line.lower()
        for framework, patterns in FRAMEWORK_MARKERS.items():
            if framework in frameworks and any(re.search(pattern, line) for pattern in patterns):
                framework_hints.add(framework)
                if repo_signal_budget < 3:
                    external_signals.append(ExternalSignal(source='framework', weight=3, summary=f'framework hit:{framework}', metadata={'line_no': index}))
                    repo_signal_budget += 1
                    score += 3
        for name, pattern, weight, rationale in compiled_patterns:
            if not pattern.search(line):
                continue
            signals.append(Signal(name=name, weight=weight, line_no=index, line=line.strip(), rationale=rationale, language=language))
            score += weight
            if 'route' in name or 'handler' in name or 'request_access' in name:
                attack_surfaces.add('request entrypoint')
                entrypoint_markers.add(name)
            if 'auth' in name:
                attack_surfaces.add('authorization boundary')
            if 'upload' in lowered_path or 'archive' in lowered_line:
                attack_surfaces.add('file ingestion')
            if 'command' in name:
                sink_kinds.add('command execution')
            if 'deserialization' in name:
                sink_kinds.add('unsafe deserialization')
            if 'filesystem' in name:
                sink_kinds.add('filesystem')
            if 'template' in name:
                sink_kinds.add('template rendering')
            if 'unsafe' in name or 'dangerous_copy' in name or 'alloc' in name:
                sink_kinds.add('memory-sensitive native path')
            if 'ssrf' in name:
                sink_kinds.add('outbound request')

    for sink in preferred_sinks:
        if any(token in sink for token in sink_kinds) or any(token in lowered_path for token in sink.split()):
            score += 5
            reasons.append(f'policy_preferred_sink:{sink} (+5) aligns with policy-requested sink class')

    retention_reason = _retention_reason(
        score=score,
        signals=signals,
        external_signals=external_signals,
        hot_path_hits=hot_path_hits,
        entrypoint_hits=entrypoint_hits,
        focus_hits=focus_hits,
        in_degree=in_degree,
        out_degree=out_degree,
        semantic_meta=semantic_meta,
    )
    if score < 10 and len(signals) < 2:
        if not retention_reason:
            return None
        score = max(score, 10)
        reasons.append(f'retention_exemption: {retention_reason}')

    signals.sort(key=lambda item: (-item.weight, item.line_no))
    trimmed_signals = signals[:max_signals_per_file]
    for signal in trimmed_signals:
        reasons.append(f'line {signal.line_no}: {signal.name} (+{signal.weight})')

    primary_symbols = []
    semantic_summary: list[str] = []
    if semantic_meta is not None:
        primary_symbols = semantic_meta.symbols[:6]
        semantic_summary = semantic_meta.summaries[:6]
        for symbol in primary_symbols[:3]:
            if 'entrypoint' in symbol.tags:
                entrypoint_markers.add(symbol.name)
            if 'authz' in symbol.tags:
                attack_surfaces.add('authorization boundary')
            if any(tag in symbol.tags for tag in ('command execution', 'deserialization', 'filesystem', 'memory-sensitive', 'outbound request')):
                if 'command execution' in symbol.tags:
                    sink_kinds.add('command execution')
                if 'deserialization' in symbol.tags:
                    sink_kinds.add('unsafe deserialization')
                if 'filesystem' in symbol.tags:
                    sink_kinds.add('filesystem')
                if 'memory-sensitive' in symbol.tags:
                    sink_kinds.add('memory-sensitive native path')
                if 'outbound request' in symbol.tags:
                    sink_kinds.add('outbound request')

    subsystem = rel_path.split('/', 1)[0]
    exposure = _infer_exposure(
        rel_path,
        language=language,
        signals=trimmed_signals,
        attack_surfaces=attack_surfaces,
        sink_kinds=sink_kinds,
        external_signals=external_signals,
        framework_hints=framework_hints,
    )
    return Candidate(
        path=file_path,
        language=language,
        subsystem=subsystem,
        exposure=exposure,
        score=score,
        attack_surfaces=sorted(attack_surfaces),
        sink_kinds=sorted(sink_kinds),
        framework_hints=sorted(framework_hints),
        entrypoint_markers=sorted(entrypoint_markers),
        primary_symbols=primary_symbols,
        semantic_summary=semantic_summary,
        reasons=reasons,
        signals=trimmed_signals,
        path_signals=path_signals,
        external_signals=external_signals,
    )


def _infer_exposure(rel_path: str, *, language: str, signals: list[Signal], attack_surfaces: set[str], sink_kinds: set[str], external_signals: list[ExternalSignal], framework_hints: set[str]) -> str:
    lowered = rel_path.lower()
    if 'request entrypoint' in attack_surfaces:
        return 'remote API'
    if 'authorization boundary' in attack_surfaces or any(token in lowered for token in ('/auth', '/session', '/token')):
        return 'auth boundary'
    if any(token in lowered for token in ('tls', 'ssl', 'x509', 'certificate', 'spiffe', 'trust', 'root_store', 'handshake', 'credentials')):
        return 'trust-material or handshake path'
    if any(token in lowered for token in ('xds', 'bootstrap', 'resolver', 'discovery', 'lb_policy')):
        return 'control-plane or resolver path'
    if 'file ingestion' in attack_surfaces or any(token in lowered for token in ('/upload', '/import', '/archive')):
        return 'file ingestion path'
    if any(token in lowered for token in ('python/', 'php/', 'ruby/', 'bindings/', 'extension', 'swig', '/ffi', 'cffi')):
        return 'language binding or FFI path'
    if any(token in lowered for token in ('/parser', 'parse', 'codec', 'decode', 'encoder', 'marshal', 'unmarshal', 'serialize', 'deserialize', 'proto')):
        return 'parser or serialization path'
    if any(token in lowered for token in ('transport', 'http2', 'hpack', 'frame', 'socket', 'endpoint', 'channel', 'server', 'client', 'subchannel', 'iomgr')):
        return 'transport or protocol state machine'
    if any(token in lowered for token in ('alloc', 'arena', 'buffer', 'memory', 'slice', 'arena', 'pool')):
        return 'allocator or buffer-management path'
    if 'command execution' in sink_kinds:
        return 'command execution path'
    if 'unsafe deserialization' in sink_kinds:
        return 'unsafe deserialization path'
    if 'filesystem' in sink_kinds:
        return 'filesystem trust-boundary path'
    if 'outbound request' in sink_kinds:
        return 'outbound network path'
    if 'memory-sensitive native path' in sink_kinds:
        if language == 'c_cpp':
            profile = _external_signal_profile(external_signals)
            if profile['crash_like']:
                return 'memory-corruption-prone native path'
            return 'native memory-lifetime path'
        return 'memory-sensitive path'
    if any(hint in {'fastapi', 'django', 'flask', 'express', 'nestjs', 'spring', 'gin', 'echo', 'actix', 'axum', 'rails', 'laravel'} for hint in framework_hints):
        return 'framework entry or middleware path'
    if signals:
        return signals[0].name
    return Path(rel_path).stem
