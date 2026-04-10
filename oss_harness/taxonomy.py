from __future__ import annotations

from pathlib import Path

ENTRYPOINT_ALIASES = {
    'remote_api': {'api', 'http', 'https', 'rest', 'graphql', 'route', 'controller', 'handler', 'webhook'},
    'rpc_api': {'rpc', 'grpc'},
    'network_protocol': {'network', 'protocol', 'transport', 'socket', 'http2', 'hpack', 'frame'},
    'file_input': {'file', 'upload', 'import', 'archive', 'extract', 'parser', 'decode', 'codec'},
    'env_or_bootstrap': {'env', 'bootstrap', 'config', 'configuration'},
    'control_plane': {'xds', 'resolver', 'control-plane', 'discovery'},
    'trust_material': {'tls', 'ssl', 'spiffe', 'certificate', 'x509', 'trust', 'credential', 'key'},
    'plugin_or_extension': {'plugin', 'extension', 'ffi', 'binding', 'swig'},
}

SINK_ALIASES = {
    'command execution': {'command execution', 'exec', 'shell', 'process'},
    'unsafe deserialization': {'unsafe deserialization', 'deserialization', 'deserialize', 'pickle', 'yaml load'},
    'filesystem': {'filesystem', 'file write', 'file read', 'path traversal', 'path handling'},
    'outbound request': {'outbound request', 'ssrf', 'http client', 'fetch', 'request'},
    'memory-sensitive native path': {'memory', 'memory corruption', 'buffer', 'uaf', 'oob', 'allocator', 'unsafe native'},
    'template rendering': {'template', 'ssti', 'render'},
}


def build_entrypoint_categories(*, rel_path: str, exposure: str, attack_surfaces: list[str], entrypoint_markers: list[str]) -> set[str]:
    lowered_path = rel_path.lower()
    lowered_exposure = exposure.lower()
    categories: set[str] = set()
    if 'remote api' in lowered_exposure or 'request entrypoint' in {item.lower() for item in attack_surfaces}:
        categories.add('remote_api')
    if any(token in lowered_path for token in ('grpc', '/rpc', 'rpc_')):
        categories.add('rpc_api')
    if any(token in lowered_path for token in ('transport', 'http2', 'hpack', 'frame', 'socket', 'endpoint', 'channel')):
        categories.add('network_protocol')
    if any(token in lowered_path for token in ('upload', 'import', 'archive', 'extract', 'parser', 'decode', 'codec', 'serialize', 'deserialize', 'proto')):
        categories.add('file_input')
    if any(token in lowered_path for token in ('bootstrap', 'config', 'env', 'settings')):
        categories.add('env_or_bootstrap')
    if any(token in lowered_path for token in ('xds', 'resolver', 'discovery', 'lb_policy')):
        categories.add('control_plane')
    if any(token in lowered_path for token in ('tls', 'ssl', 'spiffe', 'certificate', 'x509', 'credential', 'trust', 'key')):
        categories.add('trust_material')
    if any(token in lowered_path for token in ('ffi', 'binding', 'swig', 'extension', 'ext/', 'python/', 'php/', 'ruby/')):
        categories.add('plugin_or_extension')
    for marker in entrypoint_markers:
        lowered = marker.lower()
        if 'route' in lowered or 'handler' in lowered or 'request' in lowered:
            categories.add('remote_api')
    return categories


def normalize_entrypoint_policy_item(item: str) -> tuple[str, str]:
    normalized = _normalize_text(item)
    if _looks_path_like(normalized):
        return 'path', normalized
    for category, aliases in ENTRYPOINT_ALIASES.items():
        if any(alias in normalized for alias in aliases):
            return 'taxonomy', category
    return 'taxonomy', normalized.replace(' ', '_')


def normalize_sink_policy_item(item: str) -> tuple[str, str]:
    normalized = _normalize_text(item)
    if _looks_path_like(normalized):
        return 'path', normalized
    for sink, aliases in SINK_ALIASES.items():
        if normalized == sink or any(alias in normalized for alias in aliases):
            return 'taxonomy', sink
    return 'taxonomy', normalized


def match_policy_item(item: str, *, rel_path: str, categories: set[str], sinks: set[str], symbols: list[str] | None = None, kind: str) -> bool:
    matcher_kind, matcher_value = normalize_entrypoint_policy_item(item) if kind == 'entrypoint' else normalize_sink_policy_item(item)
    lowered_path = rel_path.lower()
    symbol_names = {symbol.lower() for symbol in (symbols or [])}
    if matcher_kind == 'path':
        clean = matcher_value.strip('/').lower()
        return lowered_path == clean or lowered_path.startswith(clean + '/') or lowered_path.endswith('/' + clean) or clean in lowered_path or clean in symbol_names
    if kind == 'entrypoint':
        return matcher_value in categories
    return matcher_value in sinks


def looks_header_or_utility(rel_path: str, *, entrypoint_markers: list[str], attack_surfaces: list[str]) -> bool:
    suffix = Path(rel_path).suffix.lower()
    lowered = rel_path.lower()
    if suffix in {'.h', '.hh', '.hpp', '.hxx'}:
        return True
    if any(token in lowered for token in ('/util/', '/utils/', '/common/', '/helpers/', '/helper/', '/internal/base/')):
        return not entrypoint_markers and not attack_surfaces
    return False


def _normalize_text(value: str) -> str:
    return value.strip().strip('`').replace('\\', '/').lower()


def _looks_path_like(value: str) -> bool:
    return '/' in value or value.endswith(('.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.py', '.go', '.rs', '.java', '.php', '.rb')) or any(token in value for token in ('*', '?', '::', '->'))
