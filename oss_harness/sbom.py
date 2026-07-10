from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from oss_harness.models import ExternalSignal
from oss_harness.paths import iter_repo_files

GLUE_PATH_HINTS = (
    'bindings', 'binding', 'ffi', 'cffi', 'swig', 'wrapper', 'wrappers', 'adapter', 'shim', 'bridge', 'ext', 'extension'
)
LANGUAGE_BINDING_HINTS = (
    'python/', 'php/', 'ruby/', 'node/', 'javascript/', 'java/', 'kotlin/', 'rust/', 'go/', 'csharp/'
)
VENDOR_DIR_HINTS = (
    'third_party/', 'third-party/', 'vendor/', 'vendors/', 'deps/', 'external/'
)
COMPONENT_TOKEN_RE = re.compile(r'[a-z0-9][a-z0-9+_.-]{1,}')


def load_sbom_signal_index(repo_root: Path, sbom_path: Path | None) -> dict[str, list[ExternalSignal]]:
    if sbom_path is None or not sbom_path.exists():
        return {}
    data = json.loads(sbom_path.read_text(encoding='utf-8'))
    components = _extract_components(data)
    if not components:
        return {}
    vulnerability_index = _extract_vulnerability_index(data)
    signals: dict[str, list[ExternalSignal]] = defaultdict(list)
    for file_path in iter_repo_files(repo_root):
        rel_path = str(file_path.relative_to(repo_root)).replace('\\', '/')
        lowered = rel_path.lower()
        matched = []
        for component in components:
            if not _component_matches_path(component['tokens'], lowered):
                continue
            matched.append(component)
        if not matched:
            continue
        for component in matched[:3]:
            weight = 3
            reason_bits = ['component-to-path match']
            metadata = {
                'component': component['name'],
                'version': component.get('version', ''),
                'purl': component.get('purl', ''),
                'match_tokens': component['tokens'][:6],
            }
            if any(hint in lowered for hint in VENDOR_DIR_HINTS):
                weight += 1
                reason_bits.append('vendored adjacency')
            if _is_glue_or_binding_path(lowered):
                weight += 3
                reason_bits.append('glue or binding path')
                metadata['glue_path'] = True
            vuln_meta = vulnerability_index.get(component['ref']) or vulnerability_index.get(component['name'].lower())
            if vuln_meta:
                weight += min(6, vuln_meta['weight'])
                reason_bits.append('vulnerability-linked component')
                metadata['vulnerabilities'] = vuln_meta['ids']
                metadata['severity'] = vuln_meta['severity']
            summary = f"sbom:{component['name']} {'; '.join(reason_bits)}"
            signals[rel_path].append(ExternalSignal(source='sbom', weight=weight, summary=summary, metadata=metadata))
    return dict(signals)


def _extract_components(data: dict) -> list[dict[str, object]]:
    components = []
    raw_components = []
    if isinstance(data.get('components'), list):
        raw_components.extend(data['components'])
    if isinstance(data.get('artifacts'), list):
        raw_components.extend(data['artifacts'])
    if isinstance(data.get('packages'), list):
        raw_components.extend(data['packages'])
    seen: set[str] = set()
    for item in raw_components:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name') or item.get('artifact') or '').strip()
        version = str(item.get('version') or '').strip()
        purl = str(item.get('purl') or item.get('package_url') or '').strip()
        ref = str(item.get('bom-ref') or item.get('SPDXID') or purl or name).strip()
        if not name:
            continue
        tokens = _component_tokens(name, purl)
        if not tokens:
            continue
        key = f'{ref}:{name}:{version}'
        if key in seen:
            continue
        seen.add(key)
        components.append({'name': name, 'version': version, 'purl': purl, 'ref': ref, 'tokens': tokens})
    return components


def _extract_vulnerability_index(data: dict) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    raw = data.get('vulnerabilities')
    if not isinstance(raw, list):
        return index
    for item in raw:
        if not isinstance(item, dict):
            continue
        refs = []
        affects = item.get('affects')
        if isinstance(affects, list):
            for affected in affects:
                if isinstance(affected, dict):
                    ref = str(affected.get('ref') or '').strip()
                    if ref:
                        refs.append(ref)
        if not refs:
            source_name = str(item.get('source', {}).get('name', '') if isinstance(item.get('source'), dict) else '')
            if source_name:
                refs.append(source_name.lower())
        vuln_ids = []
        for key in ('id', 'cve', 'ghsa'):
            value = item.get(key)
            if value:
                vuln_ids.append(str(value))
        ratings = item.get('ratings') or []
        severity = ''
        if isinstance(ratings, list):
            for rating in ratings:
                if isinstance(rating, dict) and rating.get('severity'):
                    severity = str(rating['severity']).lower()
                    break
        weight = {'critical': 8, 'high': 7, 'medium': 5, 'low': 3}.get(severity, 6 if vuln_ids else 0)
        if not refs or weight <= 0:
            continue
        for ref in refs:
            index[ref] = {'ids': vuln_ids, 'severity': severity or 'unknown', 'weight': weight}
    return index


def _component_tokens(name: str, purl: str) -> list[str]:
    tokens = {token.lower() for token in COMPONENT_TOKEN_RE.findall(name)}
    if purl:
        tail = purl.rsplit('/', 1)[-1]
        tokens.update(token.lower() for token in COMPONENT_TOKEN_RE.findall(tail))
    cleaned = {token for token in tokens if len(token) >= 3 and token not in {'github', 'pkg', 'generic', 'library', 'runtime'}}
    return sorted(cleaned)


def _component_matches_path(tokens: list[str], lowered_path: str) -> bool:
    if not tokens:
        return False
    path_parts = set(re.split(r'[^a-z0-9]+', lowered_path))
    for token in tokens:
        if token in path_parts:
            return True
        if token in lowered_path:
            return True
    return False


def _is_glue_or_binding_path(lowered_path: str) -> bool:
    if any(hint in lowered_path for hint in LANGUAGE_BINDING_HINTS):
        return True
    return any(hint in lowered_path for hint in GLUE_PATH_HINTS)
