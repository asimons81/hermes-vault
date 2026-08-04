from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[3]
PLUGIN = ROOT / "plugins" / "hermes-vault-desktop" / "desktop" / "plugin.js"


SDK_STUB = r'''
const values = {
  overview: { profile: 'default', credential_count: 1, lease_count: 0, active_lease_count: 0, services: ['demo'], recent_audit: [], health: { status: 'healthy' } },
  credentials: { credential_count: 1, credentials: [{ service: 'demo', alias: 'metadata' }] },
  leases: { lease_count: 0, leases: [] },
  policy: { policy_exists: true, agents: {}, doctor: { status: 'healthy' } },
  requests: { request_count: 0, requests: [] },
  integrity: { status: 'healthy', reason_code: 'ok', verified_count: 1, legacy_count: 0, recommended_next_step: 'none' }
}
export const ROUTES_AREA = 'routes'
export const SIDEBAR_NAV_AREA = 'sidebar.nav'
export const PALETTE_AREA = 'palette'
export const host = { navigate() {}, state: { profile: {} } }
export const Button = () => null
export const ConfirmDialog = () => null
export const Codicon = () => null
export const EmptyState = () => null
export const ErrorState = () => null
export const Select = () => null
export const SelectContent = () => null
export const SelectItem = () => null
export const SelectTrigger = () => null
export const SelectValue = () => null
export const Separator = () => null
export const cn = (...items) => items.filter(Boolean).join(' ')
export const useQuery = ({ queryKey }) => ({ data: values[queryKey[1]], error: null, isError: false, isFetching: false, isLoading: false, refetch: async () => ({ error: null, isError: false }) })
export const useQueryClient = () => ({ invalidateQueries() {} })
export const useValue = () => 'default'
'''

JSX_STUB = r'''
export const jsx = (type, props) => typeof type === 'function' ? type(props || {}) : ({ type, props })
export const jsxs = (type, props) => typeof type === 'function' ? type(props || {}) : ({ type, props })
'''

REACT_STUB = r'''
export const useEffect = () => {}
export const useState = initial => [initial, () => {}]
'''

LOADER = r'''
import { pathToFileURL } from 'node:url'
const sdk = pathToFileURL(process.env.SDK_STUB).href
const jsx = pathToFileURL(process.env.JSX_STUB).href
const react = pathToFileURL(process.env.REACT_STUB).href
export async function resolve(specifier, context, nextResolve) {
  if (specifier === '@hermes/plugin-sdk') return { url: sdk, shortCircuit: true }
  if (specifier === 'react/jsx-runtime') return { url: jsx, shortCircuit: true }
  if (specifier === 'react') return { url: react, shortCircuit: true }
  return nextResolve(specifier, context)
}
'''

HARNESS = r'''
import assert from 'node:assert/strict'
import { pathToFileURL } from 'node:url'
const { default: plugin } = await import(pathToFileURL(process.env.PLUGIN).href)
assert.equal(plugin.id, 'hermes-vault-desktop')
assert.equal(plugin.defaultEnabled, false)
const contributions = []
const ctx = {
  registerMany(items) { contributions.push(...items); return () => {} },
  i18n: { register() {}, t(key) { return key } }
}
plugin.register(ctx)
assert.deepEqual(contributions.map(item => item.id), ['page', 'nav', 'open'])
assert.equal(contributions[0].data.path, '/hermes-vault')
assert.equal(contributions[1].data.path, '/hermes-vault')
assert.equal(contributions[2].data.id, 'hermes-vault.open')
assert.ok(contributions[0].render())
console.log(JSON.stringify({ id: plugin.id, route: contributions[0].data.path, contributions: contributions.map(item => item.id) }))
'''


def test_runtime_plugin_contract_and_render(tmp_path: Path) -> None:
    files = {
        "sdk.mjs": SDK_STUB,
        "jsx.mjs": JSX_STUB,
        "react.mjs": REACT_STUB,
        "loader.mjs": LOADER,
        "harness.mjs": HARNESS,
    }
    paths = {}
    for name, content in files.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        paths[name] = path

    env = {
        "SDK_STUB": str(paths["sdk.mjs"]),
        "JSX_STUB": str(paths["jsx.mjs"]),
        "REACT_STUB": str(paths["react.mjs"]),
        "PLUGIN": str(PLUGIN),
    }
    result = subprocess.run(
        ["node", "--experimental-loader", str(paths["loader.mjs"]), str(paths["harness.mjs"])],
        cwd=ROOT,
        env={**__import__("os").environ, **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    payload = json.loads(result.stdout.strip().splitlines()[-1])
    assert payload == {
        "id": "hermes-vault-desktop",
        "route": "/hermes-vault",
        "contributions": ["page", "nav", "open"],
    }


def test_runtime_plugin_is_bounded_and_metadata_only() -> None:
    source = PLUGIN.read_text(encoding="utf-8")
    imports = set(re.findall(r"from ['\"]([^'\"]+)['\"]", source))
    assert imports <= {"@hermes/plugin-sdk", "react", "react/jsx-runtime"}
    assert "const ID = 'hermes-vault-desktop'" in source
    assert "path: '/hermes-vault'" in source
    assert "hermes-vault.open" in source
    assert "[ID, 'overview', profile]" in source
    assert "invalidateQueries({ queryKey: QUERY_ROOT })" in source
    assert "ConfirmDialog" in source
    assert "Approve & issue lease" in source
    assert "This read-only integration does not perform Vault mutations." in source
    assert "iframe" not in source.lower()
    assert "WebSocket" not in source
    assert not re.search(r"\bfetch\s*\(", source)
    assert "record.value" not in source
    assert "record.secret" not in source
    assert "record.token" not in source
    assert "record.ciphertext" not in source
    assert "lease.value" not in source
    assert "request.value" not in source
