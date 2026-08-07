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
        ["node", "--experimental-loader", paths["loader.mjs"].as_uri(), str(paths["harness.mjs"])],
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


# ---------------------------------------------------------------------------
# Blank-pane regression tests (t_b79a7a2a)
#
# Root cause: the packaged Hermes Desktop CSS bundle (app.asar 0.17.0,
# dist/assets/index-*.css) does not generate the Tailwind utilities this
# plugin relies on (verified 2026-08-04: zero hits for the KNOWN_MISSING
# classes below). A missing `bg-(--ui-*)` class silently renders the element
# transparent, so the four LoadingState skeleton cards (and the page header)
# have no fill -> the "four blank panes". The plugin must supply its own
# scoped stylesheet (STYLESHEET export) covering every utility the bundle
# lacks, using only theme vars the bundle defines.
# ---------------------------------------------------------------------------

# Classes the plugin renders that ARE generated by the packaged bundle
# (verified by grepping app.asar 0.17.0 dist/assets/index-D4xChd0V.css).
# When the Hermes Desktop CSS contract changes, re-verify and update this set.
CORE_PRESENT_CLASSES = frozenset(
    """
    animate-pulse block border border-(--ui-stroke-secondary) border-b flex
    flex-wrap font-medium font-semibold gap-0.5 gap-1 gap-2 gap-3 gap-4 gap-7
    grid grid-cols-2 grid-cols-[auto_1fr_auto] h-24 h-4 h-7 h-full inline-flex
    items-center justify-between justify-self-center last:border-b-0 max-w-3xl
    max-w-full min-w-0 mt-4 mx-auto overflow-auto p-8 px-3 px-6 py-10 py-2 py-3
    py-4 py-5 rounded rounded-lg rounded-md rounded-xl sm:grid-cols-2 sticky
    tabular-nums text-(--ui-accent) text-(--ui-text-quaternary)
    text-(--ui-text-tertiary) text-[0.6875rem] text-destructive text-lg
    text-sm text-xl text-xs top-0 tracking-tight truncate w-36 w-56 w-full z-10
    px-2 py-1
    """.split()
)

# Utilities the plugin uses that the packaged bundle does NOT generate.
# The plugin's injected stylesheet must cover every one of these.
KNOWN_MISSING_UTILITIES = frozenset(
    """
    bg-(--ui-background) bg-(--ui-control-background) lg:grid-cols-4 max-w-5xl
    md:grid-cols-4 pb-5 w-96
    """.split()
)

# Theme variables defined by the packaged bundle (:root/.dark vars in
# dist/assets/index-*.css). The plugin stylesheet must only reference these.
BUNDLE_THEME_VARS = frozenset(
    """
    --ui-accent --ui-accent-secondary --ui-base --ui-bg-card --ui-bg-chrome
    --ui-bg-editor --ui-bg-elevated --ui-bg-input --ui-bg-primary
    --ui-bg-quaternary --ui-bg-quinary --ui-bg-secondary --ui-bg-sidebar
    --ui-bg-tertiary --ui-blue --ui-chat-bubble-background
    --ui-chat-bubble-opaque-background --ui-chat-surface-background
    --ui-control-active-background --ui-control-hover-background --ui-cyan
    --ui-diff-add-background --ui-diff-add-border --ui-diff-add-foreground
    --ui-diff-remove-background --ui-diff-remove-border
    --ui-diff-remove-foreground --ui-editor-surface-background --ui-green
    --ui-inline-code-background --ui-inline-code-foreground --ui-orange
    --ui-purple --ui-red --ui-row-active-background --ui-row-hover-background
    --ui-sash-hover-background --ui-sash-hover-border --ui-selection-background
    --ui-sidebar-surface-background --ui-stroke-primary --ui-stroke-quaternary
    --ui-stroke-secondary --ui-stroke-tertiary --ui-surface-background
    --ui-tab-hover-darken --ui-terminal-surface-background --ui-text-primary
    --ui-text-quaternary --ui-text-secondary --ui-text-tertiary --ui-warm
    --ui-widget-surface-background --ui-yellow
    """.split()
)

# Minimal SDK stub with a phase-controlled useQuery: 'loading' (async pending)
# vs 'success' (data settled). SDK components render as element descriptors so
# the whole page tree is walkable.
SDK_RENDER_STUB = r"""
const PHASE = 'PHASE_PLACEHOLDER'
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
export const host = { navigate() {}, state: { profile: { get: () => 'default' } } }
export const Button = (p) => ({ tag: 'Button', props: p })
export const ConfirmDialog = (p) => ({ tag: 'ConfirmDialog', props: p })
export const Codicon = (p) => ({ tag: 'Codicon', props: p })
export const EmptyState = (p) => ({ tag: 'EmptyState', props: p })
export const ErrorState = (p) => ({ tag: 'ErrorState', props: p })
export const Select = (p) => ({ tag: 'Select', props: p })
export const SelectContent = (p) => ({ tag: 'SelectContent', props: p })
export const SelectItem = (p) => ({ tag: 'SelectItem', props: p })
export const SelectTrigger = (p) => ({ tag: 'SelectTrigger', props: p })
export const SelectValue = (p) => ({ tag: 'SelectValue', props: p })
export const Separator = (p) => ({ tag: 'Separator', props: p })
export const cn = (...items) => items.filter(Boolean).join(' ')
export const useQuery = ({ queryKey }) => {
  const key = queryKey[1]
  if (PHASE === 'loading') return { data: undefined, error: null, isError: false, isFetching: true, isLoading: true, refetch: async () => ({ error: null, isError: false }) }
  return { data: values[key], error: null, isError: false, isFetching: false, isLoading: false, refetch: async () => ({ error: null, isError: false }) }
}
export const useQueryClient = () => ({ invalidateQueries() {} })
export const useValue = (atom) => (atom && typeof atom.get === 'function' ? atom.get() : 'default')
"""

JSX_RENDER_STUB = r"""
export const jsx = (type, props) => (typeof type === 'function' ? type(props || {}) : { tag: type, props: props || {} })
export const jsxs = (type, props) => (typeof type === 'function' ? type(props || {}) : { tag: type, props: props || {} })
"""

RENDER_HARNESS = r"""
import { pathToFileURL } from 'node:url'
const mod = await import(pathToFileURL(process.env.PLUGIN).href)
const plugin = mod.default
const STYLESHEET = typeof mod.STYLESHEET === 'string' ? mod.STYLESHEET : ''
const contributions = []
const ctx = {
  registerMany(items) { contributions.push(...items); return () => {} },
  rest: async () => ({}),
  i18n: { register() {}, t(key) { return key } },
  storage: { get(k, f) { return f }, set() {} }
}
plugin.register(ctx)
const page = contributions.find(c => c.id === 'page')
const tree = page.render()

function flatten(node, parent) {
  const out = []
  if (node === null || node === undefined || typeof node === 'boolean') return out
  if (Array.isArray(node)) {
    for (const k of node) out.push(...flatten(k, parent))
    return out
  }
  if (typeof node === 'string' || typeof node === 'number') {
    if (parent) parent.text.push(String(node))
    return out
  }
  if (typeof node === 'object' && node.tag && node.props) {
    const rec = { tag: String(node.tag), className: String(node.props.className || ''), text: [], children: [], parent: parent || null }
    out.push(rec)
    if (parent) parent.children.push(rec)
    const kids = node.props.children
    const arr = Array.isArray(kids) ? kids : (kids === undefined || kids === null ? [] : [kids])
    for (const k of arr) out.push(...flatten(k, rec))
  }
  return out
}

const els = flatten(tree, null)
const classSet = new Set()
for (const e of els) for (const c of String(e.className).split(/\s+/)) if (c) classSet.add(c)
const skeletonCards = els.filter(e => /animate-pulse/.test(e.className) && /h-24/.test(e.className)).length
const panes = els
  .filter(e => /text-xl/.test(e.className) && /tabular-nums/.test(e.className))
  .map(v => ({
    label: v.parent && v.parent.children[0] ? v.parent.children[0].text.join('') : '',
    value: v.text.join(''),
    detail: v.parent && v.parent.children[2] ? v.parent.children[2].text.join('') : ''
  }))
console.log('RESULT=' + JSON.stringify({ skeletonCards, panes, classes: [...classSet].sort(), stylesheet: STYLESHEET }))
"""

LOADER_RENDER = r"""
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
"""


def _unescape_css_class(selector: str) -> str:
    """Turn a CSS-escaped class selector (e.g. '.md\\:grid-cols-4') into the
    plain Tailwind class token the plugin puts in className (e.g. 'md:grid-cols-4')."""
    mapping = {r"\(": "(", r"\)": ")", r"\:": ":", r"\[": "[", r"\]": "]", r"\.": ".", r"\/": "/"}
    token = selector.lstrip(".")
    for escaped, plain in mapping.items():
        token = token.replace(escaped, plain)
    return token


def _stylesheet_selectors(stylesheet: str) -> set[str]:
    """All class selectors defined by the plugin stylesheet, unescaped."""
    out = set()
    for sel in re.findall(r"\.((?:\\.|[^{}])+)\{", stylesheet):
        for part in sel.split(","):
            out.add(_unescape_css_class(part.strip()))
    return out


def _run_render(tmp_path: Path, phase: str) -> dict:
    files = {
        "sdk.mjs": SDK_RENDER_STUB.replace("PHASE_PLACEHOLDER", phase),
        "jsx.mjs": JSX_RENDER_STUB,
        "react.mjs": REACT_STUB,
        "loader.mjs": LOADER_RENDER,
        "harness.mjs": RENDER_HARNESS,
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
        ["node", "--experimental-loader", paths["loader.mjs"].as_uri(), str(paths["harness.mjs"])],
        cwd=ROOT,
        env={**__import__("os").environ, **env},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    line = next(l for l in result.stdout.strip().splitlines() if l.startswith("RESULT="))
    return json.loads(line[len("RESULT="):])


def test_runtime_plugin_blank_panes_render_visible_after_settle(tmp_path: Path) -> None:
    """Regression guard for the four blank panes (t_b79a7a2a).

    Mounts the plugin, renders the loading phase (async pending -> the four
    skeleton panes), then the settled phase (async data arrives -> the four
    overview CountCard panes), and asserts every pane has non-empty visible
    content: every class the page renders must resolve to CSS — either a core
    class the packaged bundle generates or a rule in the plugin's own
    stylesheet. Fails on the pre-fix plugin because the skeleton fill
    (bg-(--ui-control-background)) and five other utilities have no CSS.
    """
    loading = _run_render(tmp_path, "loading")
    success = _run_render(tmp_path, "success")

    # Async pending phase shows exactly the four blank skeleton panes (the repro).
    assert loading["skeletonCards"] == 4

    # After async data settles, all four count panes render with non-empty values.
    assert [p["label"] for p in success["panes"]] == ["Credentials", "Leases", "Profile", "Integrity"]
    for pane in success["panes"]:
        assert pane["value"] and pane["value"] != "—", f"pane {pane['label']} rendered empty: {pane}"

    # Visibility contract: every class rendered anywhere on the page is either
    # generated by the packaged bundle or supplied by the plugin stylesheet.
    covered = _stylesheet_selectors(success["stylesheet"])
    uncovered = (set(loading["classes"]) | set(success["classes"])) - CORE_PRESENT_CLASSES - covered
    assert not uncovered, f"classes with no CSS definition (bundle or plugin stylesheet): {sorted(uncovered)}"

    # The exact blank-pane root cause: the skeleton fill must resolve to a
    # real, non-transparent background via a bundle-present theme var.
    assert "bg-(--ui-control-background)" in covered
    assert "var(--ui-bg-tertiary)" in success["stylesheet"]


def test_runtime_plugin_stylesheet_uses_only_bundle_vars(tmp_path: Path) -> None:
    """The injected stylesheet must cover every bundle-missing utility and may
    only reference theme vars the packaged bundle actually defines (otherwise
    the fix would re-introduce the same transparent/blank-pane failure)."""
    result = _run_render(tmp_path, "success")
    stylesheet = result["stylesheet"]
    assert stylesheet, "plugin must export a non-empty STYLESHEET"

    used_vars = set(re.findall(r"var\((--[a-z0-9-]+)\)", stylesheet))
    unknown = used_vars - BUNDLE_THEME_VARS
    assert not unknown, f"stylesheet references vars absent from packaged bundle: {sorted(unknown)}"

    covered = _stylesheet_selectors(stylesheet)
    missing_uncovered = KNOWN_MISSING_UTILITIES - covered
    assert not missing_uncovered, f"plugin stylesheet does not cover bundle-missing utilities: {sorted(missing_uncovered)}"

    # Skeleton fill rule must set an actual background-color (not transparent).
    assert re.search(r"\.bg-\\\(--ui-control-background\\\)\s*\{[^}]*background-color", stylesheet)

