from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).parents[3]
PLUGIN = ROOT / "plugins" / "hermes-vault-desktop" / "desktop" / "plugin.js"


SDK_STUB = r"""
const values = {
  overview: { profile: 'default', credential_count: 1, lease_count: 0, active_lease_count: 0, services: ['demo'], recent_audit: [], health: { health_score: 100, healthy: true } },
  credentials: { credential_count: 1, credentials: [{ id: 'cred-1', service: 'demo', alias: 'metadata', status: 'unknown', credential_type: 'api_key' }] },
  leases: { lease_count: 0, leases: [] },
  policy: { policy_exists: true, agents: {}, doctor: { status: 'healthy' } },
  requests: { request_count: 0, requests: [] },
  integrity: { status: 'healthy', reason_code: 'ok', verified_count: 1, legacy_count: 0, recommended_next_step: 'none' }
}
export const ROUTES_AREA = 'routes'
export const SIDEBAR_NAV_AREA = 'sidebar.nav'
export const PALETTE_AREA = 'palette'
export const host = { navigate() {}, state: { profile: {} } }
export const Badge = () => null
export const Button = () => null
export const Checkbox = () => null
export const Codicon = () => null
export const ConfirmDialog = () => null
export const Dialog = () => null
export const DialogContent = () => null
export const DialogDescription = () => null
export const DialogFooter = () => null
export const DialogHeader = () => null
export const DialogTitle = () => null
export const DialogTrigger = () => null
export const DropdownMenu = () => null
export const DropdownMenuContent = () => null
export const DropdownMenuItem = () => null
export const DropdownMenuSeparator = () => null
export const DropdownMenuTrigger = () => null
export const EmptyState = () => null
export const ErrorState = () => null
export const Input = () => null
export const SearchField = () => null
export const SegmentedControl = () => null
export const Select = () => null
export const SelectContent = () => null
export const SelectItem = () => null
export const SelectTrigger = () => null
export const SelectValue = () => null
export const Separator = () => null
export const Skeleton = () => null
export const StatusDot = () => null
export const Switch = () => null
export const Tabs = () => null
export const TabsList = () => null
export const TabsTrigger = () => null
export const cn = (...items) => items.filter(Boolean).join(' ')
export const profileColor = () => 'color'
export const queryClient = { invalidateQueries() {} }
export const useMutation = () => [{}, () => {}]
export const useQuery = ({ queryKey }) => ({ data: values[queryKey[1]], error: null, isError: false, isFetching: false, isLoading: false, refetch: async () => ({ error: null, isError: false }) })
export const useQueryClient = () => ({ invalidateQueries() {} })
export const useValue = () => 'default'
"""

JSX_STUB = r"""
export const jsx = (type, props) => typeof type === 'function' ? type(props || {}) : ({ type, props })
export const jsxs = (type, props) => typeof type === 'function' ? type(props || {}) : ({ type, props })
"""

REACT_STUB = r"""
export const useEffect = () => {}
export const useState = initial => [initial, () => {}]
export const useCallback = fn => fn
export const useMemo = fn => fn()
export const useRef = initial => ({ current: initial })
"""

LOADER = r"""
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

HARNESS = r"""
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
"""


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
        encoding="utf-8",
        errors="replace",
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


def test_runtime_plugin_editing_dialogs_are_metadata_only() -> None:
    """Issue #90 dialog static contract: the Edit metadata and Rebind origin
    dialogs never render, prefill, or transmit secret material, and the row
    dropdown dispatches both new actions."""
    source = PLUGIN.read_text(encoding="utf-8")

    # Both dialogs exist and are dispatched from the row dropdown + VaultPage.
    assert "function EditMetadataDialog" in source
    assert "function RebindOriginDialog" in source
    assert "'edit-metadata'" in source
    assert "'rebind-origin'" in source
    assert "onEditMetadata" in source
    assert "onRebindOrigin" in source
    assert "/mutations/update-metadata" in source
    assert "/mutations/rebind-origin" in source

    # No secret-shaped fields anywhere in the editing dialogs: the secret is
    # never prefilled and cannot be replaced from these surfaces.
    forbidden = [
        "type: 'password'",
        "new_secret",
        "record.secret",
    ]
    edit_slice = source[source.index("function EditMetadataDialog") : source.index("// -- credential inventory table")]
    for needle in forbidden:
        assert needle not in edit_slice, f"EditMetadataDialog must not contain {needle}"

    rebind_slice = source[
        source.index("function RebindOriginDialog") : source.index("// -- credential inventory table")
    ]
    for needle in forbidden:
        assert needle not in rebind_slice, f"RebindOriginDialog must not contain {needle}"

    # Rebind type-to-confirm targets the NEW origin (the bridge rejects the
    # old origin / id as a confirmation: desktop_bridge.py #90 gate).
    assert "confirmation: confirmText" in source
    assert "new_service: normalizedNew" in source

    # The busy step keeps the rebind dialog mounted (no unmount mid-flight).
    assert "step === 'typeConfirm' || step === 'busy'" in source


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
# (verified by grepping app.asar dist/assets/index-DGdDbUKs.css on 2026-08-09;
# re-verify when the Hermes Desktop CSS contract changes).
CORE_PRESENT_CLASSES = frozenset(
    """
    animate-pulse bg-(--ui-bg-tertiary) block border border-(--ui-stroke-secondary)
    border-b flex flex-1 flex-wrap font-medium font-semibold gap-0.5 gap-1 gap-1.5
    gap-2 gap-3 gap-4 grid grid-cols-2 h-24 h-4 h-5 h-7 h-full inline-flex
    items-center justify-between justify-center justify-self-center leading-none
    max-w-3xl max-w-full min-w-0 mt-3 mt-4 mx-auto overflow-auto overflow-x-auto
    pt-3 px-2 px-3 px-6 py-1.5 py-10 py-2 py-2.5 py-4 py-5 rounded rounded-lg
    rounded-xl shrink-0 sticky tabular-nums text-(--ui-accent)
    text-(--ui-text-primary) text-(--ui-text-quaternary) text-(--ui-text-tertiary)
    text-[0.625rem] text-[0.6875rem] text-destructive text-lg text-sm text-xs top-0
    tracking-tight truncate w-36 w-5 w-56 w-full z-10
    """.split()
)

# Utilities the plugin uses that the packaged bundle does NOT generate.
# The plugin's injected stylesheet must cover every one of these.
KNOWN_MISSING_UTILITIES = frozenset(
    """
    bg-(--ui-background) bg-(--ui-control-background) gap-row grid-cols-cred-row
    grid-cols-stat justify-self-start lg:grid-cols-4 max-w-5xl md:grid-cols-4
    pb-5 w-96
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
# the whole page tree is walkable. The phase is mutable (__setVaultPhase) so a
# single mounted component can be re-rendered across the loading->success
# transition (React #310 regression guard).
SDK_RENDER_STUB = r"""
let PHASE = 'PHASE_PLACEHOLDER'
export function __setVaultPhase(phase) { PHASE = phase }
const values = {
  overview: { profile: 'default', credential_count: 1, lease_count: 0, active_lease_count: 0, services: ['demo'], recent_audit: [], health: { health_score: 100, healthy: true } },
  credentials: { credential_count: 1, credentials: [{ id: 'cred-1', service: 'demo', alias: 'metadata', status: 'unknown', credential_type: 'api_key' }] },
  leases: { lease_count: 0, leases: [] },
  policy: { policy_exists: true, agents: {}, doctor: { status: 'healthy' } },
  requests: { request_count: 0, requests: [] },
  integrity: { status: 'healthy', reason_code: 'ok', verified_count: 1, legacy_count: 0, recommended_next_step: 'none' },
  hello: { status: 'ok', mutations: true }
}
export const ROUTES_AREA = 'routes'
export const SIDEBAR_NAV_AREA = 'sidebar.nav'
export const PALETTE_AREA = 'palette'
export const host = { navigate() {}, state: { profile: { get: () => 'default' } } }
export const Badge = (p) => ({ tag: 'Badge', props: p })
export const Button = (p) => ({ tag: 'Button', props: p })
export const Checkbox = (p) => ({ tag: 'Checkbox', props: p })
export const Codicon = (p) => ({ tag: 'Codicon', props: p })
export const ConfirmDialog = (p) => ({ tag: 'ConfirmDialog', props: p })
export const Dialog = (p) => ({ tag: 'Dialog', props: p })
export const DialogContent = (p) => ({ tag: 'DialogContent', props: p })
export const DialogDescription = (p) => ({ tag: 'DialogDescription', props: p })
export const DialogFooter = (p) => ({ tag: 'DialogFooter', props: p })
export const DialogHeader = (p) => ({ tag: 'DialogHeader', props: p })
export const DialogTitle = (p) => ({ tag: 'DialogTitle', props: p })
export const DialogTrigger = (p) => ({ tag: 'DialogTrigger', props: p })
export const DropdownMenu = (p) => ({ tag: 'DropdownMenu', props: p })
export const DropdownMenuContent = (p) => ({ tag: 'DropdownMenuContent', props: p })
export const DropdownMenuItem = (p) => ({ tag: 'DropdownMenuItem', props: p })
export const DropdownMenuSeparator = (p) => ({ tag: 'DropdownMenuSeparator', props: p })
export const DropdownMenuTrigger = (p) => ({ tag: 'DropdownMenuTrigger', props: p })
export const EmptyState = (p) => ({ tag: 'EmptyState', props: p })
export const ErrorState = (p) => ({ tag: 'ErrorState', props: p })
export const Input = (p) => ({ tag: 'Input', props: p })
export const SearchField = (p) => ({ tag: 'SearchField', props: p })
export const SegmentedControl = (p) => ({ tag: 'SegmentedControl', props: p })
export const Select = (p) => ({ tag: 'Select', props: p })
export const SelectContent = (p) => ({ tag: 'SelectContent', props: p })
export const SelectItem = (p) => ({ tag: 'SelectItem', props: p })
export const SelectTrigger = (p) => ({ tag: 'SelectTrigger', props: p })
export const SelectValue = (p) => ({ tag: 'SelectValue', props: p })
export const Separator = (p) => ({ tag: 'Separator', props: p })
export const Skeleton = (p) => ({ tag: 'Skeleton', props: p })
export const StatusDot = (p) => ({ tag: 'StatusDot', props: p })
export const Switch = (p) => ({ tag: 'Switch', props: p })
export const Tabs = (p) => ({ tag: 'Tabs', props: p })
export const TabsList = (p) => ({ tag: 'TabsList', props: p })
export const TabsTrigger = (p) => ({ tag: 'TabsTrigger', props: p })
export const cn = (...items) => items.filter(Boolean).join(' ')
export const profileColor = () => 'color'
export const queryClient = { invalidateQueries() {} }
export const useMutation = () => [{}, () => {}]
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

# Hook-count-enforcing react stub. Real React throws "Rendered more hooks than
# during the previous render" (error #310) when a component instance changes
# its hook count between renders. These stubs reproduce exactly that check:
# every function-component render opens a frame, every hook call increments
# the frame's count, and closing a frame whose count differs from the same
# component's previous render throws #310. beginRender/endRender are consumed
# by JSX_HOOKCOUNT_STUB (same module, same render frames).
REACT_HOOKCOUNT_STUB = r"""
const hookCounts = new Map()
const frameStack = []
const countStack = []

export function beginRender(fn) {
  frameStack.push(fn)
  countStack.push(0)
}

export function endRender() {
  const fn = frameStack.pop()
  const count = countStack.pop()
  if (fn === undefined || count === undefined) throw new Error('render frame underflow')
  const prev = hookCounts.get(fn)
  if (prev !== undefined && prev !== count) {
    throw new Error(
      'Minified React error #310: rendered ' + count + ' hooks but the previous render of ' +
      (fn.name || '(anonymous)') + ' used ' + prev + ' hooks'
    )
  }
  hookCounts.set(fn, count)
}

function trackHook() {
  if (countStack.length === 0) throw new Error('Hook called outside a component render')
  countStack[countStack.length - 1] += 1
}

export const useEffect = () => { trackHook() }
export const useState = (initial) => { trackHook(); return [initial, function () {}] }
export const useCallback = (fn) => { trackHook(); return fn }
export const useMemo = (fn) => { trackHook(); return fn() }
export const useRef = (initial) => { trackHook(); return { current: initial } }
"""

# Stateful hook-count stub: same #310 enforcement as REACT_HOOKCOUNT_STUB plus
# real useState persistence keyed by component fn + hook position. This lets a
# harness drive DeleteCredentialDialog step transitions (impact -> typeConfirm)
# through the ACTUAL onClick handlers, within ONE mount, the same way the real
# desktop does — the impact->typeConfirm flip is what makes the pre-fix dialog
# grow from 5 to 7 hooks.
REACT_HOOKCOUNT_STATEFUL_STUB = r"""
const hookCounts = new Map()
const frameStack = []
const countStack = []
const stateByFn = new Map()

export function beginRender(fn) {
  frameStack.push(fn)
  countStack.push(0)
}

export function endRender() {
  const fn = frameStack.pop()
  const count = countStack.pop()
  if (fn === undefined || count === undefined) throw new Error('render frame underflow')
  const prev = hookCounts.get(fn)
  if (prev !== undefined && prev !== count) {
    throw new Error(
      'Minified React error #310: rendered ' + count + ' hooks but the previous render of ' +
      (fn.name || '(anonymous)') + ' used ' + prev + ' hooks'
    )
  }
  hookCounts.set(fn, count)
}

function trackHook() {
  if (countStack.length === 0) throw new Error('Hook called outside a component render')
  countStack[countStack.length - 1] += 1
}

function stateSlot(fn, idx) {
  let slots = stateByFn.get(fn)
  if (!slots) { slots = []; stateByFn.set(fn, slots) }
  if (slots[idx] === undefined) {
    let value = undefined
    const setter = (v) => { value = typeof v === 'function' ? v(value) : v }
    slots[idx] = { get: () => value, set: setter, init: (v) => { if (value === undefined) value = v } }
  }
  return slots[idx]
}

export const useState = (initial) => {
  trackHook()
  const fn = frameStack[frameStack.length - 1]
  const idx = countStack[countStack.length - 1] - 1
  const slot = stateSlot(fn, idx)
  slot.init(initial)
  return [slot.get(), slot.set]
}
export const useEffect = () => { trackHook() }
export const useCallback = (fn) => { trackHook(); return fn }
export const useMemo = (fn) => { trackHook(); return fn() }
export const useRef = (initial) => { trackHook(); return { current: initial } }
"""

# jsx/jsxs variant that wraps every function-component render in
# beginRender/endRender so REACT_HOOKCOUNT_STUB can enforce React #310 across
# renders of the same component instance. Imported relative to react.mjs so
# both the plugin's 'react' and 'react/jsx-runtime' specifiers share one module
# instance (loader maps them to the same two files in the tmp dir).
JSX_HOOKCOUNT_STUB = r"""
import { beginRender, endRender } from './react.mjs'
function renderFn(type, props) {
  beginRender(type)
  try {
    return type(props || {})
  } finally {
    endRender()
  }
}
export const jsx = (type, props) => (typeof type === 'function' ? renderFn(type, props) : { tag: type, props: props || {} })
export const jsxs = (type, props) => (typeof type === 'function' ? renderFn(type, props) : { tag: type, props: props || {} })
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
// Health strip: the v1 UI renders four HealthStat values with
// 'text-sm font-semibold tabular-nums' (replacing the old text-xl
// CountCards). The pane record uses the value's label sibling.
const panes = els
  .filter(e => /text-sm/.test(e.className) && /tabular-nums/.test(e.className) && e.parent && /HealthStat|grid/.test(e.parent.className || ''))
  .map(v => ({
    label: v.parent && v.parent.children[0] ? v.parent.children[0].text.join('') : '',
    value: v.text.join(''),
    detail: v.parent && v.parent.children[2] ? v.parent.children[2].text.join('') : ''
  }))
console.log('RESULT=' + JSON.stringify({ skeletonCards, panes, classes: [...classSet].sort(), stylesheet: STYLESHEET }))
"""

# Phase-flip harness (React #310 regression guard, t_cae27701): mounts the
# plugin ONCE and renders the page component across the loading->success
# transition within the SAME mount. The SDK stub's phase is flipped with
# __setVaultPhase between renders, so the second render sees isLoading=false
# while the component instance (and its hook history) is unchanged — exactly
# the situation that produced "Rendered more hooks than during the previous
# render" on the real desktop. With REACT_HOOKCOUNT_STUB active, a hook-count
# jump throws #310 and the node subprocess exits non-zero.
HARNESS_PHASEFLIP = r"""
import { pathToFileURL } from 'node:url'
const pluginMod = await import(pathToFileURL(process.env.PLUGIN).href)
const sdk = await import(pathToFileURL(process.env.SDK_STUB).href)
const plugin = pluginMod.default
const contributions = []
const ctx = {
  registerMany(items) { contributions.push(...items); return () => {} },
  rest: async () => ({}),
  i18n: { register() {}, t(key) { return key } },
  storage: { get(k, f) { return f }, set() {} }
}
plugin.register(ctx)
const page = contributions.find(c => c.id === 'page')

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

function subtreeText(el) {
  return el.text.join('') + el.children.map(subtreeText).join('')
}

// Phase 1: loading — useQuery stub reports isLoading=true (async pending).
const loadingTree = page.render()
const loadingEls = flatten(loadingTree, null)
const skeletonCards = loadingEls.filter(e => /animate-pulse/.test(e.className) && /h-24/.test(e.className)).length

// Phase 2: success — flip the SAME stub's phase, then render the SAME
// component instance again. React #310 fires exactly here if the component's
// hook count changed between renders.
sdk.__setVaultPhase('success')
const successTree = page.render()
const successEls = flatten(successTree, null)
const tabLabels = successEls.filter(e => e.tag === 'TabsTrigger').map(subtreeText)
const panes = successEls
  .filter(e => /text-sm/.test(e.className) && /tabular-nums/.test(e.className) && e.parent && /HealthStat|grid/.test(e.parent.className || ''))
  .map(v => ({
    label: v.parent && v.parent.children[0] ? v.parent.children[0].text.join('') : '',
    value: v.text.join(''),
    detail: v.parent && v.parent.children[2] ? v.parent.children[2].text.join('') : ''
  }))
console.log('RESULT=' + JSON.stringify({ skeletonCards, tabLabels, panes }))
"""

# Delete-dialog step-flip harness (React #310 regression guard, t_3e8d525a):
# mounts the plugin ONCE, renders the success page, then drives the REAL click
# path into DeleteCredentialDialog: invoke the row's Delete menu item (opens
# the dialog at the impact step), invoke "Continue to confirmation" (flips the
# dialog's internal step to typeConfirm), and re-render the SAME component
# instance. Uses REACT_HOOKCOUNT_STATEFUL_STUB so useState setters actually
# persist across renders within the mount — pre-fix, the typeConfirm branch
# runs useRef + useEffect AFTER the impact early return, so the dialog's hook
# count jumps and the stub throws #310 exactly like real React.
HARNESS_DIALOG_FLIP = r"""
import { pathToFileURL } from 'node:url'
const pluginMod = await import(pathToFileURL(process.env.PLUGIN).href)
const sdk = await import(pathToFileURL(process.env.SDK_STUB).href)
const plugin = pluginMod.default
const contributions = []
const ctx = {
  registerMany(items) { contributions.push(...items); return () => {} },
  rest: async () => ({}),
  i18n: { register() {}, t(key) { return key } },
  storage: { get(k, f) { return f }, set() {} }
}
plugin.register(ctx)
const page = contributions.find(c => c.id === 'page')

function nodeText(node) {
  if (node === null || node === undefined || typeof node === 'boolean') return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(nodeText).join('')
  if (typeof node === 'object' && node.props) return nodeText(node.props.children)
  return ''
}

function findNodes(root, tag, needle) {
  const out = []
  function walk(node) {
    if (node === null || node === undefined || typeof node === 'boolean') return
    if (Array.isArray(node)) { for (const k of node) walk(k); return }
    if (typeof node === 'object' && node.tag && node.props) {
      if (String(node.tag) === tag && nodeText(node).includes(needle)) out.push(node)
      walk(node.props.children)
    }
  }
  walk(root)
  return out
}

// Phase 1: success render — credentials tab shows one row with a Delete item.
const tree0 = page.render()
const deleteItems = findNodes(tree0, 'DropdownMenuItem', 'Delete')
if (deleteItems.length === 0) throw new Error('Delete menu item not found in row actions')
deleteItems[0].props.onClick()

// Phase 2: re-render — the delete dialog mounts at the impact step.
const tree1 = page.render()
const continueButtons = findNodes(tree1, 'Button', 'Continue to confirmation')
if (continueButtons.length === 0) throw new Error('Continue-to-confirmation button not found')
continueButtons[0].props.onClick()

// Phase 3: re-render — the SAME mounted dialog transitions impact -> typeConfirm.
// Pre-fix this throws React #310 (4 -> 6 tracked hooks) and node exits non-zero.
const tree2 = page.render()
const confirmInputs = findNodes(tree2, 'Input', '')
const hasConfirmInput = confirmInputs.some(n => n.props && n.props.id === 'confirm-delete-input')
const confirmTitles = findNodes(tree2, 'DialogTitle', 'Confirm deletion')
console.log('RESULT=' + JSON.stringify({ deleteItemFound: deleteItems.length > 0, continueFound: continueButtons.length > 0, hasConfirmInput, confirmTitleFound: confirmTitles.length > 0 }))
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


# Issue #90 editing-flows SDK stub: success-phase data with a tagged, noted,
# aliased credential so the EditMetadataDialog prefills alias+tags (the no-op
# regression) and shows the notes-clear affordance. ctx.rest captures every
# mutation call (path + body) instead of returning an empty object.
SDK_EDITING_STUB = r"""
export const ROUTES_AREA = 'routes'
export const SIDEBAR_NAV_AREA = 'sidebar.nav'
export const PALETTE_AREA = 'palette'
export const host = { navigate() {}, notify() {}, state: { profile: { get: () => 'default' } } }
export const Badge = (p) => ({ tag: 'Badge', props: p })
export const Button = (p) => ({ tag: 'Button', props: p })
export const Checkbox = (p) => ({ tag: 'Checkbox', props: p })
export const Codicon = (p) => ({ tag: 'Codicon', props: p })
export const ConfirmDialog = (p) => ({ tag: 'ConfirmDialog', props: p })
export const Dialog = (p) => ({ tag: 'Dialog', props: p })
export const DialogContent = (p) => ({ tag: 'DialogContent', props: p })
export const DialogDescription = (p) => ({ tag: 'DialogDescription', props: p })
export const DialogFooter = (p) => ({ tag: 'DialogFooter', props: p })
export const DialogHeader = (p) => ({ tag: 'DialogHeader', props: p })
export const DialogTitle = (p) => ({ tag: 'DialogTitle', props: p })
export const DialogTrigger = (p) => ({ tag: 'DialogTrigger', props: p })
export const DropdownMenu = (p) => ({ tag: 'DropdownMenu', props: p })
export const DropdownMenuContent = (p) => ({ tag: 'DropdownMenuContent', props: p })
export const DropdownMenuItem = (p) => ({ tag: 'DropdownMenuItem', props: p })
export const DropdownMenuSeparator = (p) => ({ tag: 'DropdownMenuSeparator', props: p })
export const DropdownMenuTrigger = (p) => ({ tag: 'DropdownMenuTrigger', props: p })
export const EmptyState = (p) => ({ tag: 'EmptyState', props: p })
export const ErrorState = (p) => ({ tag: 'ErrorState', props: p })
export const Input = (p) => ({ tag: 'Input', props: p })
export const SearchField = (p) => ({ tag: 'SearchField', props: p })
export const SegmentedControl = (p) => ({ tag: 'SegmentedControl', props: p })
export const Select = (p) => ({ tag: 'Select', props: p })
export const SelectContent = (p) => ({ tag: 'SelectContent', props: p })
export const SelectItem = (p) => ({ tag: 'SelectItem', props: p })
export const SelectTrigger = (p) => ({ tag: 'SelectTrigger', props: p })
export const SelectValue = (p) => ({ tag: 'SelectValue', props: p })
export const Separator = (p) => ({ tag: 'Separator', props: p })
export const Skeleton = (p) => ({ tag: 'Skeleton', props: p })
export const StatusDot = (p) => ({ tag: 'StatusDot', props: p })
export const Switch = (p) => ({ tag: 'Switch', props: p })
export const Tabs = (p) => ({ tag: 'Tabs', props: p })
export const TabsList = (p) => ({ tag: 'TabsList', props: p })
export const TabsTrigger = (p) => ({ tag: 'TabsTrigger', props: p })
export const cn = (...items) => items.filter(Boolean).join(' ')
export const profileColor = () => 'color'
export const queryClient = { invalidateQueries() {} }
export const useMutation = () => [{}, () => {}]
const values = {
  overview: { profile: 'default', credential_count: 1, lease_count: 0, active_lease_count: 0, services: ['demo'], recent_audit: [], health: { health_score: 100, healthy: true } },
  credentials: { credential_count: 1, credentials: [{ id: 'cred-1', service: 'demo', alias: 'metadata', status: 'unknown', credential_type: 'api_key', tags: ['prod'], has_notes: true, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z' }] },
  leases: { lease_count: 0, leases: [] },
  policy: { policy_exists: true, agents: {}, doctor: { status: 'healthy' } },
  requests: { request_count: 0, requests: [] },
  integrity: { status: 'healthy', reason_code: 'ok', verified_count: 1, legacy_count: 0, recommended_next_step: 'none' },
  hello: { status: 'ok', mutations: true }
}
export const useQuery = ({ queryKey }) => ({ data: values[queryKey[1]], error: null, isError: false, isFetching: false, isLoading: false, refetch: async () => ({ error: null, isError: false }) })
export const useQueryClient = () => ({ invalidateQueries() {} })
export const useValue = (atom) => (atom && typeof atom.get === 'function' ? atom.get() : 'default')
"""

# Issue #90 editing-flows harness: mounts the plugin ONCE and drives the REAL
# click path through both new dialogs with the stateful hook stub:
#   Edit metadata: open -> prefilled Continue DISABLED (no-op guard) ->
#     edit tags -> Continue -> ConfirmDialog onConfirm -> captured body has
#     ONLY changed fields, no secret keys, no ?profile= query -> success ->
#     reopen -> clear tags -> captured body carries tags: [] (clear).
#   Rebind origin: open -> type new origin (normalization) -> Continue ->
#     type-to-confirm NEW origin -> Rebind -> busy step STAYS MOUNTED (the
#     pre-fix dialog returned null mid-flight) -> captured body carries
#     confirmation === normalized new_service.
HARNESS_EDITING_FLOWS = r"""
import { pathToFileURL } from 'node:url'
const pluginMod = await import(pathToFileURL(process.env.PLUGIN).href)
const plugin = pluginMod.default
const contributions = []
const calls = []
const ctx = {
  registerMany(items) { contributions.push(...items); return () => {} },
  rest: async (path, opts) => { calls.push({ path, opts: opts || {} }); return {} },
  i18n: { register() {}, t(key) { return key } },
  storage: { get(k, f) { return f }, set() {} }
}
plugin.register(ctx)
const page = contributions.find(c => c.id === 'page')

function nodeText(node) {
  if (node === null || node === undefined || typeof node === 'boolean') return ''
  if (typeof node === 'string' || typeof node === 'number') return String(node)
  if (Array.isArray(node)) return node.map(nodeText).join('')
  if (typeof node === 'object' && node.props) return nodeText(node.props.children)
  return ''
}

function findNodes(root, tag, needle) {
  const out = []
  function walk(node) {
    if (node === null || node === undefined || typeof node === 'boolean') return
    if (Array.isArray(node)) { for (const k of node) walk(k); return }
    if (typeof node === 'object' && node.tag && node.props) {
      if (String(node.tag) === tag && nodeText(node).includes(needle)) out.push(node)
      walk(node.props.children)
    }
  }
  walk(root)
  return out
}

function inputByPlaceholder(root, placeholder) {
  const inputs = []
  function walk(node) {
    if (node === null || node === undefined || typeof node === 'boolean') return
    if (Array.isArray(node)) { for (const k of node) walk(k); return }
    if (typeof node === 'object' && node.tag && node.props) {
      if (String(node.tag) === 'Input' && node.props.placeholder === placeholder) inputs.push(node)
      walk(node.props.children)
    }
  }
  walk(root)
  return inputs[0]
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 20))
const out = { errors: [] }

// The ConfirmDialog stub keeps its title in props (children never render),
// so confirm steps are located by title prop rather than subtree text.
function findDialogByTitle(root, titleNeedle) {
  const out2 = []
  function walk(node) {
    if (node === null || node === undefined || typeof node === 'boolean') return
    if (Array.isArray(node)) { for (const k of node) walk(k); return }
    if (typeof node === 'object' && node.tag && node.props) {
      if (String(node.tag) === 'ConfirmDialog' && String(node.props.title || '').includes(titleNeedle)) out2.push(node)
      walk(node.props.children)
    }
  }
  walk(root)
  return out2[0]
}

// ---------- Edit metadata: first pass (edit tags) ----------
let tree = page.render()
let editItem = findNodes(tree, 'DropdownMenuItem', 'Edit metadata')[0]
if (!editItem) throw new Error('Edit metadata menu item not found in row actions')
editItem.props.onClick()

tree = page.render()
if (findNodes(tree, 'DialogTitle', 'Edit metadata').length === 0) throw new Error('edit dialog did not open')
let continueBtn = findNodes(tree, 'Button', 'Continue')[0]
if (!continueBtn) throw new Error('Continue button not found in edit dialog')
if (continueBtn.props.disabled !== true) out.errors.push('prefilled alias+tags must NOT count as a change (Continue enabled on open)')

const tagsInput = inputByPlaceholder(tree, 'prod, personal')
if (!tagsInput) throw new Error('tags input not found (prefill missing?)')
if (tagsInput.props.value !== 'prod') throw new Error('tags input not prefilled with existing tags')
tagsInput.props.onChange({ target: { value: 'staging, ci' } })

tree = page.render()
continueBtn = findNodes(tree, 'Button', 'Continue')[0]
if (!continueBtn || continueBtn.props.disabled === true) out.errors.push('Continue must enable after editing tags')
continueBtn.props.onClick()

tree = page.render()
const confirmDlg = findDialogByTitle(tree, 'Edit metadata')
if (!confirmDlg) throw new Error('confirm step did not render')
confirmDlg.props.onConfirm()
await tick()

if (calls.length !== 1) throw new Error('expected exactly one mutation call, got ' + calls.length)
const editBody = JSON.parse(calls[0].opts.body)
if (calls[0].path !== '/mutations/update-metadata') out.errors.push('edit call path: ' + calls[0].path)
if (calls[0].opts.method !== 'POST') out.errors.push('edit call not POST')
if (editBody.service_or_id !== 'demo') out.errors.push('service_or_id: ' + editBody.service_or_id)
if (editBody.alias !== 'metadata') out.errors.push('resolution alias missing: ' + JSON.stringify(editBody))
if (editBody.tags === undefined || String(editBody.tags) !== 'staging,ci') out.errors.push('tags: ' + JSON.stringify(editBody.tags))
if ('secret' in editBody || 'new_secret' in editBody) out.errors.push('secret-shaped field in edit body')
if ('notes' in editBody) out.errors.push('notes sent without operator input')

tree = page.render()
if (findNodes(tree, 'DialogTitle', 'Edit metadata').length !== 0) out.errors.push('edit dialog did not close after success')

// ---------- Edit metadata: second pass (clear tags -> tags: []) ----------
editItem = findNodes(tree, 'DropdownMenuItem', 'Edit metadata')[0]
editItem.props.onClick()
tree = page.render()
const tagsInput2 = inputByPlaceholder(tree, 'prod, personal')
if (!tagsInput2) throw new Error('tags input missing on reopen')
tagsInput2.props.onChange({ target: { value: '' } })
tree = page.render()
continueBtn = findNodes(tree, 'Button', 'Continue')[0]
if (!continueBtn || continueBtn.props.disabled === true) out.errors.push('Continue must enable when clearing tags')
continueBtn.props.onClick()
tree = page.render()
findDialogByTitle(tree, 'Edit metadata').props.onConfirm()
await tick()

const clearBody = JSON.parse(calls[1].opts.body)
if (JSON.stringify(clearBody.tags) !== '[]') out.errors.push('clearing tags must send tags: [], got ' + JSON.stringify(clearBody.tags))

// ---------- Rebind origin ----------
tree = page.render()
const rebindItem = findNodes(tree, 'DropdownMenuItem', 'Rebind origin')[0]
if (!rebindItem) throw new Error('Rebind origin menu item not found in row actions')
rebindItem.props.onClick()

tree = page.render()
if (findNodes(tree, 'DialogTitle', 'Rebind origin').length === 0) throw new Error('rebind dialog did not open')
const newOriginInput = inputByPlaceholder(tree, 'e.g. accounts.google.com')
if (!newOriginInput) throw new Error('new-origin input not found')
newOriginInput.props.onChange({ target: { value: 'GitHub Demo' } })

tree = page.render()
continueBtn = findNodes(tree, 'Button', 'Continue')[0]
if (!continueBtn || continueBtn.props.disabled === true) out.errors.push('Continue must enable after typing a new origin')
continueBtn.props.onClick()

tree = page.render()
if (findNodes(tree, 'DialogTitle', 'Confirm origin rebind').length === 0) throw new Error('rebind typeConfirm step did not render')
const confirmInput = inputByPlaceholder(tree, 'github_demo')
if (!confirmInput) throw new Error('confirm input placeholder must be the NORMALIZED new origin')
confirmInput.props.onChange({ target: { value: 'github_demo' } })

tree = page.render()
const rebindBtn = findNodes(tree, 'Button', 'Rebind origin')[0]
if (!rebindBtn || rebindBtn.props.disabled === true) out.errors.push('Rebind button must enable on exact match')
if (findNodes(tree, 'Button', 'demo').length !== 0) out.errors.push('old origin must not be an accepted confirmation target')
rebindBtn.props.onClick()

// busy step must stay mounted (pre-fix: `step === 'busy'` fell through to
// return null and the dialog vanished mid-flight).
tree = page.render()
if (findNodes(tree, 'DialogTitle', 'Confirm origin rebind').length === 0) out.errors.push('rebind dialog UNMOUNTED during busy step')
if (findNodes(tree, 'Button', 'Working').length === 0) out.errors.push('busy Working button not rendered')
await tick()

const rebindBody = JSON.parse(calls[2].opts.body)
if (calls[2].path !== '/mutations/rebind-origin') out.errors.push('rebind call path: ' + calls[2].path)
if (rebindBody.new_service !== 'github_demo') out.errors.push('new_service: ' + JSON.stringify(rebindBody.new_service))
if (rebindBody.confirmation !== 'github_demo') out.errors.push('confirmation must equal the NEW origin: ' + JSON.stringify(rebindBody.confirmation))
if (rebindBody.service_or_id !== 'demo' || rebindBody.alias !== 'metadata') out.errors.push('rebind target: ' + JSON.stringify(rebindBody))
if ('secret' in rebindBody || 'new_secret' in rebindBody) out.errors.push('secret-shaped field in rebind body')

for (const c of calls) {
  if (c.path.includes('?')) out.errors.push('mutation path must not carry query params: ' + c.path)
}

console.log('RESULT=' + JSON.stringify({ calls: calls.length, errors: out.errors }))
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
    """All class selectors defined by the plugin stylesheet, unescaped.

    Handles both top-level rules and rules nested inside ``@media`` blocks
    (the responsive grid utilities live in media queries).
    """
    out = set()
    # Top-level rules.
    for sel in re.findall(r"\.((?:\\\\.|[^{}])+)\{", stylesheet):
        for part in sel.split(","):
            out.add(_unescape_css_class(part.strip()))
    # Rules inside @media blocks: strip the media wrapper, then re-scan.
    for block in re.findall(r"@media[^{]+\{([^{}]+(?:\{[^{}]*\}[^{}]*)*)\}", stylesheet):
        for sel in re.findall(r"\.((?:\\\\.|[^{}])+)\{", block):
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
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    line = next(l for l in result.stdout.strip().splitlines() if l.startswith("RESULT="))
    return json.loads(line[len("RESULT=") :])


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

    # After async data settles, all four health-strip panes render with non-empty values.
    # (v1 UI: Credentials / Needs attention / Leases / Integrity — the old "Profile"
    # pane was replaced by the client-side attention bucket.)
    assert [p["label"] for p in success["panes"]] == ["Credentials", "Needs attention", "Leases", "Integrity"]
    for pane in success["panes"]:
        assert pane["value"] and pane["value"] != "—", f"pane {pane['label']} rendered empty: {pane}"

    # Integrity stat must derive from the /integrity endpoint, NOT from
    # overview.health.integrity_status — the real bridge overview payload
    # never includes that key, so the old derivation rendered a false red
    # "✗ Check" even when integrity was healthy (caught on the live surface
    # during post-approval verification; fixtures now mirror the real
    # bridge payload: overview.health has no status/integrity_status).
    integrity_pane = next(p for p in success["panes"] if p["label"] == "Integrity")
    assert integrity_pane["value"] == "✓ Healthy", (
        f"Integrity pane must derive from the /integrity endpoint result: {integrity_pane}"
    )

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
    assert not missing_uncovered, (
        f"plugin stylesheet does not cover bundle-missing utilities: {sorted(missing_uncovered)}"
    )

    # Skeleton fill rule must set an actual background-color (not transparent).
    assert re.search(r"\.bg-\\\(--ui-control-background\\\)\s*\{[^}]*background-color", stylesheet)


def test_runtime_plugin_vaultpage_hooks_stable_across_loading_to_success(tmp_path: Path) -> None:
    """Regression guard for React #310 (t_cae27701): VaultPage declared five
    hooks (useState x3 + useCallback x2) AFTER the overviewQ.isLoading /
    overviewQ.error early returns. On the real desktop the first render
    executed ~23 hooks; once query data settled, the same component instance
    executed ~28 -> "Rendered more hooks than during the previous render".

    Unlike the blank-panes tests above (separate subprocess mounts per phase),
    this mounts the plugin ONCE and flips the useQuery stub's phase from
    loading to success between renders of the SAME component instance. The
    hook-count-enforcing react stub (REACT_HOOKCOUNT_STUB) throws exactly like
    React's rules-of-hooks check when a component's hook count changes between
    renders, so the pre-fix plugin fails this test with #310 and the post-fix
    plugin renders both phases cleanly. Note the stub counts only hooks routed
    through the react module (14 -> 19 across the transition); SDK hooks
    (useValue/useQuery/useQueryClient) are untracked, so the measured delta of
    5 matches the real-desktop delta even though the absolute counts differ.
    """
    files = {
        "sdk.mjs": SDK_RENDER_STUB.replace("PHASE_PLACEHOLDER", "loading"),
        "jsx.mjs": JSX_HOOKCOUNT_STUB,
        "react.mjs": REACT_HOOKCOUNT_STUB,
        "loader.mjs": LOADER_RENDER,
        "harness.mjs": HARNESS_PHASEFLIP,
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
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    line = next(l for l in result.stdout.strip().splitlines() if l.startswith("RESULT="))
    payload = json.loads(line[len("RESULT=") :])

    # Loading phase rendered the skeleton state (the four blank cards).
    assert payload["skeletonCards"] == 4

    # Success phase rendered the full page with all six tabs, in order.
    assert payload["tabLabels"] == ["Credentials", "Access requests", "Leases", "Policy", "Audit", "Operations"]

    # Health strip panes rendered with non-empty values.
    assert [p["label"] for p in payload["panes"]] == ["Credentials", "Needs attention", "Leases", "Integrity"]
    for pane in payload["panes"]:
        assert pane["value"] and pane["value"] != "—", f"pane {pane['label']} rendered empty: {pane}"


def test_runtime_plugin_delete_dialog_hooks_stable_across_impact_to_typeconfirm(tmp_path: Path) -> None:
    """Regression guard for React #310 (t_3e8d525a): DeleteCredentialDialog
    declared useRef + useEffect INSIDE the `step === 'typeConfirm'` branch, one
    branch AFTER the `step === 'impact'` early return. On the real desktop a
    mounted dialog instance transitioning impact -> typeConfirm executes 5
    hooks on the impact render and 7 on the typeConfirm render ->
    "Rendered more hooks than during the previous render".

    Same-mount construction as the VaultPage guard (t_cae27701): mount the
    plugin ONCE, render the success page, then drive the REAL click path —
    invoke the row's Delete menu item (mounts the dialog at impact), invoke
    "Continue to confirmation" (flips the dialog's internal step to
    typeConfirm), and re-render the SAME component instance. Unlike the
    VaultPage guard, this uses REACT_HOOKCOUNT_STATEFUL_STUB whose useState
    persists across renders keyed by component fn, so the onClick handlers
    actually change state the way real React does. Pre-fix, the typeConfirm
    render runs useRef + useEffect after the impact early return, the stub
    throws #310 and node exits non-zero; post-fix, both steps render cleanly
    with a stable hook count. The stub counts only hooks routed through the
    react module (4 -> 6 across the pre-fix transition); SDK hooks
    (useQuery/useQueryClient/useValue) are untracked, so the measured delta of
    2 matches the real-desktop 5 -> 7 delta.
    """
    files = {
        "sdk.mjs": SDK_RENDER_STUB.replace("PHASE_PLACEHOLDER", "success"),
        "jsx.mjs": JSX_HOOKCOUNT_STUB,
        "react.mjs": REACT_HOOKCOUNT_STATEFUL_STUB,
        "loader.mjs": LOADER_RENDER,
        "harness.mjs": HARNESS_DIALOG_FLIP,
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
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    line = next(l for l in result.stdout.strip().splitlines() if l.startswith("RESULT="))
    payload = json.loads(line[len("RESULT=") :])

    # The row action menu rendered a Delete item and the dialog opened at impact.
    assert payload["deleteItemFound"] is True
    assert payload["continueFound"] is True

    # The typeConfirm step rendered with the confirm input + title (no #310).
    assert payload["hasConfirmInput"] is True
    assert payload["confirmTitleFound"] is True


def test_runtime_plugin_editing_dialogs_full_flows(tmp_path: Path) -> None:
    """Issue #90 behavioral coverage: drives the REAL click paths through both
    editing dialogs (Edit metadata, Rebind origin) in one mount with a
    stateful-hook stub, capturing every mutation call.

    Guards the contract end-to-end at the renderer surface:
    - row dropdown dispatches both new actions and VaultPage mounts the dialogs
    - Edit: prefilled fields do not count as a change (no no-op audit writes);
      only edited fields are sent; no secret-shaped keys; no ?profile= query
      (mutation routes 400 on query params); tags can be CLEARED (tags: [])
    - Rebind: new origin is normalized (spaces/case); type-to-confirm targets
      the NEW origin (the bridge rejects the old origin/id token); the busy
      step keeps the dialog mounted (pre-fix it returned null mid-flight)
    - both bodies are metadata-only (no secret, no new_secret)
    """
    files = {
        "sdk.mjs": SDK_EDITING_STUB,
        "jsx.mjs": JSX_HOOKCOUNT_STUB,
        "react.mjs": REACT_HOOKCOUNT_STATEFUL_STUB,
        "loader.mjs": LOADER_RENDER,
        "harness.mjs": HARNESS_EDITING_FLOWS,
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
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    line = next(l for l in result.stdout.strip().splitlines() if l.startswith("RESULT="))
    payload = json.loads(line[len("RESULT=") :])

    # Three mutations captured: edit-tags, clear-tags, rebind.
    assert payload["calls"] == 3, payload
    # The harness collects contract violations as strings; all must be absent.
    assert payload["errors"] == [], f"editing flow contract violations: {payload['errors']}"
