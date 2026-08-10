import { useEffect, useState, useCallback, useMemo, useRef } from 'react'
import {
  Badge,
  Button,
  Checkbox,
  Codicon,
  ConfirmDialog,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  EmptyState,
  ErrorState,
  Input,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  SearchField,
  SegmentedControl,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Separator,
  Skeleton,
  StatusDot,
  Switch,
  Tabs,
  TabsList,
  TabsTrigger,
  cn,
  host,
  profileColor,
  queryClient,
  useMutation,
  useQuery,
  useQueryClient,
  useValue
} from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

// -- constants ----------------------------------------------------------------
const ID = 'hermes-vault-desktop'
const DEFAULT_PROFILE = 'default'
const QUERY_ROOT = [ID]
const REFRESH_INTERVAL_MS = 30_000
const REQUEST_TIMEOUT_MS = 8_000
const MUTATION_TIMEOUT_MS = 15_000
const STALE_DAYS = 90
const UNVERIFIED_DAYS = 30
const EXPIRY_WARN_DAYS = 30

// -- scoped CSS polyfills -----------------------------------------------------
const STYLE_ID = 'hermes-vault-desktop-styles'
const SCOPED_CSS = [
  '.bg-\\(--ui-control-background\\) { background-color: var(--ui-bg-tertiary); }',
  '.bg-\\(--ui-background\\) { background-color: var(--ui-editor-surface-background); }',
  '.max-w-5xl { max-width: 64rem; }',
  '.pb-5 { padding-bottom: 1.25rem; }',
  '.w-96 { width: 24rem; }',
  '.justify-self-start { justify-self: start; }',
  '@media (min-width: 768px) { .md\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); } }',
  '@media (min-width: 1024px) { .lg\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); } }',
  '@media (min-width: 640px) { .sm\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); } }',
  '.grid-cols-stat { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }',
  '.grid-cols-cred-row { grid-template-columns: auto 1fr minmax(0, 1fr) auto auto auto; }',
  '.gap-row { gap: 0.75rem; }'
].join('\n')

export const STYLESHEET = SCOPED_CSS

function ensureStyles() {
  if (typeof document === 'undefined') return
  var style = document.getElementById(STYLE_ID)
  if (!style) {
    style = document.createElement('style')
    style.id = STYLE_ID
    document.head.appendChild(style)
  }
  if (style.textContent !== SCOPED_CSS) style.textContent = SCOPED_CSS
}

// -- utility helpers ----------------------------------------------------------
function profilePath(path, profile, extra) {
  var extraStr = extra || ''
  var query = 'profile=' + encodeURIComponent(profile)
  return path + '?' + query + extraStr
}

function safeText(value, fallback) {
  var fb = arguments.length > 1 ? fallback : '—'
  if (typeof value !== 'string' || !value || value.length > 160 || /[\u0000-\u001f\u007f]/.test(value)) {
    return fb
  }
  return value
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0 ? String(value) : '—'
}

function errorDetails(error) {
  if (!error || typeof error !== 'object') {
    return { kind: 'generic', title: 'Vault metadata unavailable', description: 'The Vault bridge did not return metadata.' }
  }
  var status = error.status || error.statusCode || (error.response && error.response.status)
  var body = error.body || error.data || (error.response && error.response.data)
  var nested = body && typeof body === 'object' && body.error && typeof body.error === 'object' ? body.error : null
  var code = (nested && nested.code) || error.code
  if (status === 423 || code === 'MISSING_PASSPHRASE' || code === 'VAULT_NOT_READY') {
    return { kind: 'locked', title: 'Vault is locked', description: 'Unlock Hermes Vault through its normal local workflow, then refresh this page.' }
  }
  if (code === 'PROTOCOL_MISMATCH') {
    return { kind: 'version', title: 'Vault bridge version mismatch', description: 'The installed bridge does not satisfy this Desktop plugin contract.' }
  }
  if (status === 503 || code === 'BINARY_MISSING' || code === 'BRIDGE_UNAVAILABLE') {
    return { kind: 'unavailable', title: 'Vault bridge unavailable', description: 'The read-only hermes-vault bridge is not available to the Hermes backend.' }
  }
  return { kind: 'generic', title: 'Vault metadata unavailable', description: 'The read-only Vault bridge returned an unexpected failure.' }
}

// -- service icons (codicon map, fallback monogram) ---------------------------
var SERVICE_ICON = {
  github: 'github',
  google: 'globe',
  openai: 'sparkle',
  anthropic: 'claude',
  claude: 'claude',
  x: 'x',
  twitter: 'x',
  stripe: 'credit-card',
  aws: 'cloud',
  cloudflare: 'cloud',
  docker: 'vm',
  postgres: 'database',
  mysql: 'database',
  sqlite: 'database',
  database: 'database',
  slack: 'comment-discussion',
  oauth: 'key'
}

function ServiceIcon(_a) {
  var service = _a.service
  if (!service) return null
  var normalized = String(service).toLowerCase().trim()
  var codicon = SERVICE_ICON[normalized]
  if (codicon) {
    return jsx(Codicon, { name: codicon, size: '1rem' })
  }
  var monogram = normalized.substring(0, 2).toUpperCase()
  return jsx('span', {
    className: 'inline-flex items-center justify-center rounded text-[0.625rem] font-semibold leading-none w-5 h-5 bg-(--ui-bg-tertiary) text-(--ui-text-tertiary)',
    children: monogram
  })
}

// -- status derivation (client-side, per visual spec §6) ----------------------
function deriveStatus(record, now) {
  var nowMs = now || Date.now()
  var status = (record && record.status) || ''
  var expiry = record && record.expiry
  var lastVerified = record && record.last_verified_at
  var updatedAt = record && record.updated_at
  var DAY_MS = 86400000

  if (status === 'expired' || (expiry && new Date(expiry).getTime() < nowMs)) {
    return { badge: 'Expired', badgeVariant: 'destructive', statusDot: 'bad', label: 'expired' }
  }
  if (status === 'invalid') {
    return { badge: 'Invalid', badgeVariant: 'destructive', statusDot: 'bad', label: 'invalid' }
  }
  if (lastVerified) {
    var verifiedAge = nowMs - new Date(lastVerified).getTime()
    if (verifiedAge > UNVERIFIED_DAYS * DAY_MS) {
      return { badge: 'Unverified', badgeVariant: 'warn', statusDot: 'warn', label: 'unverified' }
    }
  } else {
    return { badge: 'Unverified', badgeVariant: 'warn', statusDot: 'warn', label: 'unverified' }
  }
  if (expiry) {
    var expiryMs = new Date(expiry).getTime()
    var until = expiryMs - nowMs
    if (until <= EXPIRY_WARN_DAYS * DAY_MS && until > 0) {
      var days = Math.ceil(until / DAY_MS)
      return { badge: 'Expiring in ' + days + 'd', badgeVariant: 'warn', statusDot: 'warn', label: 'expiring' }
    }
  }
  if (updatedAt) {
    var updatedAge = nowMs - new Date(updatedAt).getTime()
    if (updatedAge > STALE_DAYS * DAY_MS && lastVerified) {
      var verifiedAge2 = nowMs - new Date(lastVerified).getTime()
      if (verifiedAge2 > UNVERIFIED_DAYS * DAY_MS) {
        return { badge: 'Stale', badgeVariant: 'warn', statusDot: 'warn', label: 'stale' }
      }
    }
  }
  return { badge: 'Active', badgeVariant: 'muted', statusDot: 'good', label: 'active' }
}

function relativeTime(isoString, now) {
  if (!isoString) return 'never'
  var nowMs = now || Date.now()
  var then = new Date(isoString).getTime()
  if (isNaN(then)) return 'never'
  var diff = nowMs - then
  var seconds = Math.floor(diff / 1000)
  if (seconds < 60) return 'just now'
  var minutes = Math.floor(seconds / 60)
  if (minutes < 60) return minutes + 'm ago'
  var hours = Math.floor(minutes / 60)
  if (hours < 24) return hours + 'h ago'
  var days = Math.floor(hours / 24)
  if (days < 30) return days + 'd ago'
  var months = Math.floor(days / 30)
  return months + 'mo ago'
}

function shortDate(isoString) {
  if (!isoString) return '—'
  var d = new Date(isoString)
  if (isNaN(d.getTime())) return '—'
  return d.toISOString().slice(0, 10)
}

// -- shared components --------------------------------------------------------
function StateCard(_a) {
  var details = _a.details
  var onRefresh = _a.onRefresh
  return jsxs('div', {
    className: 'mx-auto grid w-full max-w-3xl gap-4 px-6 py-10',
    children: [
      jsx(ErrorState, {
        title: details.title,
        description: details.description,
        className: 'rounded-xl border border-(--ui-stroke-secondary) p-8'
      }),
      jsx(Button, {
        className: 'justify-self-center',
        onClick: onRefresh,
        size: 'sm',
        variant: 'outline',
        children: jsxs('span', { className: 'inline-flex items-center gap-2', children: [jsx(Codicon, { name: 'refresh', size: '0.8rem' }), 'Refresh'] })
      })
    ]
  })
}

function LoadingState() {
  return jsx('div', {
    className: 'mx-auto grid w-full max-w-3xl gap-3 px-6 py-10',
    children: [
      jsx('div', { className: 'h-7 w-56 animate-pulse rounded bg-(--ui-control-background)' }),
      jsx('div', { className: 'h-4 w-96 max-w-full animate-pulse rounded bg-(--ui-control-background)' }),
      jsx('div', { className: 'mt-4 grid grid-cols-2 gap-3 md:grid-cols-4', children: [1, 2, 3, 4].map(function (i) { return jsx('div', { className: 'h-24 animate-pulse rounded-xl border border-(--ui-stroke-secondary) bg-(--ui-control-background)', key: i }) }) })
    ]
  })
}

function InlineLoading() {
  return jsx('div', {
    className: 'grid gap-2',
    'aria-busy': 'true',
    children: [1, 2, 3, 4, 5, 6].map(function (i) {
      return jsx(Skeleton, { className: 'h-12 rounded-lg', key: 'skel-' + i })
    })
  })
}

// -- page header with health strip --------------------------------------------
function PageHeader(_a) {
  var profile = _a.profile
  var profileOptions = _a.profileOptions
  var onProfileChange = _a.onProfileChange
  var onRefresh = _a.onRefresh
  var refreshing = _a.refreshing
  var health = _a.health

  return jsxs('header', {
    className: 'sticky top-0 z-10 border-b border-(--ui-stroke-secondary) bg-(--ui-background) px-6 py-4',
    children: [
      jsxs('div', { className: 'mx-auto flex w-full max-w-5xl flex-wrap items-center justify-between gap-4', children: [
        jsxs('div', { className: 'grid gap-1', children: [
          jsx('h1', { className: 'text-lg font-semibold tracking-tight', children: 'Hermes Vault' }),
          jsx('p', { className: 'text-xs text-(--ui-text-tertiary)', children: 'Read-only credential, lease, policy, and audit metadata' })
        ] }),
        jsxs('div', { className: 'flex flex-wrap items-center gap-2', children: [
          jsx(Select, { onValueChange: onProfileChange, value: profile, children: [
            jsx(SelectTrigger, { 'aria-label': 'Vault profile', className: 'w-36', children: jsx(SelectValue, {}) }),
            jsx(SelectContent, { children: profileOptions.map(function (o) { return jsx(SelectItem, { value: o, children: o, key: o }) }) })
          ] }),
          jsx(Button, { 'aria-label': 'Refresh Vault metadata', disabled: refreshing, onClick: onRefresh, size: 'icon-xs', variant: 'ghost', children: jsx(Codicon, { name: 'refresh', size: '0.8rem' }) })
        ] })
      ] }),
      health ? jsx('div', { className: 'mx-auto mt-3 grid w-full max-w-5xl gap-3 grid-cols-stat', children: [
        jsx(HealthStat, { label: 'Credentials', value: safeCount(health.credential_count) }),
        jsx(HealthStat, { label: 'Needs attention', value: safeCount(health.needsAttention), tone: health.needsAttention > 0 ? 'destructive' : 'muted' }),
        jsx(HealthStat, { label: 'Leases', value: safeCount(health.activeLeaseCount) + ' of ' + safeCount(health.leaseCount) + ' active' }),
        jsx(HealthStat, { label: 'Integrity', value: health.integrityOk ? '✓ Healthy' : '✗ Check', tone: health.integrityOk ? 'good' : 'bad' })
      ] }) : null
    ]
  })
}

function HealthStat(_a) {
  var label = _a.label
  var value = _a.value
  var tone = _a.tone
  var toneClass
  if (tone === 'destructive') toneClass = 'text-destructive'
  else if (tone === 'bad') toneClass = 'text-destructive'
  else if (tone === 'good') toneClass = 'text-(--ui-accent)'
  else toneClass = 'text-(--ui-text-primary)'
  return jsxs('div', {
    className: 'grid gap-0.5 rounded-lg border border-(--ui-stroke-secondary) px-3 py-2',
    children: [
      jsx('div', { className: 'text-[0.625rem] text-(--ui-text-tertiary)', children: label }),
      jsx('div', { className: 'text-sm font-semibold tabular-nums ' + toneClass, children: value })
    ]
  })
}

// -- mutation helpers ---------------------------------------------------------
function mutationErrorDetails(error) {
  if (!error || typeof error !== 'object') {
    return { family: 'unknown', title: 'Mutation failed', description: 'An unexpected error occurred.' }
  }
  var status = error.status || error.statusCode || (error.response && error.response.status)
  var body = error.body || error.data || (error.response && error.response.data)
  if (status === 504) {
    return { family: 'timeout', title: 'Request timed out', description: 'The request timed out — no change was written. You can retry.' }
  }
  if (status === 409) {
    return { family: 'audit-seal-failed', title: 'Write succeeded but audit seal failed', description: 'The credential was written but the audit integrity seal could not be appended. The change is recorded; integrity will re-sync on the next checkpoint.' }
  }
  if (status === 403) {
    return { family: 'rejected-before-write', title: 'Request rejected', description: (body && body.detail) || 'The request was denied before any write occurred.' }
  }
  if (status && status >= 400 && status < 500) {
    return { family: 'rejected-before-write', title: 'Request rejected', description: (body && body.detail) || 'The request was rejected.' }
  }
  if (status && status >= 500) {
    return { family: 'write-failed', title: 'Write failed', description: 'The server could not complete the write. No change was persisted.' }
  }
  return { family: 'unknown', title: 'Mutation failed', description: 'An unexpected error occurred.' }
}

// -- dialogs ------------------------------------------------------------------

// Add credential dialog (spec §8.1)
function AddCredentialDialog(_a) {
  var onClose = _a.onClose
  var mutationsEnabled = _a.mutationsEnabled
  var mutateCall = _a.mutateCall
  var onSuccess = _a.onSuccess

  var _b = useState(''), service = _b[0], setService = _b[1]
  var _c = useState(''), alias = _c[0], setAlias = _c[1]
  var _d = useState('api_key'), credType = _d[0], setCredType = _d[1]
  var _e = useState(''), secret = _e[0], setSecret = _e[1]
  var _f = useState(''), tags = _f[0], setTags = _f[1]
  var _g = useState(''), notes = _g[0], setNotes = _g[1]
  var _h = useState('idle'), phase = _h[0], setPhase = _h[1]  // idle | confirming | busy
  var _i = useState(null), mutationError = _i[0], setMutationError = _i[1]

  var normalizedService = String(service).toLowerCase().trim().replace(/\s+/g, '_')
  var queryClient = useQueryClient()

  var resetForm = function () {
    setService(''); setAlias(''); setCredType('api_key'); setSecret(''); setTags(''); setNotes('')
    setPhase('idle'); setMutationError(null)
  }
  var doClose = function () { resetForm(); onClose() }

  var handleSubmit = function () {
    var parsedTags = tags ? tags.split(',').map(function (t) { return t.trim() }).filter(Boolean) : undefined
    var body = { service: normalizedService, credential_type: credType, secret: secret }
    if (alias) body.alias = alias
    if (parsedTags && parsedTags.length > 0) body.tags = parsedTags
    if (notes) body.notes = notes
    setPhase('confirming')
  }

  var handleConfirm = function () {
    setPhase('busy')
    setMutationError(null)
    var parsedTags = tags ? tags.split(',').map(function (t) { return t.trim() }).filter(Boolean) : undefined
    var body = { service: normalizedService, credential_type: credType, secret: secret }
    if (alias) body.alias = alias
    if (parsedTags && parsedTags.length > 0) body.tags = parsedTags
    if (notes) body.notes = notes
    mutateCall('/mutations/add', body)
      .then(function () {
        host.notify({ kind: 'success', message: 'Added ' + normalizedService + (alias ? '/' + alias : '') + ' — audit entry written.' })
        queryClient.invalidateQueries({ queryKey: QUERY_ROOT })
        if (onSuccess) onSuccess()
        resetForm()
        onClose()
      })
      .catch(function (err) {
        setMutationError(err)
        setPhase('idle')
      })
  }

  if (!mutationsEnabled) {
    return jsx(ConfirmDialog, {
      open: true,
      onClose: doClose,
      onConfirm: doClose,
      title: 'Mutations unavailable',
      description: 'The Vault bridge does not support mutations. The installed adapter must be run with --allow-mutations.',
      confirmLabel: 'OK',
      destructive: false
    })
  }

  if (phase === 'confirming') {
    return jsx(ConfirmDialog, {
      open: true,
      onClose: function () { setPhase('idle') },
      onConfirm: handleConfirm,
      title: 'Add credential: ' + normalizedService + (alias ? ' / ' + alias : ''),
      description: 'This will store an encrypted credential in the vault. The secret value will never be rendered by this plugin.',
      confirmLabel: 'Add credential',
      busyLabel: 'Working\u2026',
      doneLabel: 'Done',
      destructive: false
    })
  }

  return jsx(Dialog, { open: true, onOpenChange: function (open) { if (!open) doClose() }, children: [
    jsx(DialogContent, { className: 'max-w-md', children: [
      jsx(DialogHeader, { children: [
        jsx(DialogTitle, { children: 'Add credential' }),
        jsx(DialogDescription, { children: 'Store a new credential in this profile\'s vault.' })
      ] }),
      jsxs('div', { className: 'grid gap-4 py-4', children: [
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'Service' }),
          jsx(Input, { value: service, onChange: function (e) { setService(e.target.value) }, placeholder: 'e.g. openai, github', autoFocus: true }),
          service ? jsx('span', { className: 'text-[0.6875rem] text-(--ui-text-quaternary)', children: 'Stored as ' + safeText(normalizedService) }) : null
        ] }),
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'Alias' }),
          jsx(Input, { value: alias, onChange: function (e) { setAlias(e.target.value) }, placeholder: 'e.g. primary, staging' })
        ] }),
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'Credential type' }),
          jsx(Select, { value: credType, onValueChange: setCredType, children: [
            jsx(SelectTrigger, { children: jsx(SelectValue, {}) }),
            jsx(SelectContent, { children: [
              jsx(SelectItem, { value: 'api_key', children: 'API Key' }),
              jsx(SelectItem, { value: 'oauth_access_token', children: 'OAuth Access Token' }),
              jsx(SelectItem, { value: 'oauth_refresh_token', children: 'OAuth Refresh Token' }),
              jsx(SelectItem, { value: 'password', children: 'Password' }),
              jsx(SelectItem, { value: 'certificate', children: 'Certificate' }),
              jsx(SelectItem, { value: 'other', children: 'Other' })
            ] })
          ] })
        ] }),
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'Secret' }),
          jsx(Input, { type: 'password', value: secret, onChange: function (e) { setSecret(e.target.value) }, placeholder: 'Paste the credential value' })
        ] }),
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'Tags' }),
          jsx(Input, { value: tags, onChange: function (e) { setTags(e.target.value) }, placeholder: 'optional, comma-separated' })
        ] }),
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'Notes' }),
          jsx(Input, { value: notes, onChange: function (e) { setNotes(e.target.value) }, placeholder: 'optional — do not put secrets here' }),
          jsx('span', { className: 'text-[0.625rem] text-(--ui-text-quaternary)', children: 'Notes are stored as metadata only. Never store secret values here.' })
        ] }),
        mutationError ? jsx(ErrorState, { title: mutationErrorDetails(mutationError).title, description: mutationErrorDetails(mutationError).description, children: jsx(Button, { size: 'sm', variant: 'outline', onClick: function () { setMutationError(null) }, children: 'Dismiss' }) }) : null
      ] }),
      jsx(DialogFooter, { children: [
        jsx(Button, { onClick: doClose, variant: 'ghost', size: 'sm', children: 'Cancel' }),
        jsx(Button, { onClick: handleSubmit, disabled: !service || !secret || phase === 'busy', size: 'sm', children: phase === 'busy' ? 'Working\u2026' : 'Add credential' })
      ] })
    ] })
  ] })
}

// Rotate credential dialog (spec §8.2)
function RotateCredentialDialog(_a) {
  var target = _a.target
  var onClose = _a.onClose
  var mutationsEnabled = _a.mutationsEnabled
  var mutateCall = _a.mutateCall
  var onSuccess = _a.onSuccess

  var _b = useState(''), newSecret = _b[0], setNewSecret = _b[1]
  var _c = useState('idle'), phase = _c[0], setPhase = _c[1]  // idle | busy
  var _d = useState(null), mutationError = _d[0], setMutationError = _d[1]
  var queryClient = useQueryClient()

  var service = target ? target.service : ''
  var alias = target ? target.alias : ''
  var label = service + (alias ? ' / ' + alias : '')
  var typeStr = target ? String(target.credential_type || 'api_key') : ''

  var resetForm = function () {
    setNewSecret('')
    setPhase('idle')
    setMutationError(null)
  }
  var doClose = function () { resetForm(); onClose() }

  var handleRotate = function () {
    setPhase('busy')
    setMutationError(null)
    var body = { service_or_id: service, new_secret: newSecret }
    if (alias) body.alias = alias
    mutateCall('/mutations/rotate', body)
      .then(function () {
        host.notify({ kind: 'success', message: 'Rotated ' + label + ' — audit entry written.' })
        queryClient.invalidateQueries({ queryKey: QUERY_ROOT })
        if (onSuccess) onSuccess()
        resetForm()
        onClose()
      })
      .catch(function (err) {
        setMutationError(err)
        setPhase('idle')
      })
  }

  if (!target) return null

  if (!mutationsEnabled) {
    return jsx(ConfirmDialog, {
      open: true,
      onClose: doClose,
      onConfirm: doClose,
      title: 'Mutations unavailable',
      description: 'The Vault bridge does not support mutations. The installed adapter must be run with --allow-mutations.',
      confirmLabel: 'OK',
      destructive: false
    })
  }

  return jsx(Dialog, { open: true, onOpenChange: function (open) { if (!open) doClose() }, children: [
    jsx(DialogContent, { className: 'max-w-md', children: [
      jsx(DialogHeader, { children: [
        jsx(DialogTitle, { children: 'Rotate credential' }),
        jsx(DialogDescription, { children: jsxs('span', { className: 'flex items-center gap-1.5', children: [jsx(ServiceIcon, { service: service }), jsxs('span', { children: [label, jsx('span', { className: 'text-(--ui-text-quaternary)', children: ' \u00b7 ' + typeStr })] })] }) })
      ] }),
      jsxs('div', { className: 'grid gap-4 py-4', children: [
        target.last_verified_at ? jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: 'Last verified: ' + relativeTime(target.last_verified_at) + (target.expiry ? ' \u00b7 Expiry: ' + shortDate(target.expiry) : '') }) : null,
        jsxs('div', { className: 'grid gap-1.5', children: [
          jsx('label', { className: 'text-xs font-medium', children: 'New secret' }),
          jsx(Input, { type: 'password', value: newSecret, onChange: function (e) { setNewSecret(e.target.value) }, placeholder: 'Paste the new credential value', autoFocus: true })
        ] }),
        mutationError ? jsx(ErrorState, { title: mutationErrorDetails(mutationError).title, description: mutationErrorDetails(mutationError).description, children: jsx(Button, { size: 'sm', variant: 'outline', onClick: function () { setMutationError(null) }, children: 'Dismiss' }) }) : null
      ] }),
      jsx(DialogFooter, { children: [
        jsx(Button, { onClick: doClose, variant: 'ghost', size: 'sm', children: 'Cancel' }),
        jsx(Button, { onClick: handleRotate, disabled: !newSecret || phase === 'busy', size: 'sm', children: phase === 'busy' ? 'Working\u2026' : 'Rotate' })
      ] })
    ] })
  ] })
}

// Delete credential dialog — 3-step high-friction flow (spec §8.3)
function DeleteCredentialDialog(_a) {
  var target = _a.target
  var onClose = _a.onClose
  var mutationsEnabled = _a.mutationsEnabled
  var mutateCall = _a.mutateCall
  var onSuccess = _a.onSuccess
  var credentialsQ = _a.credentialsQ
  var leasesQ = _a.leasesQ

  var _b = useState('impact'), step = _b[0], setStep = _b[1]  // impact | typeConfirm | finalConfirm | busy
  var _c = useState(''), confirmText = _c[0], setConfirmText = _c[1]
  var _d = useState(false), acknowledged = _d[0], setAcknowledged = _d[1]
  var _e = useState(null), mutationError = _e[0], setMutationError = _e[1]
  var queryClient = useQueryClient()
  // Type-to-confirm input ref + focus. MUST be hoisted above the step early
  // returns below: hooks may not appear after a conditional return (React
  // #310, "Rendered more hooks than during the previous render"). The dialog
  // transitions impact -> typeConfirm within one mount, so a hook count jump
  // here would crash the real desktop exactly like the VaultPage defect fixed
  // in t_cae27701. The effect runs on every render; the inputRef.current guard
  // keeps the focus call a no-op until the confirm input is actually mounted.
  var inputRef = useRef(null)
  // No deps array: the effect must fire after EVERY render so the input
  // auto-focuses each time the dialog lands on the typeConfirm step (pre-fix
  // behavior — the hooks mounted fresh on every typeConfirm entry because they
  // sat behind the impact early return). The inputRef.current guard keeps it a
  // no-op on every other step and on the very first mount (input not mounted).
  useEffect(function () {
    if (inputRef.current) inputRef.current.focus()
  })

  var service = target ? target.service : ''
  var alias = target ? target.alias : ''
  var label = service + (alias ? ' / ' + alias : '')
  // The bridge's deny-by-default contract (security-arch §3.3/I2) accepts ONLY
  // the exact credential id or "service:alias" as confirmation. Deriving the
  // token from the record keeps the type-to-confirm value identical to what
  // the API will accept (a bare alias or id prefix would 403 every time).
  var requiredConfirm = alias ? (service + ':' + alias) : String(target ? target.id : '')
  var typeStr = target ? String(target.credential_type || 'api_key') : ''

  // compute impact from leases
  var impactCount = 0
  var leases = leasesQ.data && leasesQ.data.leases || []
  if (target && target.id) {
    leases.forEach(function (l) {
      if (l.credential_id === target.id && l.status === 'active') impactCount++
    })
  }

  var resetForm = function () {
    setStep('impact')
    setConfirmText('')
    setAcknowledged(false)
    setMutationError(null)
  }
  var doClose = function () { resetForm(); onClose() }

  var doDelete = function () {
    setStep('busy')
    setMutationError(null)
    var body = { service_or_id: service, confirmation: requiredConfirm }
    if (alias) body.alias = alias
    mutateCall('/mutations/delete', body)
      .then(function () {
        host.notify({ kind: 'info', message: 'Deleted ' + label + ' — audit entry written.' })
        queryClient.invalidateQueries({ queryKey: QUERY_ROOT })
        if (onSuccess) onSuccess()
        resetForm()
        onClose()
      })
      .catch(function (err) {
        setMutationError(err)
        setStep('finalConfirm')
      })
  }

  if (!target) return null

  if (!mutationsEnabled) {
    return jsx(ConfirmDialog, {
      open: true,
      onClose: doClose,
      onConfirm: doClose,
      title: 'Mutations unavailable',
      description: 'The Vault bridge does not support mutations. The installed adapter must be run with --allow-mutations.',
      confirmLabel: 'OK',
      destructive: false
    })
  }

  // Step 1: Impact summary
  if (step === 'impact') {
    return jsx(Dialog, { open: true, onOpenChange: function (open) { if (!open) doClose() }, children: [
      jsx(DialogContent, { className: 'max-w-md', children: [
        jsx(DialogHeader, { children: [
          jsx(DialogTitle, { children: 'Delete credential' }),
          jsx(DialogDescription, { children: jsxs('span', { className: 'flex items-center gap-1.5', children: [jsx(ServiceIcon, { service: service }), jsxs('span', { children: [label, jsx('span', { className: 'text-(--ui-text-quaternary)', children: ' \u00b7 ' + typeStr })] })] }) })
        ] }),
        jsxs('div', { className: 'grid gap-4 py-4', children: [
          jsxs('div', { className: 'rounded-lg border border-(--ui-stroke-secondary) p-3', children: [
            impactCount > 0 ? jsxs('p', { className: 'text-sm', children: [jsx('strong', { children: String(impactCount) + ' active lease' + (impactCount > 1 ? 's' : '') }), ' issued to agents will stop working after deletion.'] }) : jsx('p', { className: 'text-sm', children: 'No active leases reference this credential.' })
          ] }),
          jsx('p', { className: 'text-xs text-(--ui-text-quaternary)', children: 'Consider creating a backup before proceeding. Deletion is permanent.' })
        ] }),
        jsx(DialogFooter, { children: [
          jsx(Button, { onClick: doClose, variant: 'ghost', size: 'sm', children: 'Cancel' }),
          jsx(Button, { onClick: function () { setStep('typeConfirm') }, size: 'sm', children: 'Continue to confirmation' })
        ] })
      ] })
    ] })
  }

  // Step 2: Type-to-confirm
  if (step === 'typeConfirm') {
    return jsx(Dialog, { open: true, onOpenChange: function (open) { if (!open) doClose() }, children: [
      jsx(DialogContent, { className: 'max-w-md', children: [
        jsx(DialogHeader, { children: [
          jsx(DialogTitle, { children: 'Confirm deletion' }),
          jsx(DialogDescription, { children: 'Type the credential ' + (alias ? 'alias' : 'ID prefix') + ' to confirm.' })
        ] }),
        jsxs('div', { className: 'grid gap-4 py-4', children: [
          jsx('label', { className: 'text-sm', children: 'Type \u201c' + requiredConfirm + '\u201d to confirm', htmlFor: 'confirm-delete-input' }),
          jsx(Input, { id: 'confirm-delete-input', ref: inputRef, value: confirmText, onChange: function (e) { setConfirmText(e.target.value) }, placeholder: requiredConfirm }),
          impactCount > 0 ? jsx('p', { className: 'text-xs text-(--ui-text-quaternary)', children: String(impactCount) + ' active lease' + (impactCount > 1 ? 's' : '') + ' will stop working.' }) : null
        ] }),
        jsx(DialogFooter, { children: [
          jsx(Button, { onClick: function () { setStep('impact') }, variant: 'ghost', size: 'sm', children: 'Back' }),
          jsx(Button, { onClick: function () { setStep('finalConfirm') }, disabled: confirmText !== requiredConfirm, size: 'sm', children: 'Continue' })
        ] })
      ] })
    ] })
  }

  // Step 3: Final destructive confirm
  if (step === 'finalConfirm') {
    return jsx(Dialog, { open: true, onOpenChange: function (open) { if (!open) doClose() }, children: [
      jsx(DialogContent, { className: 'max-w-md', children: [
        jsx(DialogHeader, { children: [
          jsx(DialogTitle, { className: 'text-destructive', children: 'Delete ' + label + '?' }),
          jsx(DialogDescription, { children: 'This permanently removes the credential.' })
        ] }),
        jsxs('div', { className: 'grid gap-4 py-4', children: [
          jsxs('div', { className: 'rounded-lg border border-(--ui-stroke-secondary) p-3', children: [
            jsx('p', { className: 'text-xs text-(--ui-text-tertiary)', children: 'A backup may restore it later. Consider running `hermes-vault backup` first.' }),
            jsx('p', { className: 'mt-2 text-xs text-(--ui-text-quaternary)', children: label + ' \u00b7 ' + typeStr })
          ] }),
          jsxs('div', { className: 'flex items-center gap-2', children: [
            jsx('label', { className: 'text-sm', children: jsx(Checkbox, { checked: acknowledged, onCheckedChange: setAcknowledged, children: 'I understand that deletion is permanent' }) })
          ] }),
          mutationError ? jsx(ErrorState, { title: mutationErrorDetails(mutationError).title, description: mutationErrorDetails(mutationError).description, children: jsx(Button, { size: 'sm', variant: 'outline', onClick: function () { setMutationError(null) }, children: 'Dismiss' }) }) : null
        ] }),
        jsx(DialogFooter, { children: [
          jsx(Button, { onClick: function () { setStep('typeConfirm') }, variant: 'ghost', size: 'sm', children: 'Back' }),
          jsx(Button, { onClick: doDelete, disabled: !acknowledged || step === 'busy', size: 'sm', variant: 'destructive', children: step === 'busy' ? 'Working\u2026' : 'Delete credential' })
        ] })
      ] })
    ] })
  }

  return null
}

// -- credential inventory table + toolbar -------------------------------------

var FILTER_BUCKETS = [
  { id: 'all', label: 'All' },
  { id: 'attention', label: 'Needs attn' },
  { id: 'active', label: 'Active' },
  { id: 'expired', label: 'Expired' }
]

function CredentialRow(_a) {
  var record = _a.record
  var onRotate = _a.onRotate
  var onDelete = _a.onDelete
  var _b = useState(false), expanded = _b[0], setExpanded = _b[1]

  var now = Date.now()
  var statusInfo = deriveStatus(record, now)
  var typeStr = String(record.credential_type || 'api_key')
  var verifiedText = record.last_verified_at ? relativeTime(record.last_verified_at, now) : 'never'
  var expiryText = record.expiry ? shortDate(record.expiry) : '—'

  var expirySoon = false
  var expiryPast = false
  if (record.expiry) {
    var expiryMs = new Date(record.expiry).getTime()
    var until = expiryMs - now
    if (until <= 0) expiryPast = true
    else if (until <= EXPIRY_WARN_DAYS * 86400000) expirySoon = true
  }

  var verifiedClass = verifiedText === 'never' ? 'text-(--ui-text-quaternary)' : ''
  var expiryClass = expiryPast ? 'text-destructive' : expirySoon ? 'text-(--ui-text-quaternary)' : ''
  var rowBg = statusInfo.label === 'expired' || statusInfo.label === 'invalid' ? 'bg-(--ui-bg-tertiary)' : ''

  return jsxs('div', {
    className: 'grid gap-2 rounded-lg border border-(--ui-stroke-secondary) px-3 py-2.5 text-xs ' + rowBg,
    children: [
      jsxs('div', {
        className: 'grid grid-cols-cred-row gap-row items-center',
        children: [
          jsx(StatusDot, { tone: statusInfo.statusDot, className: 'shrink-0' }),
          jsxs('span', {
            className: 'min-w-0',
            children: [
              jsxs('span', { className: 'flex items-center gap-1.5', children: [
                jsx(ServiceIcon, { service: record.service }),
                jsx('span', { className: 'font-medium truncate', children: safeText(record.service, 'unknown') })
              ] }),
              jsx('span', { className: 'block text-(--ui-text-tertiary) truncate', children: safeText(record.alias || record.name, '') })
            ]
          }),
          jsx('span', { className: 'justify-self-center', children: jsx(Badge, { variant: 'muted', children: typeStr.length > 24 ? typeStr.slice(0, 24) + '…' : typeStr }) }),
          jsx('span', { className: 'tabular-nums text-(--ui-text-tertiary) ' + verifiedClass, children: verifiedText }),
          jsx('span', { className: 'tabular-nums text-(--ui-text-quaternary) ' + expiryClass, children: expiryText }),
          jsx(DropdownMenu, { children: [
            jsx(DropdownMenuTrigger, { children: jsx(Button, { 'aria-label': 'Actions for ' + safeText(record.service, 'credential'), size: 'icon-xs', variant: 'ghost', children: jsx(Codicon, { name: 'chevron-down', size: '0.8rem' }) }) }),
            jsx(DropdownMenuContent, { align: 'end', children: [
              jsx('div', { className: 'px-2 py-1.5 text-(--ui-text-quaternary) text-[0.6875rem]', children: safeText(record.service, 'credential') + ' / ' + safeText(record.alias || record.name, '') }),
              jsx(DropdownMenuSeparator, {}),
              jsx(DropdownMenuItem, { onClick: function () { onRotate(record) }, children: jsxs('span', { className: 'inline-flex items-center gap-2', children: [jsx(Codicon, { name: 'sync', size: '0.8rem' }), 'Rotate'] }) }),
              jsx(DropdownMenuItem, { onClick: function () { onDelete(record) }, children: jsxs('span', { className: 'inline-flex items-center gap-2 text-destructive', children: [jsx(Codicon, { name: 'trash', size: '0.8rem' }), 'Delete'] }) })
            ] })
          ] })
        ]
      }),
      expanded ? jsxs('div', {
        className: 'grid gap-1.5 pl-6 pt-1 pb-1 border-t border-(--ui-stroke-secondary) mt-1',
        children: [
          record.tags && Array.isArray(record.tags) && record.tags.length > 0 ? jsx('div', { className: 'flex flex-wrap gap-1', children: record.tags.map(function (t) { return jsx(Badge, { variant: 'outline', children: String(t), key: 'tag-' + t }) }) }) : null,
          jsxs('div', { className: 'flex flex-wrap gap-x-4 gap-y-1 text-(--ui-text-quaternary)', children: [
            record.scopes ? jsx('span', { children: 'Scopes: ' + safeText(record.scopes, '—') }) : null,
            record.created_at ? jsx('span', { children: 'Created: ' + shortDate(record.created_at) }) : null,
            record.updated_at ? jsx('span', { children: 'Updated: ' + shortDate(record.updated_at) }) : null,
            typeof record.has_notes === 'boolean' ? jsx('span', { children: record.has_notes ? 'Notes present' : 'No notes' }) : null
          ] }),
          record.id ? jsx('span', { className: 'text-(--ui-text-quaternary) text-[0.625rem] font-mono', children: 'ID ' + String(record.id).slice(0, 8) + '…' }) : null
        ]
      }) : null,
      jsx(Button, {
        'aria-label': expanded ? 'Collapse details' : 'Expand details',
        className: 'justify-self-start',
        onClick: function () { setExpanded(!expanded) },
        size: 'icon-xs',
        variant: 'ghost',
        children: jsx(Codicon, { name: expanded ? 'chevron-up' : 'chevron-down', size: '0.6rem' })
      })
    ]
  })
}

function CredentialsTab(_a) {
  var credentialsQ = _a.credentialsQ
  var statusFilter = _a.statusFilter
  var searchQuery = _a.searchQuery
  var onSearchChange = _a.onSearchChange
  var onFilterChange = _a.onFilterChange
  var mutationsEnabled = _a.mutationsEnabled
  var onRotate = _a.onRotate
  var onDelete = _a.onDelete
  var onAdd = _a.onAdd

  var credentials = credentialsQ.data && credentialsQ.data.credentials || []
  var isLoading = credentialsQ.isLoading
  var isError = credentialsQ.error

  var filtered = useMemo(function () {
    var rows = credentials.slice()
    // filter
    if (statusFilter !== 'all') {
      var now = Date.now()
      rows = rows.filter(function (c) {
        var s = deriveStatus(c, now)
        if (statusFilter === 'attention') return s.label !== 'active'
        if (statusFilter === 'active') return s.label === 'active'
        if (statusFilter === 'expired') return s.label === 'expired' || s.label === 'invalid'
        return true
      })
    }
    if (searchQuery) {
      var q = searchQuery.toLowerCase()
      rows = rows.filter(function (c) {
        return (c.service && c.service.toLowerCase().indexOf(q) !== -1) || (c.alias && c.alias.toLowerCase().indexOf(q) !== -1)
      })
    }
    // stale-first ordering: needs-attention first, then oldest verified first, then service asc
    rows.sort(function (a, b) {
      var sa = deriveStatus(a, null)
      var sb = deriveStatus(b, null)
      if (sa.label !== sb.label) {
        if (sa.label !== 'active') return -1
        if (sb.label !== 'active') return 1
      }
      var va = a.last_verified_at ? new Date(a.last_verified_at).getTime() : 0
      var vb = b.last_verified_at ? new Date(b.last_verified_at).getTime() : 0
      if (va !== vb) return va - vb
      var na = (a.service || '').toLowerCase()
      var nb = (b.service || '').toLowerCase()
      return na < nb ? -1 : na > nb ? 1 : 0
    })
    return rows
  }, [credentials, statusFilter, searchQuery])

  if (isLoading) return jsx(InlineLoading, {})
  if (isError) {
    return jsx(ErrorState, {
      title: 'Credential metadata unavailable',
      description: 'The Vault bridge did not return credential metadata.',
      children: jsx(Button, { onClick: function () { credentialsQ.refetch() }, size: 'sm', variant: 'outline', children: 'Retry' })
    })
  }

  return jsxs('div', { className: 'grid gap-3', children: [
    jsxs('div', { className: 'flex flex-wrap items-center gap-3', children: [
      jsx(SearchField, { value: searchQuery, onChange: onSearchChange, placeholder: 'Search service or alias…', className: 'flex-1 min-w-0' }),
      jsx(SegmentedControl, { value: statusFilter, onChange: onFilterChange, options: FILTER_BUCKETS }),
      mutationsEnabled ? jsx(Button, { onClick: onAdd, size: 'sm', children: jsxs('span', { className: 'inline-flex items-center gap-1.5', children: [jsx(Codicon, { name: 'plus', size: '0.8rem' }), 'Add'] }) }) : null
    ] }),
    filtered.length > 0
      ? jsx('div', { className: 'grid gap-2', children: filtered.map(function (record, i) { return jsx(CredentialRow, { record: record, onRotate: onRotate, onDelete: onDelete, key: (record.id || safeText(record.service, 'cred')) + '-' + i }) }) })
      : jsx(EmptyState, { title: searchQuery || statusFilter !== 'all' ? 'No credentials match your filters' : 'No credential metadata', description: searchQuery || statusFilter !== 'all' ? 'Try adjusting your search or filter selection.' : 'This profile does not currently report credential records.' })
  ] })
}

// -- other tabs ---------------------------------------------------------------

function RequestsTab(_a) {
  var requestsQ = _a.requestsQ
  var requests = requestsQ.data
  var isLoading = requestsQ.isLoading
  var isError = requestsQ.error

  if (isLoading) return jsx(InlineLoading, {})
  if (isError) {
    return jsx(ErrorState, {
      title: 'Access request metadata unavailable',
      description: 'The read-only bridge did not return request metadata.',
      children: jsx(Button, { onClick: function () { requestsQ.refetch() }, size: 'sm', variant: 'outline', children: 'Retry' })
    })
  }

  var rows = requests && Array.isArray(requests.requests) ? requests.requests : []
  var count = requests && requests.request_count

  return jsxs('div', { className: 'grid gap-3', children: [
    jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: safeCount(count) + ' request(s)' }),
    rows.length > 0
      ? jsx('div', { className: 'grid gap-2', children: rows.map(function (req, i) {
          return jsxs('div', {
            className: 'grid gap-3 rounded-lg border border-(--ui-stroke-secondary) px-3 py-3',
            children: [
              jsxs('div', { className: 'flex flex-wrap items-center justify-between gap-2 text-xs', children: [
                jsxs('span', { className: 'grid gap-0.5', children: [
                  jsx('span', { className: 'font-medium', children: safeText(req.service, 'unknown service') }),
                  jsx('span', { className: 'text-(--ui-text-tertiary)', children: safeText(req.agent_id, 'agent unavailable') })
                ] }),
                jsx(Badge, { variant: 'muted', children: safeText(req.status || req.decision, 'pending') })
              ] }),
              jsxs('div', { className: 'flex flex-wrap gap-2', children: [
                jsx(Button, { onClick: function () { throw new Error('This read-only integration does not perform Vault mutations.') }, size: 'xs', variant: 'outline', children: 'Approve' }),
                jsx(Button, { onClick: function () { throw new Error('This read-only integration does not perform Vault mutations.') }, size: 'xs', variant: 'ghost', children: 'Deny' }),
                jsx(Button, { onClick: function () { throw new Error('This read-only integration does not perform Vault mutations.') }, size: 'xs', variant: 'ghost', children: 'Approve & issue lease' })
              ] })
            ],
            key: 'req-' + i
          })
        }) })
      : jsx(EmptyState, { title: 'No pending access requests', description: 'Requests are shown as metadata only.' })
  ] })
}

function LeasesTab(_a) {
  var leasesQ = _a.leasesQ
  var leases = leasesQ.data
  var isLoading = leasesQ.isLoading
  var isError = leasesQ.error

  if (isLoading) return jsx(InlineLoading, {})
  if (isError) {
    return jsx(ErrorState, {
      title: 'Lease metadata unavailable',
      description: 'No lease secrets or materialized values are rendered here.',
      children: jsx(Button, { onClick: function () { leasesQ.refetch() }, size: 'sm', variant: 'outline', children: 'Retry' })
    })
  }

  var rows = leases && Array.isArray(leases.leases) ? leases.leases : []
  var count = leases && leases.lease_count
  var activeCount = leases && leases.active_lease_count

  return jsxs('div', { className: 'grid gap-3', children: [
    jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: safeCount(count) + ' total, ' + safeCount(activeCount) + ' active' }),
    rows.length > 0
      ? jsx('div', { className: 'grid gap-2', children: rows.map(function (lease, i) {
          return jsxs('div', {
            className: 'flex flex-wrap items-center justify-between gap-2 rounded-lg border border-(--ui-stroke-secondary) px-3 py-2 text-xs',
            children: [
              jsxs('span', { className: 'grid gap-0.5', children: [
                jsx('span', { className: 'font-medium', children: safeText(lease.service, 'unknown service') }),
                jsx('span', { className: 'text-(--ui-text-tertiary)', children: safeText(lease.agent_id, 'agent unavailable') })
              ] }),
              jsx(Badge, { variant: lease.status === 'active' ? 'default' : 'muted', children: safeText(lease.status, 'unknown') })
            ],
            key: 'lease-' + i
          })
        }) })
      : jsx(EmptyState, { title: 'No lease metadata', description: 'This profile does not currently report leases.' })
  ] })
}

function PolicyTab(_a) {
  var policyQ = _a.policyQ
  var policy = policyQ.data
  var isLoading = policyQ.isLoading
  var isError = policyQ.error

  if (isLoading) return jsx(InlineLoading, {})
  if (isError) {
    return jsx(ErrorState, {
      title: 'Policy metadata unavailable',
      description: 'The bridge did not return policy metadata.',
      children: jsx(Button, { onClick: function () { policyQ.refetch() }, size: 'sm', variant: 'outline', children: 'Retry' })
    })
  }

  return jsxs('div', { className: 'grid gap-3', children: [
    jsxs('div', { className: 'flex flex-wrap gap-2', children: [
      jsx(Badge, { variant: policy && policy.policy_exists ? 'default' : 'warn', children: policy && policy.policy_exists ? 'policy present' : 'policy unavailable' }),
      jsx(Badge, { variant: 'muted', children: safeCount(policy && policy.agents ? Object.keys(policy.agents).length : 0) + ' agents described' }),
      jsx(Badge, { variant: 'muted', children: safeText(policy && policy.doctor && policy.doctor.status, 'doctor unavailable') })
    ] })
  ] })
}

function AuditTab(_a) {
  var integrityQ = _a.integrityQ
  var overviewData = _a.overviewData
  var integrity = integrityQ.data
  var isLoading = integrityQ.isLoading
  var recentAudit = Array.isArray(overviewData.recent_audit) ? overviewData.recent_audit.slice(0, 50) : []

  if (isLoading) return jsx(InlineLoading, {})

  return jsxs('div', { className: 'grid gap-4', children: [
    integrity ? jsxs('div', { className: 'grid gap-3', children: [
      jsx('h3', { className: 'text-sm font-semibold', children: 'Audit integrity' }),
      jsxs('div', { className: 'flex flex-wrap gap-2', children: [
        jsx(Badge, { variant: integrity.status === 'healthy' ? 'default' : 'destructive', children: safeText(integrity.status, 'unknown') }),
        jsx(Badge, { variant: 'muted', children: safeText(integrity.reason_code, 'no reason') }),
        jsx(Badge, { variant: 'muted', children: safeCount(integrity.verified_count) + ' verified' }),
        jsx(Badge, { variant: 'muted', children: safeCount(integrity.legacy_count) + ' legacy' })
      ] }),
      jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: safeText(integrity.recommended_next_step, 'No further operator action reported.') })
    ] }) : jsx(EmptyState, { title: 'Integrity metadata unavailable', description: 'The bridge did not return an integrity record.' }),
    recentAudit.length > 0 ? jsxs('div', { className: 'grid gap-3', children: [
      jsx('h3', { className: 'text-sm font-semibold', children: 'Recent audit entries (' + String(recentAudit.length) + ')' }),
      jsx('div', { className: 'grid gap-1', children: recentAudit.map(function (entry, i) {
        return jsxs('div', {
          className: 'grid grid-cols-[auto_1fr_auto] items-center gap-3 border-b border-(--ui-stroke-secondary) py-2 text-xs last:border-b-0',
          children: [
            jsx('span', { className: 'tabular-nums text-(--ui-text-quaternary)', children: safeCount(entry.sequence) }),
            jsxs('span', { className: 'min-w-0', children: [
              jsx('span', { className: 'block truncate font-medium', children: safeText(entry.action, 'audit event') }),
              jsx('span', { className: 'block truncate text-(--ui-text-tertiary)', children: safeText(entry.service, safeText(entry.agent_id, 'metadata')) })
            ] }),
            jsx(Badge, { variant: 'muted', children: safeText(entry.decision, 'recorded') })
          ],
          key: 'audit-' + i
        })
      }) })
    ] }) : jsx(EmptyState, { title: 'No recent audit metadata', description: 'The bridge returned no recent entries for this profile.' })
  ] })
}

function OperationsTab(_a) {
  var overviewQ = _a.overviewQ
  var integrityQ = _a.integrityQ
  var queryClient = useQueryClient()

  return jsxs('div', { className: 'grid gap-3', children: [
    jsx('h3', { className: 'text-sm font-semibold', children: 'Operations (read-only dry runs)' }),
    jsxs('div', { className: 'flex flex-wrap gap-2', children: [
      jsx(Button, { size: 'sm', variant: 'outline', onClick: function () { overviewQ.refetch() }, children: jsxs('span', { className: 'inline-flex items-center gap-1.5', children: [jsx(Codicon, { name: 'refresh', size: '0.8rem' }), 'Run health check'] }) }),
      jsx(Button, { size: 'sm', variant: 'outline', onClick: function () { integrityQ.refetch() }, children: jsxs('span', { className: 'inline-flex items-center gap-1.5', children: [jsx(Codicon, { name: 'verified', size: '0.8rem' }), 'Verify integrity'] }) }),
      jsx(Button, { size: 'sm', variant: 'outline', onClick: function () { queryClient.invalidateQueries({ queryKey: QUERY_ROOT }) }, children: jsxs('span', { className: 'inline-flex items-center gap-1.5', children: [jsx(Codicon, { name: 'sync', size: '0.8rem' }), 'Refresh all'] }) })
    ] }),
    jsx('p', { className: 'text-xs text-(--ui-text-quaternary)', children: 'All operations are read-only. Mutations are only available through individual credential actions in the Credentials tab.' })
  ] })
}

// -- main page ----------------------------------------------------------------
function VaultPage(_a) {
  var ctx = _a.ctx
  var activeProfile = useValue(host.state.profile) || DEFAULT_PROFILE
  var _b = useState(activeProfile), profile = _b[0], setProfile = _b[1]
  var _c = useState(null), openDialog = _c[0], setOpenDialog = _c[1]
  var _d = useState(null), rotateTarget = _d[0], setRotateTarget = _d[1]
  var _e = useState(null), deleteTarget = _e[0], setDeleteTarget = _e[1]
  var queryClient = useQueryClient()
  var nowRef = useRef(Date.now())

  useEffect(function () { setProfile(activeProfile) }, [activeProfile])

  var call = useCallback(function (path, extra) {
    return ctx.rest(profilePath(path, profile, extra), { timeoutMs: REQUEST_TIMEOUT_MS })
  }, [ctx, profile])

  var mutateCall = useCallback(function (path, body) {
    // Mutation routes reject ALL query params (security-arch I6 / §3.3):
    // the adapter's _no_query dependency 400s any ?profile= suffix. Mutations
    // run against the adapter's configured vault profile, so the bare path is
    // the correct call; GET reads still carry the profile query via call().
    return ctx.rest(path, { method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' }, timeoutMs: MUTATION_TIMEOUT_MS })
  }, [ctx])

  var overviewQ = useQuery({ queryKey: [ID, 'overview', profile], queryFn: function () { return call('/overview') }, refetchInterval: REFRESH_INTERVAL_MS })
  var credentialsQ = useQuery({ queryKey: [ID, 'credentials', profile], queryFn: function () { return call('/credentials') }, refetchInterval: REFRESH_INTERVAL_MS })
  var leasesQ = useQuery({ queryKey: [ID, 'leases', profile], queryFn: function () { return call('/leases') }, refetchInterval: REFRESH_INTERVAL_MS })
  var policyQ = useQuery({ queryKey: [ID, 'policy', profile], queryFn: function () { return call('/policy') }, refetchInterval: REFRESH_INTERVAL_MS })
  var requestsQ = useQuery({ queryKey: [ID, 'requests', profile], queryFn: function () { return call('/requests') }, refetchInterval: REFRESH_INTERVAL_MS })
  var integrityQ = useQuery({ queryKey: [ID, 'integrity', profile], queryFn: function () { return call('/integrity') }, refetchInterval: REFRESH_INTERVAL_MS })
  var helloQ = useQuery({ queryKey: [ID, 'hello', profile], queryFn: function () { return call('/hello') }, refetchInterval: REFRESH_INTERVAL_MS, staleTime: 600_000 })

  var refresh = useCallback(function () { queryClient.invalidateQueries({ queryKey: QUERY_ROOT }) }, [queryClient])
  var changeProfile = useCallback(function (next) { setProfile(next); queryClient.invalidateQueries({ queryKey: QUERY_ROOT }) }, [queryClient])

  var profileOptions = Array.from(new Set([DEFAULT_PROFILE, activeProfile, profile].filter(Boolean)))

  // mutation capabilities gate
  var mutationsEnabled = helloQ.data && helloQ.data.mutations === true

  // health strip derivation
  var overview = overviewQ.data || {}
  var credRecords = (credentialsQ.data && credentialsQ.data.credentials) || []
  var now = nowRef.current
  var needsAttention = 0
  credRecords.forEach(function (c) {
    var s = deriveStatus(c, now)
    if (s.label !== 'active') needsAttention++
  })
  var health = {
    credential_count: overview.credential_count,
    needsAttention: needsAttention,
    leaseCount: overview.lease_count,
    activeLeaseCount: overview.active_lease_count,
    integrityOk: overview.health && overview.health.integrity_status === 'healthy'
  }

  // open row actions
  var openRotate = useCallback(function (record) { setRotateTarget(record); setOpenDialog('rotate') }, [])
  var openDelete = useCallback(function (record) { setDeleteTarget(record); setOpenDialog('delete') }, [])
  var openAdd = useCallback(function () { setOpenDialog('add') }, [])
  var closeDialog = useCallback(function () { setOpenDialog(null); setRotateTarget(null); setDeleteTarget(null) }, [])

  // current tab state — MUST be hoisted above the loading/error early returns
  // below: hooks may not appear after a conditional return (React #310,
  // "Rendered more hooks than during the previous render"). These five hooks
  // do not depend on query data, so running them during the loading and error
  // phases is safe and keeps the hook count identical across every render.
  var _f = useState('credentials'), activeTab = _f[0], setActiveTab = _f[1]
  var _g = useState('all'), statusFilter = _g[0], setStatusFilter = _g[1]
  var _h = useState(''), searchQuery = _h[0], setSearchQuery = _h[1]

  var onSearchChange = useCallback(function (v) { setSearchQuery(v) }, [])
  var onFilterChange = useCallback(function (id) { setStatusFilter(id) }, [])

  // loading / error states
  if (overviewQ.isLoading) {
    return jsx('div', { className: 'h-full overflow-auto', children: jsx(LoadingState, {}) })
  }
  if (overviewQ.error) {
    var details = errorDetails(overviewQ.error)
    return jsxs('div', { className: 'h-full overflow-auto', children: [
      jsx(PageHeader, { profile: profile, profileOptions: profileOptions, onProfileChange: changeProfile, onRefresh: refresh, refreshing: overviewQ.isFetching }),
      jsx(StateCard, { details: details, onRefresh: refresh })
    ] })
  }

  var tabContent
  if (activeTab === 'credentials') {
    tabContent = jsx(CredentialsTab, {
      credentialsQ: credentialsQ,
      statusFilter: statusFilter,
      searchQuery: searchQuery,
      onSearchChange: onSearchChange,
      onFilterChange: onFilterChange,
      mutationsEnabled: mutationsEnabled,
      onRotate: openRotate,
      onDelete: openDelete,
      onAdd: openAdd
    })
  } else if (activeTab === 'requests') {
    tabContent = jsx(RequestsTab, { requestsQ: requestsQ })
  } else if (activeTab === 'leases') {
    tabContent = jsx(LeasesTab, { leasesQ: leasesQ })
  } else if (activeTab === 'policy') {
    tabContent = jsx(PolicyTab, { policyQ: policyQ })
  } else if (activeTab === 'audit') {
    tabContent = jsx(AuditTab, { integrityQ: integrityQ, overviewData: overview })
  } else {
    tabContent = jsx(OperationsTab, { overviewQ: overviewQ, integrityQ: integrityQ })
  }

  var requestCount = requestsQ.data ? requestsQ.data.request_count : 0
  var leaseCount = leasesQ.data ? leasesQ.data.lease_count : 0

  return jsxs('div', {
    className: 'h-full overflow-auto',
    children: [
      jsx(PageHeader, { profile: profile, profileOptions: profileOptions, onProfileChange: changeProfile, onRefresh: refresh, refreshing: overviewQ.isFetching, health: health }),
      jsxs('main', {
        className: 'mx-auto grid w-full max-w-5xl gap-4 px-6 py-5',
        children: [
          jsxs('div', { className: 'flex flex-wrap items-center gap-2', children: [
            jsx(Badge, { variant: 'muted', children: 'read-only' }),
            jsx(Badge, { variant: 'muted', children: 'raw values hidden' }),
            jsx(Badge, { variant: 'muted', children: 'profile: ' + safeText(profile, DEFAULT_PROFILE) })
          ] }),
          jsx(Tabs, { value: activeTab, onValueChange: setActiveTab, children: [
            jsx(TabsList, { className: 'overflow-x-auto', children: [
              jsx(TabsTrigger, { value: 'credentials', children: 'Credentials' }),
              jsx(TabsTrigger, { value: 'requests', children: jsxs('span', { className: 'inline-flex items-center gap-1.5', children: ['Access requests', requestCount > 0 ? jsx(Badge, { variant: 'destructive', children: String(requestCount) }) : null] }) }),
              jsx(TabsTrigger, { value: 'leases', children: 'Leases' + (leaseCount > 0 ? ' ' + String(leaseCount) : '') }),
              jsx(TabsTrigger, { value: 'policy', children: 'Policy' }),
              jsx(TabsTrigger, { value: 'audit', children: 'Audit' }),
              jsx(TabsTrigger, { value: 'operations', children: 'Operations' })
            ] }),
            jsx('div', { className: 'pt-3', children: tabContent })
          ] }),
          jsx(Separator, {}),
          jsx('div', { className: 'pb-5 text-xs text-(--ui-text-quaternary)', children: 'Hermes Vault Desktop never renders or persists secret values, ciphertext, tokens, or materialized credentials.' }),
          openDialog === 'add' ? jsx(AddCredentialDialog, { onClose: closeDialog, mutationsEnabled: mutationsEnabled, mutateCall: mutateCall, onSuccess: refresh }) : null,
          openDialog === 'rotate' ? jsx(RotateCredentialDialog, { target: rotateTarget, onClose: closeDialog, mutationsEnabled: mutationsEnabled, mutateCall: mutateCall, onSuccess: refresh }) : null,
          openDialog === 'delete' ? jsx(DeleteCredentialDialog, { target: deleteTarget, onClose: closeDialog, mutationsEnabled: mutationsEnabled, mutateCall: mutateCall, onSuccess: refresh, credentialsQ: credentialsQ, leasesQ: leasesQ }) : null
        ]
      })
    ]
  })
}

// -- plugin registration ------------------------------------------------------
var plugin = {
  id: ID,
  name: 'Hermes Vault',
  defaultEnabled: false,
  register: function (ctx) {
    ensureStyles()
    var Page = function () { return jsx(VaultPage, { ctx: ctx }) }
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: '/hermes-vault' }, render: function () { return jsx(Page, {}) } },
      { id: 'nav', area: SIDEBAR_NAV_AREA, order: 60, data: { codicon: 'shield', label: 'Hermes Vault', path: '/hermes-vault' } },
      { id: 'open', area: PALETTE_AREA, data: { id: 'hermes-vault.open', label: 'Hermes Vault: Open', keywords: ['vault', 'credentials', 'leases', 'integrity', 'policy'], run: function () { host.navigate('/hermes-vault') } } }
    ])
  }
}

export { plugin as default }
