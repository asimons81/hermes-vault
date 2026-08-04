import { useEffect, useState } from 'react'
import {
  Button,
  ConfirmDialog,
  Codicon,
  EmptyState,
  ErrorState,
  PALETTE_AREA,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Separator,
  cn,
  host,
  useQuery,
  useQueryClient,
  useValue
} from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

const ID = 'hermes-vault-desktop'
const DEFAULT_PROFILE = 'default'
const QUERY_ROOT = [ID]
const REFRESH_INTERVAL_MS = 30_000
const REQUEST_TIMEOUT_MS = 8_000

function profilePath(path, profile, extra = '') {
  const query = `profile=${encodeURIComponent(profile)}`
  return `${path}?${query}${extra}`
}

function safeText(value, fallback = '—') {
  if (typeof value !== 'string' || !value || value.length > 160 || /[\u0000-\u001f\u007f]/.test(value)) {
    return fallback
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

  const status = error.status ?? error.statusCode ?? error.response?.status
  const body = error.body ?? error.data ?? error.response?.data
  const nested = body && typeof body === 'object' && body.error && typeof body.error === 'object' ? body.error : null
  const code = nested?.code ?? error.code

  if (status === 423 || code === 'MISSING_PASSPHRASE' || code === 'VAULT_NOT_READY') {
    return {
      kind: 'locked',
      title: 'Vault is locked',
      description: 'Unlock Hermes Vault through its normal local workflow, then refresh this page.'
    }
  }
  if (code === 'PROTOCOL_MISMATCH') {
    return {
      kind: 'version',
      title: 'Vault bridge version mismatch',
      description: 'The installed bridge does not satisfy this Desktop plugin contract.'
    }
  }
  if (status === 503 || code === 'BINARY_MISSING' || code === 'BRIDGE_UNAVAILABLE') {
    return {
      kind: 'unavailable',
      title: 'Vault bridge unavailable',
      description: 'The read-only hermes-vault bridge is not available to the Hermes backend.'
    }
  }
  return {
    kind: 'generic',
    title: 'Vault metadata unavailable',
    description: 'The read-only Vault bridge returned an unexpected failure.'
  }
}

function StateCard({ details, onRefresh }) {
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
      jsx('div', { className: 'mt-4 grid grid-cols-2 gap-3 md:grid-cols-4', children: [1, 2, 3, 4].map(index => jsx('div', { className: 'h-24 animate-pulse rounded-xl border border-(--ui-stroke-secondary) bg-(--ui-control-background)', key: index })) })
    ]
  })
}

function CountCard({ label, value, detail }) {
  return jsxs('div', {
    className: 'grid gap-1 rounded-xl border border-(--ui-stroke-secondary) px-3 py-3',
    children: [
      jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: label }),
      jsx('div', { className: 'text-xl font-semibold tabular-nums', children: value }),
      detail ? jsx('div', { className: 'truncate text-[0.6875rem] text-(--ui-text-quaternary)', children: detail }) : null
    ]
  })
}

function Section({ title, action, children }) {
  return jsxs('section', {
    className: 'grid gap-3',
    children: [
      jsxs('div', { className: 'flex items-center justify-between gap-3', children: [jsx('h2', { className: 'text-sm font-semibold', children: title }), action || null] }),
      children
    ]
  })
}

function MetadataPill({ children, tone = 'quiet' }) {
  const toneClass = tone === 'good' ? 'text-(--ui-accent)' : tone === 'bad' ? 'text-destructive' : 'text-(--ui-text-tertiary)'
  return jsx('span', {
    className: cn('inline-flex items-center rounded-md border border-(--ui-stroke-secondary) px-2 py-1 text-[0.6875rem]', toneClass),
    children
  })
}

function OverviewSection({ overview, onVerify }) {
  const healthStatus = safeText(overview.health?.status, 'unknown')
  const integrityStatus = safeText(overview.health?.integrity_status, healthStatus)
  return jsxs(Section, {
    title: 'Vault overview',
    action: jsx(Button, { onClick: onVerify, size: 'xs', variant: 'outline', children: 'Verify integrity' }),
    children: [
      jsxs('div', {
        className: 'grid gap-3 sm:grid-cols-2 lg:grid-cols-4',
        children: [
          jsx(CountCard, { label: 'Credentials', value: safeCount(overview.credential_count), detail: 'metadata count only' }),
          jsx(CountCard, { label: 'Leases', value: safeCount(overview.lease_count), detail: `${safeCount(overview.active_lease_count)} active` }),
          jsx(CountCard, { label: 'Profile', value: safeText(overview.profile, DEFAULT_PROFILE), detail: 'selected profile' }),
          jsx(CountCard, { label: 'Integrity', value: integrityStatus, detail: `health: ${healthStatus}` })
        ]
      }),
      jsx('div', { className: 'flex flex-wrap gap-2', children: (Array.isArray(overview.services) ? overview.services : []).slice(0, 20).map((service, index) => jsx(MetadataPill, { children: safeText(service), key: `${safeText(service, 'service')}-${index}` })) })
    ]
  })
}

function IntegritySection({ integrity }) {
  if (!integrity) {
    return jsx(EmptyState, { title: 'Integrity metadata unavailable', description: 'The bridge did not return an integrity record.' })
  }
  return jsxs(Section, {
    title: 'Audit integrity',
    children: [
      jsxs('div', { className: 'flex flex-wrap gap-2', children: [
        jsx(MetadataPill, { children: safeText(integrity.status, 'unknown'), tone: integrity.status === 'healthy' ? 'good' : 'bad' }),
        jsx(MetadataPill, { children: safeText(integrity.reason_code, 'no reason') }),
        jsx(MetadataPill, { children: `${safeCount(integrity.verified_count)} verified` }),
        jsx(MetadataPill, { children: `${safeCount(integrity.legacy_count)} legacy` })
      ] }),
      jsx('div', { className: 'text-xs text-(--ui-text-tertiary)', children: safeText(integrity.recommended_next_step, 'No further operator action reported.') })
    ]
  })
}

function CredentialRow({ record, index }) {
  return jsxs('div', {
    className: 'flex flex-wrap items-center justify-between gap-2 rounded-lg border border-(--ui-stroke-secondary) px-3 py-2 text-xs',
    children: [
      jsxs('span', {
        className: 'grid gap-0.5',
        children: [
          jsx('span', { className: 'font-medium', children: safeText(record.service, 'unknown service') }),
          jsx('span', { className: 'text-(--ui-text-tertiary)', children: safeText(record.alias || record.name, 'metadata record') })
        ]
      }),
      jsx(MetadataPill, { children: 'value hidden' })
    ],
    key: index
  })
}

function CredentialsSection({ credentials, unavailable }) {
  if (unavailable) {
    return jsx(Section, { title: 'Credential metadata', children: jsx(EmptyState, { title: 'Credential metadata unavailable', description: 'No raw credential values are ever rendered here.' }) })
  }
  const rows = Array.isArray(credentials?.credentials) ? credentials.credentials.slice(0, 30) : []
  return jsx(Section, {
    title: `Credential metadata (${safeCount(credentials?.credential_count)})`,
    children: rows.length
      ? jsx('div', { className: 'grid gap-2', children: rows.map((record, index) => jsx(CredentialRow, { index, key: `${safeText(record.service, 'record')}-${index}`, record })) })
      : jsx(EmptyState, { title: 'No credential metadata', description: 'This profile does not currently report credential records.' })
  })
}

function LeaseRow({ lease, index }) {
  return jsxs('div', {
    className: 'flex flex-wrap items-center justify-between gap-2 rounded-lg border border-(--ui-stroke-secondary) px-3 py-2 text-xs',
    children: [
      jsxs('span', {
        className: 'grid gap-0.5',
        children: [
          jsx('span', { className: 'font-medium', children: safeText(lease.service, 'unknown service') }),
          jsx('span', { className: 'text-(--ui-text-tertiary)', children: safeText(lease.agent_id, 'agent unavailable') })
        ]
      }),
      jsx(MetadataPill, { children: safeText(lease.status, 'unknown') })
    ],
    key: index
  })
}

function LeasesSection({ leases, unavailable }) {
  if (unavailable) {
    return jsx(Section, { title: 'Lease metadata', children: jsx(EmptyState, { title: 'Lease metadata unavailable', description: 'No lease secrets or materialized values are rendered here.' }) })
  }
  const rows = Array.isArray(leases?.leases) ? leases.leases.slice(0, 30) : []
  return jsx(Section, {
    title: `Lease metadata (${safeCount(leases?.lease_count)})`,
    children: rows.length
      ? jsx('div', { className: 'grid gap-2', children: rows.map((lease, index) => jsx(LeaseRow, { index, key: `${safeText(lease.service, 'lease')}-${index}`, lease })) })
      : jsx(EmptyState, { title: 'No lease metadata', description: 'This profile does not currently report leases.' })
  })
}

function RequestRow({ request, index, onAction }) {
  return jsxs('div', {
    className: 'grid gap-3 rounded-lg border border-(--ui-stroke-secondary) px-3 py-3',
    children: [
      jsxs('div', {
        className: 'flex flex-wrap items-center justify-between gap-2 text-xs',
        children: [
          jsxs('span', {
            className: 'grid gap-0.5',
            children: [
              jsx('span', { className: 'font-medium', children: safeText(request.service, 'unknown service') }),
              jsx('span', { className: 'text-(--ui-text-tertiary)', children: safeText(request.agent_id, 'agent unavailable') })
            ]
          }),
          jsx(MetadataPill, { children: safeText(request.status || request.decision, 'pending') })
        ]
      }),
      jsxs('div', {
        className: 'flex flex-wrap gap-2',
        children: [
          jsx(Button, { onClick: () => onAction('approve', request), size: 'xs', variant: 'outline', children: 'Approve' }),
          jsx(Button, { onClick: () => onAction('deny', request), size: 'xs', variant: 'ghost', children: 'Deny' }),
          jsx(Button, { onClick: () => onAction('lease', request), size: 'xs', variant: 'ghost', children: 'Approve & issue lease' })
        ]
      })
    ],
    key: index
  })
}

function RequestsSection({ requests, onAction, unavailable }) {
  if (unavailable) {
    return jsx(Section, { title: 'Access requests', children: jsx(EmptyState, { title: 'Access request metadata unavailable', description: 'The read-only bridge did not return request metadata.' }) })
  }
  const rows = Array.isArray(requests?.requests) ? requests.requests.slice(0, 20) : []
  return jsx(Section, {
    title: `Access requests (${safeCount(requests?.request_count)})`,
    children: rows.length
      ? jsx('div', { className: 'grid gap-2', children: rows.map((request, index) => jsx(RequestRow, { index, key: `${safeText(request.service, 'request')}-${index}`, onAction, request })) })
      : jsx(EmptyState, { title: 'No pending access requests', description: 'Requests are shown as metadata only.' })
  })
}

function AuditRow({ entry, index }) {
  return jsxs('div', {
    className: 'grid grid-cols-[auto_1fr_auto] items-center gap-3 border-b border-(--ui-stroke-secondary) py-2 text-xs last:border-b-0',
    children: [
      jsx('span', { className: 'tabular-nums text-(--ui-text-quaternary)', children: safeCount(entry.sequence) }),
      jsxs('span', {
        className: 'min-w-0',
        children: [
          jsx('span', { className: 'block truncate font-medium', children: safeText(entry.action, 'audit event') }),
          jsx('span', { className: 'block truncate text-(--ui-text-tertiary)', children: safeText(entry.service, safeText(entry.agent_id, 'metadata')) })
        ]
      }),
      jsx(MetadataPill, { children: safeText(entry.decision, 'recorded') })
    ],
    key: index
  })
}

function AuditSection({ overview }) {
  const entries = Array.isArray(overview.recent_audit) ? overview.recent_audit.slice(0, 20) : []
  return jsx(Section, {
    title: 'Recent audit metadata',
    children: entries.length
      ? jsx('div', { className: 'grid gap-1', children: entries.map((entry, index) => jsx(AuditRow, { entry, index, key: `${safeText(entry.action, 'audit')}-${index}` })) })
      : jsx(EmptyState, { title: 'No recent audit metadata', description: 'The bridge returned no recent entries for this profile.' })
  })
}

function ReadOnlyActionDialog({ action, onClose }) {
  if (!action) {
    return null
  }
  return jsx(ConfirmDialog, {
    open: true,
    onClose,
    onConfirm: action.onConfirm,
    title: action.title,
    description: action.description,
    confirmLabel: action.confirmLabel,
    busyLabel: 'Working…',
    doneLabel: 'Done',
    destructive: action.kind === 'deny'
  })
}

function VaultPage({ ctx }) {
  const activeProfile = useValue(host.state.profile) || DEFAULT_PROFILE
  const [profile, setProfile] = useState(activeProfile)
  const [action, setAction] = useState(null)
  const queryClient = useQueryClient()

  useEffect(() => {
    setProfile(activeProfile)
  }, [activeProfile])

  const call = (path, extra = '') => ctx.rest(profilePath(path, profile, extra), { timeoutMs: REQUEST_TIMEOUT_MS })
  const overview = useQuery({ queryKey: [ID, 'overview', profile], queryFn: () => call('/overview'), refetchInterval: REFRESH_INTERVAL_MS })
  const credentials = useQuery({ queryKey: [ID, 'credentials', profile], queryFn: () => call('/credentials'), refetchInterval: REFRESH_INTERVAL_MS })
  const leases = useQuery({ queryKey: [ID, 'leases', profile], queryFn: () => call('/leases'), refetchInterval: REFRESH_INTERVAL_MS })
  const policy = useQuery({ queryKey: [ID, 'policy', profile], queryFn: () => call('/policy'), refetchInterval: REFRESH_INTERVAL_MS })
  const requests = useQuery({ queryKey: [ID, 'requests', profile], queryFn: () => call('/requests'), refetchInterval: REFRESH_INTERVAL_MS })
  const integrity = useQuery({ queryKey: [ID, 'integrity', profile], queryFn: () => call('/integrity'), refetchInterval: REFRESH_INTERVAL_MS })

  const refresh = () => void queryClient.invalidateQueries({ queryKey: QUERY_ROOT })
  const changeProfile = next => {
    setProfile(next)
    void queryClient.invalidateQueries({ queryKey: QUERY_ROOT })
  }
  const profileOptions = Array.from(new Set([DEFAULT_PROFILE, activeProfile, profile].filter(Boolean)))
  const primaryDetails = errorDetails(overview.error)

  const openAction = (kind, request = null) => {
    if (kind === 'verify') {
      setAction({
        kind,
        title: 'Verify Vault audit integrity?',
        description: 'This performs a read-only integrity verification for the selected profile.',
        confirmLabel: 'Verify',
        onConfirm: async () => {
          const result = await integrity.refetch()
          if (result.error || result.isError) {
            throw new Error('Vault integrity verification failed.')
          }
        }
      })
      return
    }
    const operation = kind === 'lease' ? 'approve this request and issue a lease' : `${kind} this request`
    setAction({
      kind,
      title: `Confirm: ${operation}?`,
      description: `${safeText(request?.service, 'This request')} is shown in read-only mode. No Vault mutation will be performed by this integration.`,
      confirmLabel: 'Continue',
      onConfirm: async () => {
        throw new Error('This read-only integration does not perform Vault mutations.')
      }
    })
  }

  if (overview.isLoading) {
    return jsx('div', { className: 'h-full overflow-auto', children: jsx(LoadingState, {}) })
  }
  if (overview.error) {
    return jsxs('div', { className: 'h-full overflow-auto', children: [jsx(PageHeader, { profile, profileOptions, onProfileChange: changeProfile, onRefresh: refresh, refreshing: overview.isFetching }), jsx(StateCard, { details: primaryDetails, onRefresh: refresh })] })
  }

  const overviewData = overview.data || {}
  return jsxs('div', {
    className: 'h-full overflow-auto',
    children: [
      jsx(PageHeader, { profile, profileOptions, onProfileChange: changeProfile, onRefresh: refresh, refreshing: overview.isFetching }),
      jsxs('main', {
        className: 'mx-auto grid w-full max-w-5xl gap-7 px-6 py-5',
        children: [
          jsxs('div', { className: 'flex flex-wrap items-center gap-2', children: [jsx(MetadataPill, { children: 'read-only' }), jsx(MetadataPill, { children: 'raw values hidden' }), jsx(MetadataPill, { children: `profile: ${safeText(profile, DEFAULT_PROFILE)}` })] }),
          jsx(OverviewSection, { overview: overviewData, onVerify: () => openAction('verify') }),
          jsx(IntegritySection, { integrity: integrity.data }),
          jsx(Section, { title: 'Policy metadata', children: jsxs('div', { className: 'flex flex-wrap gap-2', children: [jsx(MetadataPill, { children: policy.data?.policy_exists ? 'policy present' : 'policy unavailable', tone: policy.data?.policy_exists ? 'good' : 'quiet' }), jsx(MetadataPill, { children: `${safeCount(policy.data?.agents ? Object.keys(policy.data.agents).length : 0)} agents described` }), jsx(MetadataPill, { children: safeText(policy.data?.doctor?.status, 'doctor unavailable') })] }) }),
          jsx(CredentialsSection, { credentials: credentials.data, unavailable: Boolean(credentials.error) }),
          jsx(LeasesSection, { leases: leases.data, unavailable: Boolean(leases.error) }),
          jsx(RequestsSection, { requests: requests.data, onAction: openAction, unavailable: Boolean(requests.error) }),
          jsx(AuditSection, { overview: overviewData }),
          jsx(Separator, {}),
          jsx('div', { className: 'pb-5 text-xs text-(--ui-text-quaternary)', children: 'Hermes Vault Desktop never renders or persists secret values, ciphertext, tokens, or materialized credentials.' })
        ]
      }),
      jsx(ReadOnlyActionDialog, { action, onClose: () => setAction(null) })
    ]
  })
}

function PageHeader({ profile, profileOptions, onProfileChange, onRefresh, refreshing }) {
  return jsxs('header', {
    className: 'sticky top-0 z-10 border-b border-(--ui-stroke-secondary) bg-(--ui-background) px-6 py-4',
    children: [
      jsxs('div', { className: 'mx-auto flex w-full max-w-5xl flex-wrap items-center justify-between gap-4', children: [
        jsxs('div', { className: 'grid gap-1', children: [jsx('h1', { className: 'text-lg font-semibold tracking-tight', children: 'Hermes Vault' }), jsx('p', { className: 'text-xs text-(--ui-text-tertiary)', children: 'Read-only credential, lease, policy, and audit metadata' })] }),
        jsxs('div', { className: 'flex flex-wrap items-center gap-2', children: [
          jsx(Select, { onValueChange: onProfileChange, value: profile, children: [
            jsx(SelectTrigger, { 'aria-label': 'Vault profile', className: 'w-36', children: jsx(SelectValue, {}) }),
            jsx(SelectContent, { children: profileOptions.map(option => jsx(SelectItem, { value: option, children: option, key: option })) })
          ] }),
          jsx(Button, { 'aria-label': 'Refresh Vault metadata', disabled: refreshing, onClick: onRefresh, size: 'icon-xs', variant: 'ghost', children: jsx(Codicon, { name: 'refresh', size: '0.8rem' }) })
        ] })
      ] })
    ]
  })
}

const plugin = {
  id: ID,
  name: 'Hermes Vault',
  defaultEnabled: false,
  register(ctx) {
    const Page = () => jsx(VaultPage, { ctx })
    ctx.registerMany([
      {
        id: 'page',
        area: ROUTES_AREA,
        data: { path: '/hermes-vault' },
        render: () => jsx(Page, {})
      },
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        order: 60,
        data: { codicon: 'shield', label: 'Hermes Vault', path: '/hermes-vault' }
      },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'hermes-vault.open',
          label: 'Hermes Vault: Open',
          keywords: ['vault', 'credentials', 'leases', 'integrity', 'policy'],
          run: () => host.navigate('/hermes-vault')
        }
      }
    ])
  }
}

export default plugin
