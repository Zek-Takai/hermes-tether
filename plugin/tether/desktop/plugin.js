// Hermes Tether Desktop half: the Tether tab in the right sidebar (beside Files).
// It shows what the Hermes this app is connected to does with tether: on a host, the paired machines (online,
// the words that open each one, its idle limit); on a device, the settings this machine owns (idle limit,
// consent wait, pause). Both show the connection log: when machines connected, chats tethered and untethered,
// sessions allowed or denied. Nothing private: no commands, paths, keys or addresses.
// Open it from the right sidebar, the command palette ("Open Hermes Tether"), or Cmd+Shift+E (macOS) /
// Ctrl+Shift+E (Windows, Linux); the shortcut can be changed in Keybinds.
import { Button, EmptyState, Input, KEYBINDS_AREA, PALETTE_AREA, host, icons } from '@hermes/plugin-sdk'
import { useCallback, useEffect, useState } from 'react'
import { jsx, jsxs } from 'react/jsx-runtime'

const PLUGIN_ID = 'tether'
const PANE_ID = 'tether-panel'
const SHORTCUT = 'mod+shift+e'
const REFRESH_MS = 10000
const OK = '#3fb950'
const OFF = '#8b949e'
const BAD = '#f85149'

let rest = null
const refreshListeners = new Set()
const notifyRefresh = () => refreshListeners.forEach((fn) => fn())

function isMac() {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '')
}

const shortcutLabel = () => (isMac() ? '⌘⇧E' : 'Ctrl+Shift+E')

function openPanel() {
  const id = `${PLUGIN_ID}:${PANE_ID}`
  if (typeof host.undismissPane === 'function') host.undismissPane(id)
  if (typeof host.revealPane === 'function') host.revealPane(id)
  notifyRefresh()
}

function when(ts) {
  if (!ts) return ''
  const d = new Date(ts * 1000)
  const now = new Date()
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  return d.toDateString() === now.toDateString() ? time : `${d.toLocaleDateString([], { month: 'short', day: 'numeric' })} ${time}`
}

function chat(e) {
  return e.session ? ` (chat …${e.session})` : ''
}

function describe(e) {
  const dev = e.device || 'device'
  const why = e.reason ? ` — ${e.reason}` : ''
  switch (e.kind) {
    case 'device_connected': return `${dev} connected${e.link ? ` (${e.link})` : ''}`
    case 'device_disconnected': return `${dev} went offline`
    case 'connection_refused': return `Refused a connection${why}`
    case 'tethered': return `Tethered to ${dev}${chat(e)}`
    case 'untethered': return `Untethered from ${dev}${chat(e)}${why}`
    case 'host_connected': return `Connected to ${e.host || 'the host'}`
    case 'host_disconnected': return `Disconnected from ${e.host || 'the host'}`
    case 'allowed': return `Remote use allowed${chat(e)}`
    case 'denied': return `Remote use denied${chat(e)}`
    case 'lapsed': return `Session lapsed${chat(e)}${why}`
    case 'session_closed': return `Session closed${chat(e)}${why}`
    case 'settings_changed': return `Settings changed${e.device ? ` for ${e.device}` : ''}${why}`
    case 'device_renamed': return `Renamed to ${dev}${why}`
    case 'paused': return 'Remote use paused'
    case 'resumed': return 'Remote use resumed'
    default: return `${e.kind}${why}`
  }
}

function tone(kind) {
  if (['denied', 'connection_refused', 'device_disconnected', 'host_disconnected', 'paused'].includes(kind)) return BAD
  if (['allowed', 'tethered', 'device_connected', 'host_connected', 'resumed'].includes(kind)) return OK
  return OFF
}

const dot = (color) => jsx('span', {
  style: { width: 8, height: 8, borderRadius: 999, background: color, display: 'inline-block', flex: 'none' }
})

const section = (title, children) => jsxs('div', {
  className: 'flex flex-col gap-2 px-3 py-3 border-b border-[var(--ui-border,rgba(127,127,127,.2))]',
  children: [jsx('div', { className: 'text-xs font-semibold uppercase tracking-wide opacity-60', children: title }), ...children]
})

function DeviceCard({ d, onSaved }) {
  const [label, setLabel] = useState(d.name)
  const [idle, setIdle] = useState(d.host_idle_minutes != null ? String(d.host_idle_minutes) : '')
  const [msg, setMsg] = useState('')
  useEffect(() => setLabel(d.name), [d.name])
  useEffect(() => setIdle(d.host_idle_minutes != null ? String(d.host_idle_minutes) : ''), [d.host_idle_minutes])

  const color = d.online === true ? OK : d.online === false ? OFF : BAD
  const state = d.online === true ? 'online' : d.online === false ? (d.last_seen ? `offline since ${when(d.last_seen)}` : 'offline') : 'status unknown'
  const effective = [d.host_idle_minutes, d.device_idle_minutes].filter((x) => x != null)
  const closes = effective.length ? Math.round(Math.min(...effective)) : null

  const save = async () => {
    const body = {}
    if (label.trim() && label.trim() !== d.name) body.label = label.trim()
    const idleText = idle.trim()
    const current = d.host_idle_minutes != null ? String(d.host_idle_minutes) : ''
    if (idleText !== current) body.idle_minutes = idleText === '' ? null : Number(idleText)
    if (!Object.keys(body).length) {
      setMsg('Nothing changed.')
      return
    }
    try {
      const res = await rest(`/devices/${encodeURIComponent(d.name)}`, { method: 'PUT', body })
      setMsg(body.label ? `Saved. Now opened with "${res.phrase}"; it reconnects in a few seconds.` : 'Saved.')
      onSaved()
    } catch (e) {
      setMsg(String(e?.message || e))
    }
  }

  return jsxs('div', {
    className: 'rounded-md border border-[var(--ui-border,rgba(127,127,127,.25))] px-3 py-2 flex flex-col gap-2',
    children: [
      jsxs('div', { className: 'flex items-center gap-2', children: [dot(color), jsx('span', { className: 'font-medium', children: d.name }), jsx('span', { className: 'text-xs opacity-60', children: state })] }),
      jsxs('div', { className: 'text-xs', children: ['Open with: ', jsx('code', { className: 'px-1 rounded bg-[var(--ui-muted,rgba(127,127,127,.15))]', children: d.phrase })] }),
      d.os && jsx('div', { className: 'text-xs opacity-70', children: d.os }),
      closes != null && jsx('div', { className: 'text-xs opacity-70', children: `Closes after ${closes} idle minutes${d.device_idle_minutes != null ? ` (the machine's own limit: ${Math.round(d.device_idle_minutes)})` : ''}` }),
      jsxs('div', { className: 'grid gap-1', style: { gridTemplateColumns: 'auto 1fr' }, children: [
        jsx('span', { className: 'text-xs self-center pr-2', children: 'Label' }),
        jsx(Input, { value: label, onChange: (e) => setLabel(e.target.value), className: 'h-7', placeholder: 'e.g. studio pc' }),
        jsx('span', { className: 'text-xs self-center pr-2', children: 'Idle limit' }),
        jsxs('div', { className: 'flex items-center gap-2', children: [
          jsx(Input, { value: idle, onChange: (e) => setIdle(e.target.value), className: 'h-7 w-20', inputMode: 'decimal', placeholder: 'none' }),
          jsx('span', { className: 'text-xs opacity-60', children: 'minutes (1–1440, empty = the machine decides)' })
        ] })
      ] }),
      jsxs('div', { className: 'flex items-center gap-2', children: [
        jsx(Button, { size: 'sm', variant: 'outline', onClick: () => void save(), children: 'Save' }),
        jsx('span', { className: 'text-xs opacity-60', children: msg || 'The label is the word that opens it. The shorter idle limit wins.' })
      ] })
    ].filter(Boolean)
  })
}

function NumberSetting({ label, hint, value, unit, field, limits, onSaved }) {
  const [draft, setDraft] = useState(String(value ?? ''))
  const [msg, setMsg] = useState('')
  useEffect(() => setDraft(String(value ?? '')), [value])
  const save = async () => {
    try {
      await rest('/settings', { method: 'PUT', body: { [field]: Number(draft) } })
      setMsg('Saved; applies within a few seconds.')
      onSaved()
    } catch (e) {
      setMsg(String(e?.message || e))
    }
  }
  const range = limits ? `${limits.min}–${limits.max} ${unit}` : unit
  return jsxs('div', {
    className: 'flex flex-col gap-1',
    children: [
      jsx('div', { className: 'text-sm', children: label }),
      jsxs('div', { className: 'flex items-center gap-2', children: [
        jsx(Input, { value: draft, onChange: (e) => setDraft(e.target.value), className: 'h-7 w-24', inputMode: 'decimal' }),
        jsx('span', { className: 'text-xs opacity-60', children: range }),
        jsx(Button, { size: 'sm', variant: 'outline', onClick: () => void save(), children: 'Save' })
      ] }),
      jsx('div', { className: 'text-xs opacity-60', children: msg || hint })
    ]
  })
}

function TetherPane({ ctx }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    try {
      setData(await rest('/status'))
      setError('')
    } catch (e) {
      setError(String(e?.message || e))
    }
  }, [])

  useEffect(() => {
    void refresh()
    refreshListeners.add(refresh)
    const stop = ctx.setInterval(() => void refresh(), REFRESH_MS)
    return () => {
      refreshListeners.delete(refresh)
      stop()
    }
  }, [refresh, ctx])

  const header = jsxs('div', {
    className: 'flex items-center justify-between px-3 py-2 border-b border-[var(--ui-border,rgba(127,127,127,.2))]',
    children: [
      jsxs('div', { className: 'flex flex-col', children: [
        jsx('span', { className: 'font-semibold', children: 'Hermes Tether' }),
        jsx('span', { className: 'text-xs opacity-60', children: data ? `This Hermes: ${data.roles.length ? data.roles.join(' + ') : 'tether off'}${data.name ? ` (${data.name})` : ''}` : 'Loading…' })
      ] }),
      jsx(Button, { size: 'sm', variant: 'ghost', onClick: () => void refresh(), title: 'Refresh', children: jsx(icons.RefreshCw, { size: 14 }) })
    ]
  })

  if (error && !data) {
    return jsxs('div', { className: 'flex h-full flex-col', children: [header, jsx(EmptyState, { title: 'Tether is not available here', description: error })] })
  }
  if (!data) return jsx('div', { className: 'flex h-full flex-col', children: [header] })

  const parts = [header]
  if (!data.roles.length) {
    parts.push(jsx(EmptyState, { title: 'Tether is off on this Hermes', description: 'Set plugins.entries.tether.settings.role to host or device.' }))
  }
  if (data.host) {
    const devices = data.host.devices || []
    parts.push(section('Paired machines', devices.length
      ? [...devices.map((d) => jsx(DeviceCard, { d, onSaved: refresh }, d.name)),
         jsx('div', { className: 'text-xs opacity-60', children: 'Only these exact words open a machine. The person at it allows each session on its own screen; "untether", sent as a message on its own, closes it.' })]
      : [jsx('div', { className: 'text-sm opacity-70', children: 'No paired machines yet. Pair one with `hermes tether pair`.' })]))
    if (data.host.note) parts.push(jsx('div', { className: 'px-3 pt-2 text-xs', style: { color: BAD }, children: `Live status unavailable: ${data.host.note}` }))
  }
  if (data.device) {
    const dv = data.device
    parts.push(section('This machine', [
      jsx('div', { className: 'text-sm', children: dv.paired_host ? `Paired with ${dv.paired_host}` : 'Not paired with a host' }),
      jsxs('div', { className: 'flex items-center gap-2', children: [
        dot(dv.paused ? BAD : OK),
        jsx('span', { className: 'text-sm', children: dv.paused ? 'Remote use paused' : 'Remote use allowed when you approve it' }),
        jsx(Button, { size: 'sm', variant: 'outline', onClick: async () => { await rest('/pause', { method: 'POST', body: { paused: !dv.paused } }); void refresh() }, children: dv.paused ? 'Resume' : 'Pause' })
      ] }),
      jsx(NumberSetting, { label: 'Idle limit', unit: 'minutes', field: 'grant_idle_minutes', value: dv.grant_idle_minutes, limits: dv.limits?.grant_idle_minutes, hint: 'A session closes after this long without use; the next use asks you again.', onSaved: refresh }),
      jsx(NumberSetting, { label: 'Consent wait', unit: 'seconds', field: 'consent_timeout_seconds', value: dv.consent_timeout_seconds, limits: dv.limits?.consent_timeout_seconds, hint: 'How long the allow/deny prompt waits; no answer means deny.', onSaved: refresh }),
      jsx('div', { className: 'text-xs opacity-60', children: 'These belong to this machine; the host cannot change them.' })
    ]))
  }
  const events = data.events || []
  parts.push(section('Connection log', events.length
    ? events.map((e, i) => jsxs('div', { className: 'flex items-start gap-2 text-xs', children: [
        jsx('span', { className: 'opacity-60 tabular-nums', style: { minWidth: 72 }, children: when(e.ts) }),
        dot(tone(e.kind)),
        jsx('span', { children: describe(e) })
      ] }, `${e.ts}-${i}`))
    : [jsx('div', { className: 'text-sm opacity-70', children: 'Nothing yet.' })]))
  parts.push(jsx('div', { className: 'px-3 py-2 text-xs opacity-50', children: `${shortcutLabel()} opens this panel.` }))

  return jsx('div', { className: 'flex h-full flex-col overflow-y-auto', children: parts })
}

export default {
  id: PLUGIN_ID,
  name: 'Hermes Tether',
  register(ctx) {
    rest = ctx.rest
    ctx.onEvent('tool.complete', (event) => {
      if (event?.payload?.name === 'devices') notifyRefresh()
    })
    ctx.registerMany([
      {
        id: PANE_ID,
        area: 'panes',
        title: 'Tether',
        data: { placement: 'right', dock: { pane: 'files', pos: 'center' } },
        render: () => jsx(TetherPane, { ctx })
      },
      {
        id: 'tether-palette',
        area: PALETTE_AREA,
        data: { id: 'tether.open', label: 'Open Hermes Tether', keywords: ['tether', 'devices', 'remote', 'paired'], run: openPanel }
      },
      {
        id: 'tether-keybind',
        area: KEYBINDS_AREA,
        data: { id: 'tether.openPanel', label: 'Open Hermes Tether', category: 'view', defaults: [SHORTCUT], run: openPanel }
      }
    ])
  }
}
