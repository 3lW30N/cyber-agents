import { useEffect, useRef, useState, useCallback } from 'react'
import type { AgentEvent } from '../types/simulation'

const API_BASE = (import.meta.env.VITE_API_URL as string | undefined) || '/api'
const MAX_RECONNECT_ATTEMPTS = 5
const RECONNECT_DELAY_MS = 2000

interface UseSSEResult {
  events: AgentEvent[]
  isConnected: boolean
  error: string | null
  clearEvents: () => void
}

export function useSSE(sessionId: string | null): UseSSEResult {
  const [events, setEvents] = useState<AgentEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const esRef = useRef<EventSource | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const isMountedRef = useRef(true)

  const clearEvents = useCallback(() => {
    setEvents([])
  }, [])

  const connect = useCallback(() => {
    if (!sessionId || !isMountedRef.current) return

    const url = `${API_BASE}/scenarios/stream/${sessionId}`

    // Close existing connection if any
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }

    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => {
      if (!isMountedRef.current) return
      setIsConnected(true)
      setError(null)
      reconnectAttemptsRef.current = 0
    }

    es.onmessage = (event: MessageEvent) => {
      if (!isMountedRef.current) return
      try {
        const parsed: AgentEvent = JSON.parse(event.data as string)
        setEvents((prev) => [...prev, parsed])
      } catch (err) {
        console.error('Failed to parse SSE event:', err, event.data)
      }
    }

    es.addEventListener('agent_event', (event: MessageEvent) => {
      if (!isMountedRef.current) return
      try {
        const parsed: AgentEvent = JSON.parse(event.data as string)
        setEvents((prev) => [...prev, parsed])
      } catch (err) {
        console.error('Failed to parse agent_event SSE:', err, event.data)
      }
    })

    es.onerror = () => {
      if (!isMountedRef.current) return
      setIsConnected(false)
      es.close()
      esRef.current = null

      if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        reconnectAttemptsRef.current += 1
        const delay = RECONNECT_DELAY_MS * reconnectAttemptsRef.current
        setError(
          `Connection lost. Reconnecting in ${delay / 1000}s (attempt ${reconnectAttemptsRef.current}/${MAX_RECONNECT_ATTEMPTS})...`
        )
        reconnectTimerRef.current = setTimeout(() => {
          if (isMountedRef.current) connect()
        }, delay)
      } else {
        setError('Connection failed after maximum retry attempts. Please reset the simulation.')
      }
    }
  }, [sessionId])

  useEffect(() => {
    isMountedRef.current = true

    if (sessionId) {
      reconnectAttemptsRef.current = 0
      connect()
    } else {
      if (esRef.current) {
        esRef.current.close()
        esRef.current = null
      }
      setIsConnected(false)
    }

    return () => {
      isMountedRef.current = false
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current)
        reconnectTimerRef.current = null
      }
      if (esRef.current) {
        esRef.current.close()
        esRef.current = null
      }
    }
  }, [sessionId, connect])

  return { events, isConnected, error, clearEvents }
}
