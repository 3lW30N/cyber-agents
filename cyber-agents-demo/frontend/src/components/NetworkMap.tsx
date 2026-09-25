import { useEffect, useRef, useCallback } from 'react'
import * as d3 from 'd3'
import type { AgentAction, NetworkState as HookNetworkState } from '../hooks/useSimulation'

interface NodeDatum extends d3.SimulationNodeDatum {
  id: string
  hostname: string
  ip: string
  os: string
  services: string[]
  patch_level: number
  compromise_status: string
  is_isolated: boolean
  importance: number
}

interface LinkDatum extends d3.SimulationLinkDatum<NodeDatum> {
  source: string | NodeDatum
  target: string | NodeDatum
  blocked: boolean
}

interface NetworkMapProps {
  networkState: HookNetworkState | null
  events: AgentAction[]
  activeEvent: AgentAction | null
}

const HOST_IMPORTANCE: Record<string, number> = {
  'domain-controller': 1.8,
  'db-server': 1.4,
  'web-server': 1.3,
  'mail-server': 1.1,
  'internal-workstation': 1.0,
}

const CONNECTION_MAP: Record<string, string[]> = {
  'web-server': ['db-server', 'mail-server', 'internal-workstation'],
  'db-server': ['web-server'],
  'mail-server': ['web-server', 'internal-workstation'],
  'internal-workstation': ['domain-controller', 'web-server', 'mail-server'],
  'domain-controller': ['internal-workstation', 'db-server'],
}

function statusColor(status: string): string {
  switch (status) {
    case 'owned':
    case 'compromised':
      return '#ef4444'
    case 'foothold':
    case 'partially_compromised':
      return '#eab308'
    default:
      return '#3b82f6'
  }
}

function statusGlow(status: string): string {
  switch (status) {
    case 'owned':
    case 'compromised':
      return 'url(#glow-red)'
    case 'foothold':
    case 'partially_compromised':
      return 'url(#glow-yellow)'
    default:
      return 'none'
  }
}

export default function NetworkMap({ networkState, events, activeEvent }: NetworkMapProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const simulationRef = useRef<d3.Simulation<NodeDatum, LinkDatum> | null>(null)
  const nodesRef = useRef<NodeDatum[]>([])
  const linksRef = useRef<LinkDatum[]>([])

  const buildGraph = useCallback(() => {
    const hosts = networkState?.hosts ?? {}
    const hostNames = Object.keys(hosts).length > 0
      ? Object.keys(hosts)
      : ['web-server', 'db-server', 'mail-server', 'internal-workstation', 'domain-controller']

    const nodes: NodeDatum[] = hostNames.map((hn) => {
      const h = hosts[hn]
      return {
        id: hn,
        hostname: hn,
        ip: h?.ip ?? '10.0.0.x',
        os: h?.os ?? 'Unknown',
        services: (h?.services ?? []) as unknown as string[],
        patch_level: h?.patch_level ?? 5,
        compromise_status: h?.compromise_status ?? 'clean',
        is_isolated: h?.is_isolated ?? false,
        importance: HOST_IMPORTANCE[hn] ?? 1.0,
      }
    })

    const links: LinkDatum[] = []
    hostNames.forEach((src) => {
      const targets = CONNECTION_MAP[src] ?? []
      targets.forEach((dst) => {
        if (hostNames.includes(dst)) {
          links.push({ source: src, target: dst, blocked: false })
        }
      })
    })

    return { nodes, links }
  }, [networkState])

  const animatePacket = useCallback(
    (svgEl: SVGSVGElement, srcId: string, dstId: string, color: string) => {
      const svg = d3.select(svgEl)
      const srcNode = nodesRef.current.find((n) => n.id === srcId)
      const dstNode = nodesRef.current.find((n) => n.id === dstId)
      if (!srcNode || !dstNode) return
      if (srcNode.x == null || srcNode.y == null || dstNode.x == null || dstNode.y == null) return

      const packet = svg
        .select<SVGGElement>('g.packets')
        .append('circle')
        .attr('r', 5)
        .attr('fill', color)
        .attr('cx', srcNode.x!)
        .attr('cy', srcNode.y!)
        .style('filter', `drop-shadow(0 0 4px ${color})`)

      packet
        .transition()
        .duration(900)
        .ease(d3.easeLinear)
        .attr('cx', dstNode.x!)
        .attr('cy', dstNode.y!)
        .on('end', () => packet.remove())
    },
    []
  )

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return
    const container = containerRef.current
    const { width, height } = container.getBoundingClientRect()
    const W = width || 600
    const H = height || 400

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', W).attr('height', H)

    // Defs: gradients + filters
    const defs = svg.append('defs')

    const makeGlow = (id: string, col: string) => {
      const f = defs.append('filter').attr('id', id).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%')
      f.append('feGaussianBlur').attr('in', 'SourceGraphic').attr('stdDeviation', 4).attr('result', 'blur')
      const merge = f.append('feMerge')
      merge.append('feMergeNode').attr('in', 'blur')
      merge.append('feMergeNode').attr('in', 'SourceGraphic')
      // tint
      defs
        .append('filter')
        .attr('id', `${id}-tint`)
        .append('feColorMatrix')
        .attr('type', 'matrix')
        .attr('values', col === '#ef4444'
          ? '2 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0'
          : '2 0 0 0 0  1.5 1.5 0 0 0  0 0 0 0 0  0 0 0 1 0')
    }
    makeGlow('glow-red', '#ef4444')
    makeGlow('glow-yellow', '#eab308')
    makeGlow('glow-blue', '#3b82f6')

    // Background grid
    svg.append('rect').attr('width', W).attr('height', H).attr('fill', '#0a0e1a')
    const gridG = svg.append('g').attr('class', 'grid').attr('opacity', 0.07)
    for (let x = 0; x < W; x += 40) {
      gridG.append('line').attr('x1', x).attr('x2', x).attr('y1', 0).attr('y2', H).attr('stroke', '#4b9eff').attr('stroke-width', 0.5)
    }
    for (let y = 0; y < H; y += 40) {
      gridG.append('line').attr('x1', 0).attr('x2', W).attr('y1', y).attr('y2', y).attr('stroke', '#4b9eff').attr('stroke-width', 0.5)
    }

    const { nodes, links } = buildGraph()
    nodesRef.current = nodes
    linksRef.current = links

    const simulation = d3
      .forceSimulation<NodeDatum>(nodes)
      .force('link', d3.forceLink<NodeDatum, LinkDatum>(links).id((d) => d.id).distance(110).strength(0.7))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide(50))

    simulationRef.current = simulation

    const linkG = svg.append('g').attr('class', 'links')
    const linkSel = linkG
      .selectAll<SVGLineElement, LinkDatum>('line')
      .data(links)
      .join('line')
      .attr('stroke', '#334155')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', (d) => (d.blocked ? '6,3' : 'none'))
      .attr('opacity', 0.7)

    // Firewall icons on blocked edges
    const fwG = svg.append('g').attr('class', 'firewalls')
    linksRef.current.filter((l) => l.blocked).forEach((l) => {
      const src = nodes.find((n) => n.id === (typeof l.source === 'string' ? l.source : l.source.id))
      const dst = nodes.find((n) => n.id === (typeof l.target === 'string' ? l.target : l.target.id))
      if (!src || !dst || src.x == null || src.y == null || dst.x == null || dst.y == null) return
      const mx = ((src.x!) + (dst.x!)) / 2
      const my = ((src.y!) + (dst.y!)) / 2
      fwG.append('text')
        .attr('x', mx)
        .attr('y', my)
        .attr('text-anchor', 'middle')
        .attr('dominant-baseline', 'middle')
        .attr('font-size', 14)
        .attr('fill', '#fb923c')
        .text('🔥')
    })

    svg.append('g').attr('class', 'packets')

    const nodeG = svg.append('g').attr('class', 'nodes')

    const nodeSel = nodeG
      .selectAll<SVGGElement, NodeDatum>('g.node')
      .data(nodes, (d) => d.id)
      .join('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(
        d3
          .drag<SVGGElement, NodeDatum>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart()
            d.fx = d.x
            d.fy = d.y
          })
          .on('drag', (event, d) => {
            d.fx = event.x
            d.fy = event.y
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0)
            d.fx = null
            d.fy = null
          }) as d3.DragBehavior<SVGGElement, NodeDatum, NodeDatum | d3.SubjectPosition>
      )

    // Outer pulse ring for compromised nodes
    nodeSel
      .append('circle')
      .attr('class', 'pulse')
      .attr('r', (d) => {
        const base = 22 * d.importance
        return d.compromise_status !== 'clean' && d.compromise_status !== 'none' ? base + 6 : 0
      })
      .attr('fill', 'none')
      .attr('stroke', (d) => statusColor(d.compromise_status))
      .attr('stroke-width', 2)
      .attr('opacity', 0.5)

    // Main circle
    nodeSel
      .append('circle')
      .attr('class', 'body')
      .attr('r', (d) => 22 * d.importance)
      .attr('fill', (d) => (d.is_isolated ? '#374151' : statusColor(d.compromise_status)))
      .attr('fill-opacity', (d) => (d.is_isolated ? 0.6 : 0.85))
      .attr('stroke', (d) => (d.is_isolated ? '#6b7280' : statusColor(d.compromise_status)))
      .attr('stroke-width', 2)
      .style('filter', (d) => statusGlow(d.compromise_status))

    // Icon text
    nodeSel
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .attr('font-size', (d) => 16 * d.importance)
      .attr('fill', '#fff')
      .attr('dy', (d) => (d.is_isolated ? -2 : 0))
      .text((d) => {
        if (d.is_isolated) return '🚫'
        if (d.compromise_status === 'owned' || d.compromise_status === 'compromised') return '💀'
        if (d.compromise_status === 'foothold' || d.compromise_status === 'partially_compromised') return '⚠'
        if (d.hostname === 'domain-controller') return '🏛'
        if (d.hostname === 'db-server') return '🗄'
        if (d.hostname === 'mail-server') return '✉'
        if (d.hostname === 'web-server') return '🌐'
        return '💻'
      })

    // Labels
    nodeSel
      .append('text')
      .attr('class', 'label')
      .attr('text-anchor', 'middle')
      .attr('dy', (d) => 22 * d.importance + 14)
      .attr('font-size', 11)
      .attr('fill', '#94a3b8')
      .text((d) => d.hostname)

    nodeSel
      .append('text')
      .attr('class', 'ip')
      .attr('text-anchor', 'middle')
      .attr('dy', (d) => 22 * d.importance + 26)
      .attr('font-size', 9)
      .attr('fill', '#475569')
      .text((d) => d.ip)

    // Tooltip
    const tooltip = d3
      .select(container)
      .append('div')
      .attr('class', 'nmap-tooltip')
      .style('position', 'absolute')
      .style('background', 'rgba(15,23,42,0.97)')
      .style('border', '1px solid #334155')
      .style('border-radius', '6px')
      .style('padding', '10px 14px')
      .style('font-size', '12px')
      .style('color', '#e2e8f0')
      .style('pointer-events', 'none')
      .style('display', 'none')
      .style('z-index', '100')
      .style('max-width', '220px')
      .style('line-height', '1.6')

    nodeSel
      .on('mouseenter', (event: MouseEvent, d: NodeDatum) => {
        const svcList = Array.isArray(d.services)
          ? d.services
              .map((s) => (typeof s === 'string' ? s : (s as { name?: string; port?: number })?.name ?? String(s)))
              .join(', ')
          : ''
        tooltip
          .style('display', 'block')
          .html(
            `<div style="font-weight:700;color:#60a5fa;margin-bottom:4px">${d.hostname}</div>
             <div><span style="color:#64748b">IP: </span>${d.ip}</div>
             <div><span style="color:#64748b">OS: </span>${d.os}</div>
             <div><span style="color:#64748b">Services: </span>${svcList || 'N/A'}</div>
             <div><span style="color:#64748b">Patch: </span>${d.patch_level}/10</div>
             <div><span style="color:#64748b">Status: </span><span style="color:${statusColor(d.compromise_status)}">${d.compromise_status}</span></div>
             ${d.is_isolated ? '<div style="color:#fb923c;margin-top:4px">ISOLATED</div>' : ''}`
          )
      })
      .on('mousemove', (event: MouseEvent) => {
        const rect = container.getBoundingClientRect()
        tooltip
          .style('left', `${event.clientX - rect.left + 12}px`)
          .style('top', `${event.clientY - rect.top - 20}px`)
      })
      .on('mouseleave', () => {
        tooltip.style('display', 'none')
      })

    simulation.on('tick', () => {
      linkSel
        .attr('x1', (d) => ((d.source as NodeDatum).x ?? 0))
        .attr('y1', (d) => ((d.source as NodeDatum).y ?? 0))
        .attr('x2', (d) => ((d.target as NodeDatum).x ?? 0))
        .attr('y2', (d) => ((d.target as NodeDatum).y ?? 0))

      nodeSel.attr('transform', (d) => `translate(${d.x ?? 0},${d.y ?? 0})`)
    })

    // Pulse animation via CSS keyframes injected once
    if (!document.getElementById('nmap-keyframes')) {
      const style = document.createElement('style')
      style.id = 'nmap-keyframes'
      style.textContent = `
        @keyframes nmapPulse {
          0% { r: 26; opacity: 0.6; }
          50% { r: 34; opacity: 0.2; }
          100% { r: 26; opacity: 0.6; }
        }
        .node circle.pulse { animation: nmapPulse 1.6s ease-in-out infinite; }
      `
      document.head.appendChild(style)
    }

    // Legend
    const legendData = [
      { color: '#3b82f6', label: 'Clean' },
      { color: '#eab308', label: 'Foothold' },
      { color: '#ef4444', label: 'Owned' },
      { color: '#374151', label: 'Isolated' },
    ]
    const lg = svg.append('g').attr('transform', `translate(14,${H - 80})`)
    legendData.forEach((item, i) => {
      lg.append('circle').attr('cx', 8).attr('cy', i * 18).attr('r', 6).attr('fill', item.color)
      lg.append('text').attr('x', 20).attr('y', i * 18 + 4).attr('font-size', 11).attr('fill', '#94a3b8').text(item.label)
    })

    return () => {
      simulation.stop()
      tooltip.remove()
    }
  }, [buildGraph])

  // React to state changes: smooth color transitions
  useEffect(() => {
    if (!svgRef.current || !networkState) return
    const svg = d3.select(svgRef.current)
    const hosts = networkState.hosts ?? {}

    svg
      .selectAll<SVGGElement, NodeDatum>('g.node')
      .each(function (d) {
        const h = hosts[d.id]
        if (!h) return
        d.compromise_status = h.compromise_status
        d.is_isolated = h.is_isolated
        const color = statusColor(h.compromise_status)
        d3.select(this)
          .select('circle.body')
          .transition()
          .duration(600)
          .attr('fill', h.is_isolated ? '#374151' : color)
          .attr('stroke', h.is_isolated ? '#6b7280' : color)
          .style('filter', statusGlow(h.compromise_status))
        d3.select(this)
          .select('circle.pulse')
          .attr('stroke', color)
          .attr('r', h.compromise_status !== 'clean' && h.compromise_status !== 'none' ? 28 : 0)
        d3.select(this)
          .select('text')
          .text(() => {
            if (h.is_isolated) return '🚫'
            if (h.compromise_status === 'owned' || h.compromise_status === 'compromised') return '💀'
            if (h.compromise_status === 'foothold' || h.compromise_status === 'partially_compromised') return '⚠'
            if (d.hostname === 'domain-controller') return '🏛'
            if (d.hostname === 'db-server') return '🗄'
            if (d.hostname === 'mail-server') return '✉'
            if (d.hostname === 'web-server') return '🌐'
            return '💻'
          })
      })
  }, [networkState])

  // Animate attack packets on new events
  useEffect(() => {
    if (!activeEvent || !svgRef.current) return
    const target = activeEvent.target
    if (!target) return

    const team = activeEvent.team
    const color = team === 'red' ? '#ef4444' : '#22c55e'

    const src = team === 'red' ? 'web-server' : 'internal-workstation'
    if (src !== target) {
      animatePacket(svgRef.current, src, target, color)
    }
  }, [activeEvent, animatePacket])

  // Resize observer
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const ro = new ResizeObserver(() => {
      // Rebuild on resize
      if (svgRef.current && el) {
        const { width, height } = el.getBoundingClientRect()
        d3.select(svgRef.current).attr('width', width).attr('height', height)
        if (simulationRef.current) {
          simulationRef.current
            .force('center', d3.forceCenter(width / 2, height / 2))
            .alpha(0.3)
            .restart()
        }
      }
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  return (
    <div ref={containerRef} className="relative w-full h-full" style={{ background: '#0a0e1a' }}>
      <svg ref={svgRef} style={{ display: 'block', width: '100%', height: '100%' }} />
    </div>
  )
}
