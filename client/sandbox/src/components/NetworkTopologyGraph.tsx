import React, { useEffect, useRef, useState, useCallback } from 'react';

// ── Types ───────────────────────────────────────────────────────
export interface TopoNode {
  id: string;
  label: string;
  type: 'cloud' | 'firewall' | 'router' | 'switch' | 'workstation' | 'server' | 'nas' | 'siem';
  ip: string;
  os: string;
  x: number;
  y: number;
}

export interface TopoEdge {
  source: string;
  target: string;
  type: 'normal' | 'attack' | 'detection';
}

export interface AttackEvent {
  id: string;
  attack_type: string;
  source_node: string;
  target_node: string;
  severity: 'critical' | 'high' | 'medium';
  technique_id: string;
  timestamp: string;
  message: string;
}

interface Props {
  nodes: TopoNode[];
  edges: TopoEdge[];
  activeAttack: AttackEvent | null;
  detectedAlerts: AttackEvent[];
}

// ── Icon glyphs per node type ─────────────────────────────────
const NODE_ICONS: Record<string, string> = {
  cloud:       '☁',
  firewall:    '🔥',
  router:      '📡',
  switch:      '🔀',
  workstation: '💻',
  server:      '🖥',
  nas:         '💾',
  siem:        '🛡',
};

const NODE_COLORS: Record<string, string> = {
  cloud:       '#8888aa',
  firewall:    '#ff6600',
  router:      '#00aaff',
  switch:      '#aa55ff',
  workstation: '#00ff88',
  server:      '#00aaff',
  nas:         '#ffcc00',
  siem:        '#00ff88',
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ff3366',
  high:     '#ff6600',
  medium:   '#ffcc00',
};

// ── Main Component ────────────────────────────────────────────
const NetworkTopologyGraph: React.FC<Props> = ({ nodes, edges, activeAttack, detectedAlerts }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ w: 800, h: 480 });
  const [compromised, setCompromised] = useState<Set<string>>(new Set());
  const [siemFlash, setSiemFlash]     = useState(false);
  const [tooltip, setTooltip]         = useState<{ node: TopoNode; x: number; y: number } | null>(null);
  const [packetPos, setPacketPos]     = useState<number>(0);   // 0..1 along attack edge
  const [detectionPos, setDetectionPos] = useState<number>(0); // 0..1 along detection edge
  const attackAnimRef   = useRef<ReturnType<typeof setInterval> | null>(null);
  const detectAnimRef   = useRef<ReturnType<typeof setInterval> | null>(null);

  // Observe container size
  useEffect(() => {
    if (!containerRef.current) return;
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect;
      setDimensions({ w: width, h: height });
    });
    ro.observe(containerRef.current);
    return () => ro.disconnect();
  }, []);

  // Scale positions from the 1000×600 design space to actual container size
  const DESIGN_W = 1000;
  const DESIGN_H = 620;
  const scaleX = (x: number) => (x / DESIGN_W) * dimensions.w;
  const scaleY = (y: number) => (y / DESIGN_H) * dimensions.h;

  const getNode = useCallback((id: string) => nodes.find(n => n.id === id), [nodes]);

  // ── Attack animation sequence ────────────────────────────────
  useEffect(() => {
    if (!activeAttack) {
      setPacketPos(0);
      setDetectionPos(0);
      setSiemFlash(false);
      return;
    }

    let isSubscribed = true;

    function runCycle() {
      if (!isSubscribed) return;
      
      setPacketPos(0);
      setDetectionPos(0);
      const startTime = performance.now();
      const phase1Duration = 1500;

      function animPhase1(now: number) {
        if (!isSubscribed) return;
        const t = Math.min(1, (now - startTime) / phase1Duration);
        setPacketPos(t);
        
        if (t < 1) {
          requestAnimationFrame(animPhase1);
        } else {
          // Mark target as compromised
          setCompromised(prev => new Set(prev).add(activeAttack!.target_node));
          
          // Phase 2: detection signal travels src → switch → siem
          setTimeout(() => {
            if (!isSubscribed) return;
            const p2Start = performance.now();
            const phase2Duration = 1200;
            
            function animPhase2(now2: number) {
              if (!isSubscribed) return;
              const t2 = Math.min(1, (now2 - p2Start) / phase2Duration);
              setDetectionPos(t2);
              if (t2 < 1) {
                requestAnimationFrame(animPhase2);
              } else {
                setSiemFlash(true);
                setTimeout(() => {
                  if (isSubscribed) setSiemFlash(false);
                }, 1500);
                setDetectionPos(0);
                
                // Restart cycle after a delay to loop
                setTimeout(() => {
                  if (isSubscribed) runCycle();
                }, 2000);
              }
            }
            requestAnimationFrame(animPhase2);
          }, 800);
        }
      }
      requestAnimationFrame(animPhase1);
    }

    runCycle();

    return () => {
      isSubscribed = false;
    };
  }, [activeAttack]);

  // ── Interpolate a point along an edge ────────────────────────
  function lerpEdge(srcId: string, dstId: string, t: number): { x: number; y: number } | null {
    const src = getNode(srcId);
    const dst = getNode(dstId);
    if (!src || !dst) return null;
    return {
      x: scaleX(src.x) + (scaleX(dst.x) - scaleX(src.x)) * t,
      y: scaleY(src.y) + (scaleY(dst.y) - scaleY(src.y)) * t,
    };
  }

  // ── Render ────────────────────────────────────────────────────
  const attackColor = activeAttack ? (SEVERITY_COLORS[activeAttack.severity] ?? '#ff3366') : '#ff3366';
  const srcNode  = activeAttack ? getNode(activeAttack.source_node) : null;
  const dstNode  = activeAttack ? getNode(activeAttack.target_node) : null;
  const swNode   = getNode('switch');
  const siemNode = getNode('siem');

  const packetPt   = (activeAttack && packetPos   > 0 && packetPos   < 1) ? lerpEdge(activeAttack.source_node, activeAttack.target_node, packetPos)   : null;
  const detectPt   = (activeAttack && detectionPos > 0 && detectionPos < 1 && dstNode && swNode)    ? lerpEdge(activeAttack.target_node, 'siem', detectionPos)  : null;

  return (
    <div ref={containerRef} className="topology-canvas grid-bg scanline-overlay w-full h-full">
      <svg width={dimensions.w} height={dimensions.h} className="absolute inset-0">
        <defs>
          {/* Glow filters */}
          <filter id="glow-green" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <filter id="glow-red" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <filter id="glow-blue" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>

          {/* Animated attack dash */}
          <style>{`
            @keyframes dash-move { to { stroke-dashoffset: -24; } }
            .dash-anim { animation: dash-move 0.5s linear infinite; }
            @keyframes node-pulse { 0%,100%{r:18} 50%{r:26} }
          `}</style>
        </defs>

        {/* ── Normal edges ── */}
        {edges.map((e, i) => {
          const s = getNode(e.source);
          const t = getNode(e.target);
          if (!s || !t) return null;
          return (
            <line
              key={i}
              x1={scaleX(s.x)} y1={scaleY(s.y)}
              x2={scaleX(t.x)} y2={scaleY(t.y)}
              stroke="rgba(30,30,60,0.9)"
              strokeWidth={1.5}
              strokeDasharray="4 4"
            />
          );
        })}

        {/* ── Attack edge (animated dashes src→dst) ── */}
        {activeAttack && srcNode && dstNode && (
          <line
            x1={scaleX(srcNode.x)} y1={scaleY(srcNode.y)}
            x2={scaleX(dstNode.x)} y2={scaleY(dstNode.y)}
            stroke={attackColor}
            strokeWidth={2.5}
            strokeDasharray="8 4"
            strokeOpacity={0.9}
            className="dash-anim"
            filter="url(#glow-red)"
          />
        )}

        {/* ── Detection edge (dst→switch→siem) ── */}
        {activeAttack && dstNode && swNode && detectionPos > 0 && (
          <>
            <line
              x1={scaleX(dstNode.x)} y1={scaleY(dstNode.y)}
              x2={scaleX(swNode.x)}  y2={scaleY(swNode.y)}
              stroke="#00aaff" strokeWidth={2} strokeDasharray="6 3"
              strokeOpacity={0.8} className="dash-anim"
              filter="url(#glow-blue)"
            />
            {swNode && siemNode && (
              <line
                x1={scaleX(swNode.x)}  y1={scaleY(swNode.y)}
                x2={scaleX(siemNode.x)} y2={scaleY(siemNode.y)}
                stroke="#00aaff" strokeWidth={2} strokeDasharray="6 3"
                strokeOpacity={0.8} className="dash-anim"
                filter="url(#glow-blue)"
              />
            )}
          </>
        )}

        {/* ── Packet dot on attack edge ── */}
        {packetPt && (
          <circle cx={packetPt.x} cy={packetPt.y} r={5}
            fill={attackColor} filter="url(#glow-red)" opacity={0.95} />
        )}

        {/* ── Detection packet dot ── */}
        {detectPt && (
          <circle cx={detectPt.x} cy={detectPt.y} r={4}
            fill="#00aaff" filter="url(#glow-blue)" opacity={0.9} />
        )}

        {/* ── Nodes ── */}
        {nodes.map(node => {
          const cx = scaleX(node.x);
          const cy = scaleY(node.y);
          const isAttacker   = activeAttack?.source_node === node.id;
          const isVictim     = activeAttack?.target_node === node.id;
          const isCompromised= compromised.has(node.id);
          const isSiem       = node.id === 'siem';
          const baseColor    = NODE_COLORS[node.type] ?? '#8888aa';

          const ringColor = isAttacker    ? '#ff3366'
                          : isVictim      ? '#ff6600'
                          : isCompromised ? '#ff3366'
                          : isSiem && siemFlash ? '#00aaff'
                          : 'transparent';

          const bgOpacity = isAttacker ? 0.35 : 0.15;

          return (
            <g key={node.id}
               style={{ cursor: 'pointer' }}
               onMouseEnter={() => setTooltip({ node, x: cx, y: cy })}
               onMouseLeave={() => setTooltip(null)}
            >
              {/* Ring pulse */}
              {(isAttacker || isVictim || (isSiem && siemFlash)) && (
                <circle cx={cx} cy={cy} r={30}
                  fill="none"
                  stroke={ringColor}
                  strokeWidth={1.5}
                  opacity={0.5}
                />
              )}

              {/* Node background circle */}
              <circle cx={cx} cy={cy} r={20}
                fill={baseColor}
                fillOpacity={bgOpacity}
                stroke={isCompromised ? '#ff3366' : (isSiem && siemFlash ? '#00aaff' : baseColor)}
                strokeWidth={isAttacker || isVictim ? 2.5 : 1.5}
                strokeOpacity={isAttacker || isVictim ? 1 : 0.7}
                filter={isAttacker || isVictim ? 'url(#glow-red)' : (isSiem && siemFlash ? 'url(#glow-blue)' : undefined)}
              />

              {/* Icon */}
              <text x={cx} y={cy + 6} textAnchor="middle"
                fontSize={18} style={{ userSelect: 'none', pointerEvents: 'none' }}>
                {NODE_ICONS[node.type] ?? '●'}
              </text>

              {/* Label */}
              <text x={cx} y={cy + 36} textAnchor="middle"
                fontSize={9} fill="rgba(200,210,240,0.7)"
                fontFamily="JetBrains Mono, monospace"
                style={{ pointerEvents: 'none' }}>
                {node.label}
              </text>

              {/* IP */}
              <text x={cx} y={cy + 47} textAnchor="middle"
                fontSize={8} fill="rgba(136,136,170,0.6)"
                fontFamily="JetBrains Mono, monospace"
                style={{ pointerEvents: 'none' }}>
                {node.ip}
              </text>

              {/* Compromised indicator dot */}
              {isCompromised && (
                <circle cx={cx + 14} cy={cy - 14} r={5} fill="#ff3366" />
              )}
            </g>
          );
        })}

        {/* ── Attack tooltip popup ── */}
        {activeAttack && dstNode && (
          <foreignObject
            x={scaleX(dstNode.x) + 24}
            y={scaleY(dstNode.y) - 48}
            width={200} height={90}>
            <div style={{
              background: 'rgba(13,13,31,0.95)',
              border: `1px solid ${attackColor}`,
              boxShadow: `0 0 12px ${attackColor}55`,
              borderRadius: 5,
              padding: '7px 10px',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 9,
              color: '#f0f8ff',
              lineHeight: 1.6,
            }}>
              <div style={{ color: attackColor, fontWeight: 700, marginBottom: 3 }}>
                ⚠ ATTACK DETECTED
              </div>
              <div>Type: {activeAttack.attack_type.replace(/_/g, ' ').toUpperCase()}</div>
              <div>Tech: {activeAttack.technique_id}</div>
              <div>Sev: <span style={{ color: attackColor }}>{activeAttack.severity.toUpperCase()}</span></div>
              <div style={{ color: '#8888aa' }}>{new Date(activeAttack.timestamp).toLocaleTimeString()}</div>
            </div>
          </foreignObject>
        )}

        {/* ── SIEM detection label ── */}
        {siemFlash && siemNode && (
          <foreignObject
            x={scaleX(siemNode.x) + 24}
            y={scaleY(siemNode.y) - 30}
            width={160} height={44}>
            <div style={{
              background: 'rgba(0,30,60,0.95)',
              border: '1px solid #00aaff',
              boxShadow: '0 0 16px rgba(0,170,255,0.5)',
              borderRadius: 4,
              padding: '5px 9px',
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 9,
              color: '#00aaff',
              fontWeight: 700,
            }}>
              🛡 Alert Forwarded to SIEM<br/>
              <span style={{ color: '#8888aa', fontWeight: 400 }}>Processing…</span>
            </div>
          </foreignObject>
        )}
      </svg>

      {/* ── Hover tooltip ── */}
      {tooltip && (
        <div style={{
          position: 'absolute',
          left: tooltip.x + 26,
          top:  tooltip.y - 20,
          background: 'rgba(10,10,20,0.97)',
          border: '1px solid rgba(0,170,255,0.4)',
          borderRadius: 5,
          padding: '7px 11px',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 10,
          color: '#f0f8ff',
          zIndex: 20,
          pointerEvents: 'none',
          lineHeight: 1.7,
          minWidth: 160,
        }}>
          <div style={{ color: '#00aaff', fontWeight: 600, marginBottom: 2 }}>{tooltip.node.label}</div>
          <div style={{ color: '#8888aa' }}>IP: {tooltip.node.ip}</div>
          <div style={{ color: '#8888aa' }}>OS: {tooltip.node.os}</div>
          <div style={{ color: '#8888aa' }}>Type: {tooltip.node.type}</div>
          {compromised.has(tooltip.node.id) && (
            <div style={{ color: '#ff3366', marginTop: 3 }}>⚠ COMPROMISED</div>
          )}
        </div>
      )}
    </div>
  );
};

export default NetworkTopologyGraph;
