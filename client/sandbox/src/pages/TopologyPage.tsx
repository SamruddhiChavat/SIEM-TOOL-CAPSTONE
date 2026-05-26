import React, { useEffect, useRef, useState, useCallback } from 'react';
import { OrgNode, DEPT_ZONES } from '../data/orgTopology';
import { LiveAttack } from '../App';

interface Props {
  nodes: OrgNode[];
  edges: { source: string; target: string }[];
  attacks: LiveAttack[];
  compromised: Set<string>;
  contained: Set<string>;
  selectedAttackerId?: string;
  selectedTargetId?: string;
  onSelectAttacker?: (id: string) => void;
  onSelectTarget?: (id: string) => void;
}

const ICONS: Record<string, string> = {
  internet:'🌐', fw:'🔥', router:'📡', switch:'🔀', vpn:'🔐',
  workstation:'💻', server:'🖥', nas:'💾', printer:'🖨',
  siem:'🛡', edr:'🔬', attacker:'☠',
};

const NODE_COLOR: Record<string, string> = {
  internet:'#5599cc', fw:'#ff7722', router:'#00aaff', switch:'#9966ee',
  vpn:'#00ccff', workstation:'#00dd77', server:'#3399dd', nas:'#ffcc00',
  printer:'#778899', siem:'#00ff88', edr:'#00ffcc', attacker:'#ff3366',
};

const DEPT_COLOR: Record<string, string> = {
  INTERNET:'#5599cc', ATTACKER:'#ff3366', PERIMETER:'#ff8822',
  IT:'#00aaff', ENGINEERING:'#00dd77', HR:'#cc66ff',
  FINANCE:'#ffcc00', EXECUTIVE:'#ff9933', SECURITY:'#00ffcc',
};

function nodeR(n: OrgNode) {
  if (n.external) return 31;
  if (n.type === 'siem' || n.type === 'router') return 29;
  if (n.type === 'fw' || n.type === 'switch' || n.type === 'vpn') return 25;
  if (n.type === 'server' || n.type === 'nas') return 23;
  return 21;
}

const MIN_ZOOM = 0.1, MAX_ZOOM = 4;

// Compute zoom+pan to fit all nodes in the viewport with padding
function calcFit(nodes: OrgNode[], vpW: number, vpH: number) {
  if (!nodes.length) return { zoom: 0.5, pan: { x: 20, y: 20 } };
  const PAD = 52;
  const r = (n: OrgNode) => n.external ? 31 : 29;
  const xs = nodes.map(n => [n.x - r(n), n.x + r(n)]).flat();
  const ys = nodes.map(n => [n.y - r(n) - 48, n.y + r(n) + 48]).flat();
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const cw = maxX - minX, ch = maxY - minY;
  const z = Math.min(
    Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, (vpW - PAD * 2) / cw)),
    Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, (vpH - PAD * 2) / ch))
  );
  return {
    zoom: z,
    pan: { x: PAD - minX * z, y: PAD - minY * z },
  };
}

export default function TopologyPage({ nodes, edges, attacks, compromised, contained, selectedAttackerId, selectedTargetId, onSelectAttacker, onSelectTarget }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const [vpW, setVpW] = useState(1200);
  const [vpH, setVpH] = useState(700);
  const [zoom, setZoom] = useState(0.4);
  const [pan, setPan]   = useState({ x: 20, y: 20 });
  const isPanning = useRef(false);
  const lastMouse = useRef({ x: 0, y: 0 });
  const [tooltip, setTooltip] = useState<{ node: OrgNode; sx: number; sy: number } | null>(null);
  const fittedOnce = useRef(false);

  // Smooth packet animation position (0..1 per attack)
  const [packetT, setPacketT] = useState<Record<string, number>>({});
  const rafRef = useRef<number>(0);
  const lastTs = useRef<number>(0);

  const fitToScreen = useCallback((w: number, h: number) => {
    const f = calcFit(nodes, w, h);
    setZoom(f.zoom);
    setPan(f.pan);
  }, [nodes]);

  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver(e => {
      const w = e[0].contentRect.width;
      const h = e[0].contentRect.height;
      setVpW(w); setVpH(h);
      if (!fittedOnce.current) { fittedOnce.current = true; fitToScreen(w, h); }
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [fitToScreen]);

  // rAF-based packet animation — advances t continuously and wraps
  useEffect(() => {
    const SPEED = 0.18; // canvas units per ms × 1000
    function frame(ts: number) {
      const dt = ts - (lastTs.current || ts);
      lastTs.current = ts;
      setPacketT(prev => {
        const next: Record<string, number> = {};
        attacks.filter(a => a.status !== 'contained').forEach(a => {
          const edgeCount = Math.max(1, a.path.length - 1);
          const t = ((prev[a.id] ?? 0) + (dt * SPEED) / (edgeCount * 400)) % 1;
          next[a.id] = t;
        });
        // keep contained ones at 0
        attacks.filter(a => a.status === 'contained').forEach(a => { next[a.id] = 0; });
        return { ...prev, ...next };
      });
      rafRef.current = requestAnimationFrame(frame);
    }
    rafRef.current = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(rafRef.current);
  }, [attacks]);

  // ── Pan via pointer capture (works even if cursor leaves element) ──
  const onPointerDown = useCallback((e: React.PointerEvent) => {
    if ((e.target as Element).closest('[data-node]')) return;
    isPanning.current = true;
    lastMouse.current = { x: e.clientX, y: e.clientY };
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    if (!isPanning.current) return;
    const dx = e.clientX - lastMouse.current.x;
    const dy = e.clientY - lastMouse.current.y;
    lastMouse.current = { x: e.clientX, y: e.clientY };
    setPan(p => ({ x: p.x + dx, y: p.y + dy }));
  }, []);

  const onPointerUp = useCallback((e: React.PointerEvent) => {
    isPanning.current = false;
    (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
  }, []);

  // ── Wheel zoom — gentle step, anchored to cursor ──
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const handler = (e: WheelEvent) => {
      e.preventDefault();
      // Gentle step: 6% per tick
      const factor = e.deltaY < 0 ? 1.06 : 0.945;
      const rect = el.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;
      setZoom(z => {
        const nz = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, z * factor));
        setPan(p => ({
          x: mx - (mx - p.x) * (nz / z),
          y: my - (my - p.y) * (nz / z),
        }));
        return nz;
      });
    };
    el.addEventListener('wheel', handler, { passive: false });
    return () => el.removeEventListener('wheel', handler);
  }, []);

  const getNode = (id: string) => nodes.find(n => n.id === id);

  // Build lit sets from attack path steps
  const litNodes = new Set<string>();
  const litEdges = new Set<string>();
  attacks.filter(a => a.status !== 'contained').forEach(a => {
    a.path.forEach((id, i) => {
      litNodes.add(id);
      if (i > 0) { litEdges.add(`${a.path[i-1]}|${id}`); litEdges.add(`${id}|${a.path[i-1]}`); }
    });
  });

  // Interpolate packet world position along entire path
  function packetWorldPos(a: LiveAttack, t: number): { x: number; y: number; color: string } | null {
    if (a.path.length < 2) return null;
    const edges = a.path.length - 1;
    const globalPos = t * edges;
    const edgeIdx = Math.min(Math.floor(globalPos), edges - 1);
    const localT   = globalPos - edgeIdx;
    const src = getNode(a.path[edgeIdx]);
    const dst = getNode(a.path[edgeIdx + 1]);
    if (!src || !dst) return null;
    return {
      x: src.x + (dst.x - src.x) * localT,
      y: src.y + (dst.y - src.y) * localT,
      color: a.attackDef.color,
    };
  }

  const showTip = (node: OrgNode, e: React.MouseEvent) => {
    const r = wrapRef.current?.getBoundingClientRect();
    if (r) setTooltip({ node, sx: e.clientX - r.left, sy: e.clientY - r.top });
  };

  return (
    <div ref={wrapRef} style={{
      width:'100%', height:'100%', position:'relative', overflow:'hidden',
      background:'radial-gradient(ellipse at 40% 20%, rgba(0,15,40,0.8) 0%, #050510 75%)',
      cursor: isPanning.current ? 'grabbing' : 'grab',
      userSelect:'none', touchAction:'none',
    }}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onPointerCancel={onPointerUp}
    >
      {/* Dot-grid background that follows pan */}
      <div style={{
        position:'absolute', inset:0, pointerEvents:'none',
        backgroundImage:'radial-gradient(circle, rgba(0,150,255,0.12) 1px, transparent 1px)',
        backgroundSize:'48px 48px',
        backgroundPosition:`${pan.x % 48}px ${pan.y % 48}px`,
      }} />

      <svg width={vpW} height={vpH} style={{ position:'absolute', inset:0, overflow:'visible' }}>
        <defs>
          <filter id="fR" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="8" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <filter id="fB" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="6" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <filter id="fG" x="-60%" y="-60%" width="220%" height="220%">
            <feGaussianBlur stdDeviation="5" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
          <marker id="mR" markerWidth="9" markerHeight="9" refX="8" refY="4" orient="auto">
            <path d="M0,0 L0,8 L9,4z" fill="#ff3366" opacity="0.9"/>
          </marker>
          <marker id="mB" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M0,0 L0,8 L8,4z" fill="#334466" opacity="0.9"/>
          </marker>
          <style>{`
            @keyframes atkDash { to { stroke-dashoffset:-24; } }
            .atk { animation: atkDash .38s linear infinite; }
            @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.15} }
            .blink { animation: blink 1s ease-in-out infinite; }
            @keyframes pulseRing { 0%,100%{opacity:.4;r:36px} 50%{opacity:.9;r:46px} }
            .pr { animation: pulseRing 1.2s ease-in-out infinite; }
          `}</style>
        </defs>

        <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>

          {/* ── Dept zone backgrounds ── */}
          {DEPT_ZONES.map(z => {
            const c = DEPT_COLOR[z.dept] ?? '#4488bb';
            return (
              <g key={z.dept}>
                <rect x={z.x} y={z.y} width={z.w} height={z.h} rx={10}
                  fill={`${c}07`} stroke={c}
                  strokeWidth={z.dashed ? 1.5 : 1}
                  strokeOpacity={z.dashed ? 0.55 : 0.2}
                  strokeDasharray={z.dashed ? '10 6' : undefined}
                />
                {/* Label pill */}
                <rect x={z.x+12} y={z.y+10} width={z.label.length*7.4+18} height={20} rx={5}
                  fill={`${c}20`} stroke={c} strokeWidth={0.6} strokeOpacity={0.5}
                />
                <text x={z.x+21} y={z.y+24}
                  fontSize={9.5} fontFamily="'Orbitron',monospace" fontWeight={700}
                  fill={c} fillOpacity={0.95} letterSpacing={1}>
                  {z.label}
                </text>
              </g>
            );
          })}

          {/* ── Edges — subtle dotted, uniform color ── */}
          {edges.map((e, i) => {
            const s = getNode(e.source), t = getNode(e.target);
            if (!s || !t) return null;
            const lit = litEdges.has(`${e.source}|${e.target}`);
            return (
              <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                stroke={lit ? '#ff3366' : '#4a6080'}
                strokeWidth={lit ? 2.5 : 1.5}
                strokeDasharray={lit ? '10 5' : '3 10'}
                strokeOpacity={lit ? 0.9 : 0.5}
                strokeLinecap="round"
                className={lit ? 'atk' : undefined}
                markerEnd={lit ? 'url(#mR)' : 'url(#mB)'}
                filter={lit ? 'url(#fR)' : undefined}
              />
            );
          })}

          {/* Attacker → Internet edges */}
          {attacks.filter(a => a.status !== 'contained').map(a => {
            const atk = getNode(a.attackerId), inet = getNode('internet');
            if (!atk || !inet) return null;
            return (
              <line key={`al-${a.id}`}
                x1={atk.x} y1={atk.y} x2={inet.x} y2={inet.y}
                stroke="#ff3366" strokeWidth={2.5} strokeDasharray="9 5"
                strokeOpacity={0.88} className="atk"
                filter="url(#fR)" markerEnd="url(#mR)"
              />
            );
          })}

          {/* ── Nodes ── */}
          {nodes.map(node => {
            const r = nodeR(node);
            const bc  = NODE_COLOR[node.type] ?? '#8888aa';
            const dc  = DEPT_COLOR[node.dept]  ?? '#8888aa';
            const isAtk = attacks.some(a => a.attackerId === node.id && a.status !== 'contained');
            const isVic = attacks.some(a => a.targetId   === node.id && a.status !== 'contained');
            const isCmp = compromised.has(node.id);
            const isCon = contained.has(node.id);
            const isSiem = node.id === 'siem';

            const stroke = isCon ? '#00aaff' : isCmp ? '#ff3366' : isAtk ? '#ff3366' : isVic ? '#ff8822' : isSiem ? '#00ff88' : dc;
            const glow   = isAtk||isCmp ? 'url(#fR)' : isCon ? 'url(#fB)' : isSiem ? 'url(#fG)' : undefined;
            const sw     = isAtk||isVic ? 3 : isCon ? 2.5 : 1.8;

            const isSelAtk = node.id === selectedAttackerId;
            const isSelTgt = node.id === selectedTargetId;

            return (
              <g key={node.id} data-node={node.id} style={{ cursor:'pointer' }}
                onMouseEnter={e => showTip(node, e)} onMouseLeave={() => setTooltip(null)}
                onClick={() => {
                  if (node.type === 'attacker') onSelectAttacker?.(node.id);
                  else if (!node.external && node.type !== 'internet') onSelectTarget?.(node.id);
                }}
              >

                {/* Selection ring — attacker = red, target = cyan */}
                {isSelAtk && (
                  <circle cx={node.x} cy={node.y} r={r+18}
                    fill="none" stroke="#ff3366" strokeWidth={2.5}
                    strokeDasharray="6 3" opacity={0.9}
                  />
                )}
                {isSelTgt && (
                  <circle cx={node.x} cy={node.y} r={r+18}
                    fill="none" stroke="#00aaff" strokeWidth={2.5}
                    strokeDasharray="6 3" opacity={0.9}
                  />
                )}

                {/* Pulse ring */}
                {(isAtk || isVic || (isCmp && !isCon)) && (
                  <circle cx={node.x} cy={node.y} r={r+14}
                    fill="none" stroke={isAtk ? '#ff3366' : '#ff8822'}
                    strokeWidth={1.5} className="pr"
                  />
                )}

                {/* Glow halo */}
                <circle cx={node.x} cy={node.y} r={r+6}
                  fill={stroke} fillOpacity={0.07} filter={glow}
                />

                {/* Node body */}
                <circle cx={node.x} cy={node.y} r={r}
                  fill={bc} fillOpacity={node.external ? 0.22 : 0.13}
                  stroke={stroke} strokeWidth={sw} strokeOpacity={isAtk||isVic ? 1 : 0.85}
                />

                {/* Icon */}
                <text x={node.x} y={node.y + r*0.38} textAnchor="middle" fontSize={r*1.15}
                  style={{ userSelect:'none', pointerEvents:'none' }}>
                  {ICONS[node.type] ?? '●'}
                </text>

                {/* Label */}
                <text x={node.x} y={node.y+r+23} textAnchor="middle" fontSize={16.5}
                  fontFamily="'JetBrains Mono',monospace"
                  fill={stroke} fillOpacity={0.95}
                  style={{ pointerEvents:'none' }}>
                  {node.label}
                </text>

                {/* IP */}
                <text x={node.x} y={node.y+r+42} textAnchor="middle" fontSize={14}
                  fontFamily="'JetBrains Mono',monospace" fill="#44446a"
                  style={{ pointerEvents:'none' }}>
                  {node.ip}
                </text>

                {/* Badges */}
                {isCmp && !isCon && (
                  <circle cx={node.x+r*0.75} cy={node.y-r*0.75} r={6.5}
                    fill="#ff3366" className="blink"
                  />
                )}
                {isCon && (
                  <text x={node.x} y={node.y-r-14} textAnchor="middle"
                    fontSize={14} fontFamily="'Orbitron',monospace" fontWeight={700} fill="#00aaff"
                    style={{ pointerEvents:'none' }}>
                    🔒 ISOLATED
                  </text>
                )}
              </g>
            );
          })}

          {/* ── Smooth attack packets (rAF) ── */}
          {attacks.filter(a => a.status !== 'contained').map(a => {
            const t   = packetT[a.id] ?? 0;
            const pos = packetWorldPos(a, t);
            if (!pos) return null;
            const c = a.attackDef.color;

            // Which edge segment are we on?
            const edgeCount = a.path.length - 1;
            const gPos = t * edgeCount;
            const eIdx = Math.min(Math.floor(gPos), edgeCount - 1);
            const hopLabel = `${a.path[eIdx]} → ${a.path[eIdx+1] ?? '...'}`;

            return (
              <g key={`pkt-${a.id}`}>
                {/* Glow halo */}
                <circle cx={pos.x} cy={pos.y} r={16} fill={c} fillOpacity={0.12} filter="url(#fR)"/>
                {/* Core packet dot */}
                <circle cx={pos.x} cy={pos.y} r={8} fill={c} filter="url(#fR)"/>
                {/* Inner bright dot */}
                <circle cx={pos.x} cy={pos.y} r={4} fill="#ffffff" fillOpacity={0.8}/>
                {/* Tail */}
                {eIdx >= 0 && (() => {
                  const src = getNode(a.path[eIdx]);
                  const dst = getNode(a.path[eIdx+1]);
                  if (!src || !dst) return null;
                  const localT = gPos - eIdx;
                  const tailT  = Math.max(0, localT - 0.25);
                  const tx = src.x + (dst.x - src.x) * tailT;
                  const ty = src.y + (dst.y - src.y) * tailT;
                  return (
                    <line x1={tx} y1={ty} x2={pos.x} y2={pos.y}
                      stroke={c} strokeWidth={3} strokeOpacity={0.35}
                      strokeLinecap="round"
                    />
                  );
                })()}
                {/* Hop label */}
                <rect x={pos.x+14} y={pos.y-13} width={160} height={24} rx={5}
                  fill="rgba(5,5,16,0.92)" stroke={c} strokeWidth={0.8}
                />
                <text x={pos.x+22} y={pos.y+4} fontSize={9.5} fill={c}
                  fontFamily="'JetBrains Mono',monospace">
                  {a.attackDef.icon} {hopLabel.slice(0,22)}
                </text>
              </g>
            );
          })}
        </g>
      </svg>

      {/* Tooltip */}
      {tooltip && (
        <div style={{
          position:'absolute', left:Math.min(tooltip.sx+14, vpW-215), top:Math.max(4, tooltip.sy-10),
          background:'rgba(4,4,16,0.98)', border:`1px solid ${DEPT_COLOR[tooltip.node.dept] ?? '#00aaff'}55`,
          borderRadius:8, padding:'10px 14px', zIndex:100, pointerEvents:'none',
          fontFamily:"'JetBrains Mono',monospace", fontSize:11, color:'#ddeeff',
          lineHeight:1.8, minWidth:210,
          boxShadow:'0 8px 40px rgba(0,0,0,0.8)',
        }}>
          <div style={{ color:DEPT_COLOR[tooltip.node.dept]??'#00aaff', fontWeight:700, fontSize:12, marginBottom:5 }}>
            {ICONS[tooltip.node.type]} {tooltip.node.label}
          </div>
          <div><span style={{color:'#44446a'}}>IP:   </span>{tooltip.node.ip}</div>
          <div><span style={{color:'#44446a'}}>OS:   </span>{tooltip.node.os}</div>
          <div><span style={{color:'#44446a'}}>Dept: </span>
            <span style={{color:DEPT_COLOR[tooltip.node.dept]??'#c8d1d9'}}>{tooltip.node.dept}</span>
          </div>
          {compromised.has(tooltip.node.id) && !contained.has(tooltip.node.id) && (
            <div style={{color:'#ff3366', fontWeight:700, marginTop:6}}>⚠ COMPROMISED</div>
          )}
          {contained.has(tooltip.node.id) && (
            <div style={{color:'#00aaff', fontWeight:700, marginTop:6}}>🔒 ISOLATED</div>
          )}
        </div>
      )}

      {/* Zoom controls */}
      <div style={{ position:'absolute', bottom:16, right:16, display:'flex', flexDirection:'column', gap:5, zIndex:50 }}>
        {[{l:'+',a:()=>setZoom(z=>Math.min(MAX_ZOOM,z*1.2))},
          {l:'−',a:()=>setZoom(z=>Math.max(MIN_ZOOM,z/1.2))},
          {l:'⊡',a:()=>fitToScreen(vpW, vpH)},
        ].map(b => (
          <button key={b.l} onClick={b.a} style={{
            width:36, height:36, borderRadius:7, cursor:'pointer',
            background:'rgba(8,8,22,0.92)', border:'1px solid rgba(0,170,255,0.28)',
            color:'#00aaff', fontSize:20, display:'flex', alignItems:'center', justifyContent:'center',
            transition:'all 0.15s',
          }}
          onMouseEnter={e=>(e.currentTarget.style.background='rgba(0,170,255,0.14)')}
          onMouseLeave={e=>(e.currentTarget.style.background='rgba(8,8,22,0.92)')}>
            {b.l}
          </button>
        ))}
      </div>

      {/* Legend */}
      <div style={{
        position:'absolute', bottom:16, left:16, zIndex:50,
        background:'rgba(4,4,16,0.92)', border:'1px solid rgba(255,255,255,0.06)',
        borderRadius:7, padding:'8px 14px', backdropFilter:'blur(8px)',
        fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'#44446a',
        display:'flex', gap:16, alignItems:'center',
      }}>
        <span style={{color:'#00aaff', fontFamily:"'Orbitron',monospace", fontSize:8, fontWeight:700}}>LEGEND</span>
        {[['#00dd77','Healthy'],['#ff8822','Under Attack'],['#ff3366','Compromised'],['#00aaff','Isolated'],['#ff3366','☠ Attacker']].map(([c,l])=>(
          <span key={l} style={{display:'flex',alignItems:'center',gap:5}}>
            <span style={{width:8,height:8,borderRadius:'50%',background:c,display:'inline-block'}}/>
            {l}
          </span>
        ))}
      </div>

      {/* Zoom % + hint */}
      <div style={{
        position:'absolute', top:12, left:12, zIndex:50,
        background:'rgba(4,4,16,0.88)', border:'1px solid rgba(0,170,255,0.18)',
        borderRadius:5, padding:'4px 10px',
        fontFamily:"'JetBrains Mono',monospace", fontSize:9, color:'#44446a',
      }}>
        {Math.round(zoom*100)}% · scroll to zoom · drag to pan
      </div>

      {/* Active attack badge */}
      {attacks.filter(a=>a.status!=='contained').length > 0 && (
        <div style={{
          position:'absolute', top:12, right:16, zIndex:50,
          background:'rgba(255,51,102,0.1)', border:'1px solid rgba(255,51,102,0.4)',
          borderRadius:5, padding:'5px 12px',
          fontFamily:"'Orbitron',monospace", fontSize:9, fontWeight:700,
          color:'#ff3366', display:'flex', alignItems:'center', gap:6,
        }}>
          <span className="blink" style={{width:6,height:6,borderRadius:'50%',background:'#ff3366',display:'inline-block'}}/>
          {attacks.filter(a=>a.status!=='contained').length} ACTIVE ATTACK{attacks.filter(a=>a.status!=='contained').length>1?'S':''}
        </div>
      )}
    </div>
  );
}
