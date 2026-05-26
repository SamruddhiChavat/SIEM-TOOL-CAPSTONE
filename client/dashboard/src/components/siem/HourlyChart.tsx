import { useState } from "react";

type HourRow = { h: number; baseline: number; current: number; anomaly: boolean; label: string };

export function HourlyChart({ data }: { data: HourRow[] }) {
  const [hovered, setHovered] = useState<number | null>(null);

  const W = 100; const VH = 300;
  const PAD_L = 52; const PAD_R = 16; const PAD_T = 20; const PAD_B = 36;
  const totalW = 24 * W + PAD_L + PAD_R;
  const chartH  = VH - PAD_T - PAD_B;
  const maxVal  = Math.max(...data.map(d => Math.max(d.baseline, d.current)));

  const ys = (v: number) => PAD_T + chartH - (v / maxVal) * chartH;
  const xs = (h: number) => PAD_L + h * W + W / 2;

  const baselinePts = data.map(d => `${xs(d.h)},${ys(d.baseline)}`).join(" ");
  const todayPts    = data.map(d => `${xs(d.h)},${ys(d.current)}`).join(" ");

  const baselineArea =
    `M${xs(0)},${ys(data[0].baseline)} ` +
    data.map(d => `L${xs(d.h)},${ys(d.baseline)}`).join(" ") +
    ` L${xs(23)},${VH - PAD_B} L${xs(0)},${VH - PAD_B} Z`;

  const todayArea =
    `M${xs(0)},${ys(data[0].current)} ` +
    data.map(d => `L${xs(d.h)},${ys(d.current)}`).join(" ") +
    ` L${xs(23)},${VH - PAD_B} L${xs(0)},${VH - PAD_B} Z`;

  const yTicks = [0, 100, 200, 300, 400, 500].filter(v => v <= maxVal + 30);

  return (
    <div className="w-full overflow-x-auto">
      <svg
        viewBox={`0 0 ${totalW} ${VH}`}
        className="w-full"
        style={{ minWidth: 560, height: 220 }}
        preserveAspectRatio="none"
      >
        <defs>
          <linearGradient id="ueba-gradBase" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="hsl(190,100%,50%)" stopOpacity="0.15" />
            <stop offset="100%" stopColor="hsl(190,100%,50%)" stopOpacity="0.01" />
          </linearGradient>
          <linearGradient id="ueba-gradToday" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="hsl(190,100%,50%)" stopOpacity="0.38" />
            <stop offset="100%" stopColor="hsl(190,100%,50%)" stopOpacity="0.02" />
          </linearGradient>
          <filter id="ueba-redGlow" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="6" result="blur" />
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>

        {/* Y grid + labels */}
        {yTicks.map(v => (
          <g key={v}>
            <line x1={PAD_L} y1={ys(v)} x2={totalW - PAD_R} y2={ys(v)}
              stroke="hsl(220,25%,16%)" strokeWidth="1" />
            <text x={PAD_L - 6} y={ys(v) + 4} textAnchor="end"
              fontSize="17" fill="hsl(215,11%,42%)" fontFamily="monospace">{v}</text>
          </g>
        ))}

        {/* Baseline filled area + dashed line */}
        <path d={baselineArea} fill="url(#ueba-gradBase)" />
        <polyline points={baselinePts} fill="none"
          stroke="rgba(0,212,255,0.35)" strokeWidth="2.5" strokeDasharray="8 5" />

        {/* Today filled area + solid line */}
        <path d={todayArea} fill="url(#ueba-gradToday)" />
        <polyline points={todayPts} fill="none"
          stroke="hsl(190,100%,50%)" strokeWidth="3"
          strokeLinejoin="round" strokeLinecap="round" />

        {/* Dots + anomaly spike */}
        {data.map(d => {
          const x = xs(d.h); const y = ys(d.current);
          const isH = hovered === d.h;
          if (d.anomaly) {
            return (
              <g key={d.h}
                onMouseEnter={() => setHovered(d.h)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: "pointer" }}>
                <circle cx={x} cy={y} r="22" fill="rgba(248,113,113,0.10)" />
                <circle cx={x} cy={y} r="11" fill="rgba(248,113,113,0.22)" />
                <circle cx={x} cy={y} r="5.5" fill="hsl(0,84%,60%)" filter="url(#ueba-redGlow)" />
              </g>
            );
          }
          return (
            <circle key={d.h} cx={x} cy={y}
              r={isH ? 7 : 4}
              fill={isH ? "hsl(190,100%,50%)" : "rgba(0,212,255,0.55)"}
              stroke="hsl(190,100%,50%)" strokeWidth={isH ? 2 : 1}
              style={{ cursor: "pointer", transition: "r 0.12s, fill 0.12s" }}
              onMouseEnter={() => setHovered(d.h)}
              onMouseLeave={() => setHovered(null)}
            />
          );
        })}

        {/* SVG Tooltip */}
        {hovered !== null && (() => {
          const d = data[hovered];
          if (!d) return null;
          const x = xs(d.h); const y = ys(d.current);
          const bw = 218; const bh = 56;
          const bx = Math.max(PAD_L, Math.min(x - bw / 2, totalW - PAD_R - bw));
          const by = Math.max(4, y - bh - 12);
          return (
            <g>
              <rect x={bx} y={by} width={bw} height={bh} rx="6"
                fill="hsl(220,20%,8%)" stroke="hsl(220,25%,22%)" strokeWidth="1.2" />
              <text x={bx + 10} y={by + 20} fontSize="15" fontWeight="bold" fontFamily="monospace"
                fill={d.anomaly ? "hsl(0,84%,60%)" : "hsl(190,100%,60%)"}>
                {d.label}
              </text>
              <text x={bx + 10} y={by + 40} fontSize="13" fontFamily="monospace"
                fill="hsl(215,11%,55%)">
                Baseline: {d.baseline}  ·  Today: {d.current}
              </text>
            </g>
          );
        })()}

        {/* X-axis hour labels every 3h */}
        {data.filter(d => d.h % 3 === 0).map(d => (
          <text key={d.h} x={xs(d.h)} y={VH - 8} textAnchor="middle"
            fontSize="15" fill="hsl(215,11%,38%)" fontFamily="monospace">
            {String(d.h).padStart(2, "0")}:00
          </text>
        ))}

        {/* Bottom axis line */}
        <line x1={PAD_L} y1={VH - PAD_B} x2={totalW - PAD_R} y2={VH - PAD_B}
          stroke="hsl(220,25%,18%)" strokeWidth="1.5" />
      </svg>
    </div>
  );
}
