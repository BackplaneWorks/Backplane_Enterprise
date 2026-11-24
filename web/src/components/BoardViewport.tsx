import React, { useRef } from 'react';
import type { BoardProject, PinComment } from '../types/domain';

export type ViewportMode = 'pcb' | 'schematic' | '3d';

interface BoardViewportProps {
  board: BoardProject;
  mode: ViewportMode;
  activeLayer: 'F.Cu' | 'B.Cu' | 'F.SilkS' | 'Edge.Cuts';
  selectedCommentId: string | null;
  onSelectComment: (commentId: string) => void;
  onPlacePin: (coords: { layer: string; xMm: number; yMm: number; refdes?: string }) => void;
}

export const BoardViewport: React.FC<BoardViewportProps> = ({
  board,
  mode,
  activeLayer,
  selectedCommentId,
  onSelectComment,
  onPlacePin,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);

  const handleSvgClick = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;

    const normX = (e.clientX - rect.left) / rect.width;
    const normY = (e.clientY - rect.top) / rect.height;
    const xMm = Math.round(normX * board.widthMm * 10) / 10;
    const yMm = Math.round(normY * board.heightMm * 10) / 10;

    const hitComponent = board.components.find(
      (comp) =>
        Math.abs(comp.xMm - xMm) <= comp.widthMm / 2 + 1 &&
        Math.abs(comp.yMm - yMm) <= comp.heightMm / 2 + 1,
    );

    onPlacePin({
      layer: mode === 'schematic' ? 'Schematic' : mode === '3d' ? '3D.Top' : activeLayer,
      xMm,
      yMm,
      refdes: hitComponent?.refdes,
    });
  };

  const renderPinMarkers = (comments: PinComment[]) =>
    comments.map((cmt, idx) => {
      const selected = cmt.id === selectedCommentId;
      return (
        <g
          key={cmt.id}
          transform={`translate(${cmt.xMm}, ${cmt.yMm})`}
          onClick={(e) => {
            e.stopPropagation();
            onSelectComment(cmt.id);
          }}
        >
          <circle
            r={selected ? 2.8 : 2.2}
            fill={cmt.resolved ? '#10b981' : '#f59e0b'}
            stroke="#0b0f14"
            strokeWidth={0.5}
          />
          <text
            x={0}
            y={0.8}
            textAnchor="middle"
            fontSize={2.2}
            fontWeight="bold"
            fill="#0b0f14"
          >
            {idx + 1}
          </text>
        </g>
      );
    });

  return (
    <div className="svg-viewport">
      <svg
        ref={svgRef}
        className="svg-canvas"
        viewBox={`0 0 ${board.widthMm} ${board.heightMm}`}
        role="img"
        aria-label={`${board.name} ${mode} viewport`}
        onClick={handleSvgClick}
      >
        <rect x={0} y={0} width={board.widthMm} height={board.heightMm} fill="#070b10" />

        {mode === 'pcb' && (
          <g>
            <rect
              x={1}
              y={1}
              width={board.widthMm - 2}
              height={board.heightMm - 2}
              rx={1.5}
              fill="#0c261c"
              stroke="#eab308"
              strokeWidth={0.4}
            />
            {/* Simulated copper differential pairs & buses */}
            <path
              d={`M 10 52 L 28 52 L 38 40 L 46 34`}
              fill="none"
              stroke={activeLayer === 'B.Cu' ? '#38bdf8' : '#ef4444'}
              strokeWidth={0.55}
              opacity={0.85}
            />
            <path
              d={`M 22 24 L 36 24 L 46 34`}
              fill="none"
              stroke={activeLayer === 'B.Cu' ? '#38bdf8' : '#ef4444'}
              strokeWidth={0.45}
              opacity={0.85}
            />
            <path
              d={`M 46 34 L 68 34 L 76 18`}
              fill="none"
              stroke="#ef4444"
              strokeWidth={0.7}
              opacity={0.8}
            />

            {board.components.map((c) => (
              <g key={c.refdes}>
                <rect
                  x={c.xMm - c.widthMm / 2}
                  y={c.yMm - c.heightMm / 2}
                  width={c.widthMm}
                  height={c.heightMm}
                  fill="#161f2b"
                  stroke="#94a3b8"
                  strokeWidth={0.35}
                />
                <text
                  x={c.xMm}
                  y={c.yMm + 0.8}
                  textAnchor="middle"
                  fontSize={2.4}
                  fill="#f8fafc"
                >
                  {c.refdes}
                </text>
              </g>
            ))}
          </g>
        )}

        {mode === 'schematic' && (
          <g>
            <rect
              x={2}
              y={2}
              width={board.widthMm - 4}
              height={board.heightMm - 4}
              fill="#0b1220"
              stroke="#334155"
              strokeWidth={0.35}
            />
            {board.components.map((c, idx) => {
              const boxX = 12 + (idx % 3) * 28;
              const boxY = 12 + Math.floor(idx / 3) * 26;
              return (
                <g key={c.refdes}>
                  <rect
                    x={boxX}
                    y={boxY}
                    width={22}
                    height={16}
                    fill="#111a2b"
                    stroke="#38bdf8"
                    strokeWidth={0.4}
                  />
                  <text x={boxX + 11} y={boxY + 7} textAnchor="middle" fontSize={2.6} fill="#f1f5f9">
                    {c.refdes}
                  </text>
                  <text x={boxX + 11} y={boxY + 11.5} textAnchor="middle" fontSize={1.9} fill="#93c5fd">
                    {c.mpn}
                  </text>
                </g>
              );
            })}
          </g>
        )}

        {mode === '3d' && (
          <g>
            <polygon
              points={`10,${board.heightMm * 0.55} ${board.widthMm * 0.5},${board.heightMm * 0.16} ${board.widthMm - 10},${board.heightMm * 0.45} ${board.widthMm * 0.5},${board.heightMm * 0.84}`}
              fill="#0f3d2e"
              stroke="#34d399"
              strokeWidth={0.5}
            />
            {board.components.map((c) => (
              <g key={c.refdes}>
                <rect
                  x={c.xMm - c.widthMm * 0.45}
                  y={c.yMm - c.heightMm * 0.45}
                  width={c.widthMm * 0.9}
                  height={c.heightMm * 0.9}
                  fill="#1f2937"
                  stroke="#cbd5e1"
                  strokeWidth={0.35}
                />
                <text x={c.xMm} y={c.yMm + 0.7} textAnchor="middle" fontSize={2.1} fill="#e2e8f0">
                  {c.refdes}
                </text>
              </g>
            ))}
          </g>
        )}

        {renderPinMarkers(board.comments)}
      </svg>
    </div>
  );
};
