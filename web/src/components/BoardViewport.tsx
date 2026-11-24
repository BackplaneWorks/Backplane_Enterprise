import React, { useRef } from 'react';
import type { BoardProject, PinComment } from '../types/domain';

export type ViewportMode = 'pcb' | 'schematic' | '3d';

// Drawn in Backplane's palette. KiCad's own layer colours belong to KiCad renders only.
const INK = '#d9dde4';
const BONE = '#e6e9de';
const DIM = '#8a93a3';
const RULE = '#353c49';
const TICK = '#6b7383';
const ACCENT = '#5fb3ff';
const OK = '#58c28a';
const WARN = '#e3b341';

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

  const copper = (layer: 'F.Cu' | 'B.Cu') =>
    mode === 'pcb' && activeLayer === layer ? ACCENT : TICK;

  const renderPinMarkers = (comments: PinComment[]) =>
    comments.map((cmt, idx) => {
      const selected = cmt.id === selectedCommentId;
      const tone = cmt.resolved ? OK : WARN;
      return (
        <g
          key={cmt.id}
          className="pin-marker"
          transform={`translate(${cmt.xMm}, ${cmt.yMm})`}
          onClick={(e) => {
            e.stopPropagation();
            onSelectComment(cmt.id);
          }}
        >
          {selected && (
            <rect x={-3.4} y={-3.4} width={6.8} height={6.8} fill="none" stroke={BONE} strokeWidth={0.3} />
          )}
          <rect x={-2.3} y={-2.3} width={4.6} height={4.6} fill={tone} />
          <text
            className="svg-label"
            x={0}
            y={0.95}
            textAnchor="middle"
            fontSize={2.6}
            fontWeight="700"
            fill="#0d0f12"
          >
            {idx + 1}
          </text>
        </g>
      );
    });

  return (
    <div className="viewport board">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${board.widthMm} ${board.heightMm}`}
        role="img"
        aria-label={`${board.name} ${mode} viewport`}
        onClick={handleSvgClick}
      >
        {mode === 'pcb' && (
          <g>
            <rect
              x={1}
              y={1}
              width={board.widthMm - 2}
              height={board.heightMm - 2}
              fill="#0d0f12"
              fillOpacity={0.86}
              stroke={activeLayer === 'Edge.Cuts' ? ACCENT : RULE}
              strokeWidth={activeLayer === 'Edge.Cuts' ? 0.45 : 0.3}
            />
            {/* Indicative routing between placed parts */}
            <path d="M 10 52 L 28 52 L 38 40 L 46 34" fill="none" stroke={copper('F.Cu')} strokeWidth={0.5} />
            <path d="M 22 24 L 36 24 L 46 34" fill="none" stroke={copper('F.Cu')} strokeWidth={0.4} />
            <path d="M 46 34 L 68 34 L 76 18" fill="none" stroke={copper('B.Cu')} strokeWidth={0.6} />

            {board.components.map((c) => (
              <g key={c.refdes}>
                <rect
                  x={c.xMm - c.widthMm / 2}
                  y={c.yMm - c.heightMm / 2}
                  width={c.widthMm}
                  height={c.heightMm}
                  fill="#1a1e25"
                  stroke={activeLayer === 'F.SilkS' ? BONE : DIM}
                  strokeWidth={0.25}
                />
                <text
                  className="svg-label"
                  x={c.xMm}
                  y={c.yMm + 0.8}
                  textAnchor="middle"
                  fontSize={2.3}
                  fill={INK}
                >
                  {c.refdes}
                </text>
              </g>
            ))}
          </g>
        )}

        {mode === 'schematic' && (
          <g>
            {board.components.map((c, idx) => {
              const boxX = 12 + (idx % 3) * 28;
              const boxY = 12 + Math.floor(idx / 3) * 26;
              return (
                <g key={c.refdes}>
                  <rect x={boxX} y={boxY} width={22} height={16} fill="#13161b" stroke={ACCENT} strokeWidth={0.3} />
                  <text className="svg-label" x={boxX + 11} y={boxY + 7} textAnchor="middle" fontSize={2.6} fill={INK}>
                    {c.refdes}
                  </text>
                  <text className="svg-label" x={boxX + 11} y={boxY + 11.5} textAnchor="middle" fontSize={1.8} fill={DIM}>
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
              fill="#13161b"
              stroke={RULE}
              strokeWidth={0.35}
            />
            {board.components.map((c) => (
              <g key={c.refdes}>
                <rect
                  x={c.xMm - c.widthMm * 0.45}
                  y={c.yMm - c.heightMm * 0.45}
                  width={c.widthMm * 0.9}
                  height={c.heightMm * 0.9}
                  fill="#20252e"
                  stroke={DIM}
                  strokeWidth={0.25}
                />
                <text className="svg-label" x={c.xMm} y={c.yMm + 0.7} textAnchor="middle" fontSize={2.1} fill={INK}>
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
