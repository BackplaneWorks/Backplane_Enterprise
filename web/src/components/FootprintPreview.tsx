import React from 'react';
import { generateIpc7351Footprint, generateSchematicSymbol } from '../lib/ipc7351';
import type { Ipc7351Spec } from '../types/domain';

interface FootprintPreviewProps {
  spec: Ipc7351Spec;
  mpn: string;
}

export const FootprintPreview: React.FC<FootprintPreviewProps> = ({ spec, mpn }) => {
  const fp = generateIpc7351Footprint(spec);
  const sym = generateSchematicSymbol(spec.pinCount, spec.family);
  const halfW = fp.viewBoxWidthMm / 2;
  const halfH = fp.viewBoxHeightMm / 2;

  return (
    <div className="split-pane-equal">
      <div className="card">
        <div className="card-header">
          <h4 className="card-title">IPC-7351 Footprint Preview</h4>
          <span className="badge badge-cyan mono">{fp.name}</span>
        </div>
        <div className="svg-viewport">
          <svg
            className="svg-canvas"
            viewBox={`${-halfW} ${-halfH} ${fp.viewBoxWidthMm} ${fp.viewBoxHeightMm}`}
            role="img"
            aria-label={`IPC-7351 footprint for ${mpn}`}
          >
            {/* Courtyard */}
            <rect
              x={-fp.courtyardWidthMm / 2}
              y={-fp.courtyardLengthMm / 2}
              width={fp.courtyardWidthMm}
              height={fp.courtyardLengthMm}
              fill="none"
              stroke="#64748b"
              strokeDasharray="0.25 0.2"
              strokeWidth={0.07}
            />
            {/* Package Body */}
            <rect
              x={-fp.bodyWidthMm / 2}
              y={-fp.bodyLengthMm / 2}
              width={fp.bodyWidthMm}
              height={fp.bodyLengthMm}
              fill="#111827"
              stroke="#e2e8f0"
              strokeWidth={0.09}
            />
            {/* Pin-1 Marker */}
            <circle cx={fp.pin1Marker.xMm} cy={fp.pin1Marker.yMm} r={0.18} fill="#f59e0b" />
            {/* Copper Pads */}
            {fp.pads.map((pad) => (
              <rect
                key={pad.pin}
                x={pad.xMm - pad.widthMm / 2}
                y={pad.yMm - pad.heightMm / 2}
                width={pad.widthMm}
                height={pad.heightMm}
                rx={pad.shape === 'circle' ? pad.widthMm / 2 : pad.shape === 'roundrect' ? 0.06 : 0}
                fill="#ef4444"
                opacity={0.9}
              />
            ))}
          </svg>
        </div>
        <div className="text-sm muted mono">
          Pads: {fp.pads.length} | Courtyard: {fp.courtyardWidthMm} x {fp.courtyardLengthMm} mm
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h4 className="card-title">Schematic Symbol Preview</h4>
          <span className="badge badge-blue mono">{mpn}</span>
        </div>
        <div className="svg-viewport">
          <svg
            className="svg-canvas"
            viewBox={`-36 0 ${sym.width + 72} ${sym.height}`}
            role="img"
            aria-label={`Schematic symbol for ${mpn}`}
          >
            <rect
              x={0}
              y={8}
              width={sym.width}
              height={sym.height - 16}
              fill="#0f172a"
              stroke="#38bdf8"
              strokeWidth={1.6}
            />
            {sym.pins.map((pin) => {
              const xEnd = pin.side === 'left' ? -18 : sym.width + 18;
              return (
                <g key={pin.number}>
                  <line
                    x1={pin.x}
                    y1={pin.y}
                    x2={xEnd}
                    y2={pin.y}
                    stroke="#94a3b8"
                    strokeWidth={1.4}
                  />
                  <text
                    x={pin.side === 'left' ? 6 : sym.width - 6}
                    y={pin.y + 3.5}
                    textAnchor={pin.side === 'left' ? 'start' : 'end'}
                    fontSize={8}
                    fill="#e2e8f0"
                  >
                    {pin.name}
                  </text>
                  <text
                    x={pin.side === 'left' ? -10 : sym.width + 10}
                    y={pin.y - 3}
                    textAnchor="middle"
                    fontSize={7}
                    fill="#94a3b8"
                  >
                    {pin.number}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="text-sm muted mono">
          Displayed pins: {sym.pins.length} / Total package pins: {spec.pinCount}
        </div>
      </div>
    </div>
  );
};
