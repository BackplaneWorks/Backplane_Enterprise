import React from 'react';
import { generateIpc7351Footprint, generateSchematicSymbol } from '../lib/ipc7351';
import type { Ipc7351Spec } from '../types/domain';
import { Panel } from './ui';

interface FootprintPreviewProps {
  spec: Ipc7351Spec;
  mpn: string;
  /** Footprint only, stacked: used beside the new-part form. */
  compact?: boolean;
}

// Drawing colours: Backplane's own palette, one accent for copper.
const INK = '#d9dde4';
const DIM = '#8a93a3';
const FAINT = '#5c6473';
const COPPER = '#5fb3ff';
const PIN1 = '#e3b341';

export const FootprintPreview: React.FC<FootprintPreviewProps> = ({ spec, mpn, compact }) => {
  const fp = generateIpc7351Footprint(spec);
  const sym = generateSchematicSymbol(spec.pinCount, spec.family);
  const halfW = fp.viewBoxWidthMm / 2;
  const halfH = fp.viewBoxHeightMm / 2;

  const footprint = (
    <Panel title="Footprint" meta={fp.name}>
      <div className="viewport figure">
        <svg
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
            stroke={FAINT}
            strokeDasharray="0.25 0.2"
            strokeWidth={0.05}
          />
          {/* Package body */}
          <rect
            x={-fp.bodyWidthMm / 2}
            y={-fp.bodyLengthMm / 2}
            width={fp.bodyWidthMm}
            height={fp.bodyLengthMm}
            fill="#13161b"
            stroke={INK}
            strokeWidth={0.06}
          />
          {/* Pin-1 marker */}
          <rect
            x={fp.pin1Marker.xMm - 0.16}
            y={fp.pin1Marker.yMm - 0.16}
            width={0.32}
            height={0.32}
            fill={PIN1}
          />
          {/* Copper pads */}
          {fp.pads.map((pad) => (
            <rect
              key={pad.pin}
              x={pad.xMm - pad.widthMm / 2}
              y={pad.yMm - pad.heightMm / 2}
              width={pad.widthMm}
              height={pad.heightMm}
              rx={pad.shape === 'circle' ? pad.widthMm / 2 : pad.shape === 'roundrect' ? 0.06 : 0}
              fill={COPPER}
              opacity={0.88}
            />
          ))}
        </svg>
      </div>
      <dl className="kv flush">
        <dt>Pads</dt>
        <dd>{fp.pads.length}</dd>
        <dt>Pitch</dt>
        <dd>{spec.pitchMm} mm</dd>
        <dt>Courtyard</dt>
        <dd>
          {fp.courtyardWidthMm} × {fp.courtyardLengthMm} mm
        </dd>
      </dl>
    </Panel>
  );

  if (compact) return footprint;

  return (
    <div className="cols-2">
      {footprint}

      <Panel title="Symbol" meta={mpn}>
        <div className="viewport figure">
          <svg
            viewBox={`-36 0 ${sym.width + 72} ${sym.height}`}
            role="img"
            aria-label={`Schematic symbol for ${mpn}`}
          >
            <rect
              x={0}
              y={8}
              width={sym.width}
              height={sym.height - 16}
              fill="#13161b"
              stroke={COPPER}
              strokeWidth={1.2}
            />
            {sym.pins.map((pin) => {
              const xEnd = pin.side === 'left' ? -18 : sym.width + 18;
              return (
                <g key={pin.number}>
                  <line x1={pin.x} y1={pin.y} x2={xEnd} y2={pin.y} stroke={DIM} strokeWidth={1.2} />
                  <text
                    className="svg-label"
                    x={pin.side === 'left' ? 6 : sym.width - 6}
                    y={pin.y + 3}
                    textAnchor={pin.side === 'left' ? 'start' : 'end'}
                    fontSize={7.5}
                    fill={INK}
                  >
                    {pin.name}
                  </text>
                  <text
                    className="svg-label"
                    x={pin.side === 'left' ? -10 : sym.width + 10}
                    y={pin.y - 3}
                    textAnchor="middle"
                    fontSize={6.5}
                    fill={FAINT}
                  >
                    {pin.number}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>
        <dl className="kv flush">
          <dt>Pins shown</dt>
          <dd>
            {sym.pins.length} of {spec.pinCount}
          </dd>
          <dt>Family</dt>
          <dd>{spec.family}</dd>
          <dt>Body</dt>
          <dd>
            {spec.bodyWidthMm} × {spec.bodyLengthMm} mm
          </dd>
        </dl>
      </Panel>
    </div>
  );
};
