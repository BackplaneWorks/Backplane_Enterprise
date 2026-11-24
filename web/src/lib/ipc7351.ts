import type { Ipc7351Spec } from '../types/domain';

export interface PadGeometry {
  pin: string;
  xMm: number;
  yMm: number;
  widthMm: number;
  heightMm: number;
  shape: 'rect' | 'roundrect' | 'circle';
  layer: 'F.Cu';
}

export interface FootprintGeometry {
  name: string;
  pads: PadGeometry[];
  bodyWidthMm: number;
  bodyLengthMm: number;
  courtyardWidthMm: number;
  courtyardLengthMm: number;
  pin1Marker: { xMm: number; yMm: number };
  viewBoxWidthMm: number;
  viewBoxHeightMm: number;
}

export interface SymbolPin {
  number: number;
  name: string;
  side: 'left' | 'right';
  x: number;
  y: number;
}

export interface SymbolGeometry {
  width: number;
  height: number;
  pins: SymbolPin[];
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export function generateIpc7351Footprint(spec: Ipc7351Spec): FootprintGeometry {
  const pads: PadGeometry[] = [];
  const pinCount = Math.max(2, spec.pinCount);
  const pitch = Math.max(0.25, spec.pitchMm);
  const bodyW = Math.max(0.6, spec.bodyWidthMm);
  const bodyL = Math.max(0.6, spec.bodyLengthMm);
  const padW = Math.max(0.15, spec.padWidthMm);
  const padL = Math.max(0.15, spec.padLengthMm);

  if (spec.family === 'CHIP') {
    const span = bodyL * 0.45;
    pads.push(
      {
        pin: '1',
        xMm: round3(-span),
        yMm: 0,
        widthMm: round3(padW),
        heightMm: round3(padL),
        shape: 'roundrect',
        layer: 'F.Cu',
      },
      {
        pin: '2',
        xMm: round3(span),
        yMm: 0,
        widthMm: round3(padW),
        heightMm: round3(padL),
        shape: 'roundrect',
        layer: 'F.Cu',
      },
    );
  } else if (spec.family === 'SOIC') {
    const perSide = Math.max(1, Math.floor(pinCount / 2));
    const spanY = ((perSide - 1) * pitch) / 2;
    const xOffset = bodyW / 2 + padL * 0.45;

    for (let i = 0; i < perSide; i++) {
      pads.push({
        pin: String(i + 1),
        xMm: round3(-xOffset),
        yMm: round3(-spanY + i * pitch),
        widthMm: round3(padL),
        heightMm: round3(padW),
        shape: 'roundrect',
        layer: 'F.Cu',
      });
    }
    for (let i = 0; i < perSide; i++) {
      pads.push({
        pin: String(perSide + i + 1),
        xMm: round3(xOffset),
        yMm: round3(spanY - i * pitch),
        widthMm: round3(padL),
        heightMm: round3(padW),
        shape: 'roundrect',
        layer: 'F.Cu',
      });
    }
  } else if (spec.family === 'QFN' || spec.family === 'LQFP') {
    const perSide = Math.max(1, Math.floor(pinCount / 4));
    const span = ((perSide - 1) * pitch) / 2;
    const xLead = bodyW / 2 + (spec.family === 'LQFP' ? padL * 0.45 : 0.05);
    const yLead = bodyL / 2 + (spec.family === 'LQFP' ? padL * 0.45 : 0.05);

    let pin = 1;
    for (let i = 0; i < perSide; i++) {
      pads.push({
        pin: String(pin++),
        xMm: round3(-xLead),
        yMm: round3(-span + i * pitch),
        widthMm: round3(padL),
        heightMm: round3(padW),
        shape: 'roundrect',
        layer: 'F.Cu',
      });
    }
    for (let i = 0; i < perSide; i++) {
      pads.push({
        pin: String(pin++),
        xMm: round3(-span + i * pitch),
        yMm: round3(yLead),
        widthMm: round3(padW),
        heightMm: round3(padL),
        shape: 'roundrect',
        layer: 'F.Cu',
      });
    }
    for (let i = 0; i < perSide; i++) {
      pads.push({
        pin: String(pin++),
        xMm: round3(xLead),
        yMm: round3(span - i * pitch),
        widthMm: round3(padL),
        heightMm: round3(padW),
        shape: 'roundrect',
        layer: 'F.Cu',
      });
    }
    for (let i = 0; i < perSide; i++) {
      pads.push({
        pin: String(pin++),
        xMm: round3(span - i * pitch),
        yMm: round3(-yLead),
        widthMm: round3(padW),
        heightMm: round3(padL),
        shape: 'roundrect',
        layer: 'F.Cu',
      });
    }

    if (spec.thermalPadMm && spec.thermalPadMm > 0) {
      pads.push({
        pin: 'EP',
        xMm: 0,
        yMm: 0,
        widthMm: round3(spec.thermalPadMm),
        heightMm: round3(spec.thermalPadMm),
        shape: 'rect',
        layer: 'F.Cu',
      });
    }
  } else {
    // BGA matrix
    const cols = Math.max(2, Math.round(Math.sqrt(pinCount)));
    const rows = Math.max(2, Math.ceil(pinCount / cols));
    const spanX = ((cols - 1) * pitch) / 2;
    const spanY = ((rows - 1) * pitch) / 2;
    let count = 0;
    for (let r = 0; r < rows && count < pinCount; r++) {
      for (let c = 0; c < cols && count < pinCount; c++) {
        count++;
        const rowLetter = String.fromCharCode(65 + (r % 26));
        pads.push({
          pin: `${rowLetter}${c + 1}`,
          xMm: round3(-spanX + c * pitch),
          yMm: round3(-spanY + r * pitch),
          widthMm: round3(padW),
          heightMm: round3(padW),
          shape: 'circle',
          layer: 'F.Cu',
        });
      }
    }
  }

  const maxX = Math.max(bodyW / 2, ...pads.map((p) => Math.abs(p.xMm) + p.widthMm / 2));
  const maxY = Math.max(bodyL / 2, ...pads.map((p) => Math.abs(p.yMm) + p.heightMm / 2));
  const courtyardWidthMm = round3(maxX * 2 + 0.5);
  const courtyardLengthMm = round3(maxY * 2 + 0.5);

  const firstPad = pads[0] ?? { xMm: -bodyW / 2, yMm: -bodyL / 2, widthMm: 0.4, heightMm: 0.4 };

  return {
    name: `${spec.family}-${pinCount}_P${pitch}mm_${bodyW}x${bodyL}mm`,
    pads,
    bodyWidthMm: bodyW,
    bodyLengthMm: bodyL,
    courtyardWidthMm,
    courtyardLengthMm,
    pin1Marker: {
      xMm: round3(firstPad.xMm - firstPad.widthMm / 2 - 0.35),
      yMm: round3(firstPad.yMm),
    },
    viewBoxWidthMm: round3(Math.max(courtyardWidthMm + 2.4, 6)),
    viewBoxHeightMm: round3(Math.max(courtyardLengthMm + 2.4, 6)),
  };
}

export function generateSchematicSymbol(
  pinCount: number,
  family: Ipc7351Spec['family'],
): SymbolGeometry {
  const clamped = Math.min(Math.max(2, pinCount), 32);
  const leftCount = Math.ceil(clamped / 2);
  const rightCount = clamped - leftCount;
  const maxSide = Math.max(leftCount, rightCount);
  const spacing = 18;
  const height = Math.max(70, maxSide * spacing + 28);
  const width = 120;
  const pins: SymbolPin[] = [];

  for (let i = 0; i < leftCount; i++) {
    const num = i + 1;
    pins.push({
      number: num,
      name: family === 'CHIP' ? (num === 1 ? '1' : '2') : num === 1 ? 'VIN/P1' : `IO_${num}`,
      side: 'left',
      x: 0,
      y: 22 + i * spacing,
    });
  }
  for (let i = 0; i < rightCount; i++) {
    const num = leftCount + i + 1;
    pins.push({
      number: num,
      name: num === clamped ? 'GND' : `OUT_${num}`,
      side: 'right',
      x: width,
      y: 22 + i * spacing,
    });
  }

  return { width, height, pins };
}
