import { describe, expect, it } from 'vitest';
import { generateIpc7351Footprint, generateSchematicSymbol } from '../lib/ipc7351';
import { buildKicadHttpLibConfig } from '../lib/safeUrl';

describe('IPC-7351 Footprint/Symbol & KiCad HTTP Library Generator', () => {
  it('generates valid pad geometries for QFN (with thermal pad), SOIC, LQFP, CHIP, and BGA', () => {
    const qfn = generateIpc7351Footprint({
      family: 'QFN',
      pinCount: 16,
      pitchMm: 0.5,
      bodyWidthMm: 3,
      bodyLengthMm: 3,
      padWidthMm: 0.25,
      padLengthMm: 0.75,
      thermalPadMm: 1.5,
    });
    expect(qfn.pads).toHaveLength(17); // 16 + EP
    expect(qfn.pads.some((p) => p.pin === 'EP')).toBe(true);
    expect(qfn.courtyardWidthMm).toBeGreaterThan(qfn.bodyWidthMm);

    const soic = generateIpc7351Footprint({
      family: 'SOIC',
      pinCount: 8,
      pitchMm: 1.27,
      bodyWidthMm: 3.9,
      bodyLengthMm: 4.9,
      padWidthMm: 0.6,
      padLengthMm: 1.55,
    });
    expect(soic.pads).toHaveLength(8);

    const lqfp = generateIpc7351Footprint({
      family: 'LQFP',
      pinCount: 100,
      pitchMm: 0.5,
      bodyWidthMm: 14,
      bodyLengthMm: 14,
      padWidthMm: 0.3,
      padLengthMm: 1.45,
    });
    expect(lqfp.pads).toHaveLength(100);

    const chip = generateIpc7351Footprint({
      family: 'CHIP',
      pinCount: 2,
      pitchMm: 1.0,
      bodyWidthMm: 1.6,
      bodyLengthMm: 3.2,
      padWidthMm: 0.9,
      padLengthMm: 1.2,
    });
    expect(chip.pads).toHaveLength(2);

    const bga = generateIpc7351Footprint({
      family: 'BGA',
      pinCount: 16,
      pitchMm: 0.8,
      bodyWidthMm: 5,
      bodyLengthMm: 5,
      padWidthMm: 0.4,
      padLengthMm: 0.4,
    });
    expect(bga.pads).toHaveLength(16);
    expect(bga.pads[0]?.pin).toBe('A1');
  });

  it('generates schematic symbols and tenant-scoped .kicad_httplib config JSON', () => {
    const sym = generateSchematicSymbol(14, 'QFN');
    expect(sym.pins).toHaveLength(14);

    const raw = buildKicadHttpLibConfig({
      orgName: 'AeroWorks Avionics',
      tenantSlug: 'aeroworks',
      baseUrl: 'https://enterprise.backplane.dev/',
      token: 'bpe_usr_demo_secret',
    });
    const parsed = JSON.parse(raw) as {
      meta: { version: number };
      source: { type: string; root_url: string; token: string };
    };
    expect(parsed.meta.version).toBe(1.0);
    expect(parsed.source.type).toBe('REST_API');
    expect(parsed.source.root_url).toBe('https://enterprise.backplane.dev/v1/httplib/aeroworks');
    expect(parsed.source.token).toBe('bpe_usr_demo_secret');
  });
});
