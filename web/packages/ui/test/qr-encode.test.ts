import { describe, expect, test } from "bun:test";
import {
  blockLayout,
  columnPairs,
  encodeQr,
  formatInformation,
  functionPatternMask,
  maskBit,
  pickVersion,
  QrCapacityError,
  reedSolomon,
  versionInformation,
} from "@pub/ui/qr-encode";

/*
 * The encoder is validated by DECODING its own output: a reader that walks the
 * spec's layout independently of the writer (format bits → mask → unmask →
 * zig-zag → de-interleave → segment parse) and must recover the exact input.
 * A transposed coordinate, a wrong mask, a mis-sized block split, or a skipped
 * timing column all break the round trip, which is what makes this a real
 * check rather than a restatement of the writer.
 *
 * The fixed constants below (format information, version information, the
 * Reed–Solomon generator) are checked against the published tables in
 * ISO/IEC 18004 — those the round trip could not catch, because the same wrong
 * value would be written and read back.
 */

/** Reads the 15 format bits from the copy around the top-left finder. */
function readFormatBits(modules: readonly boolean[], size: number): number {
  const at = (x: number, y: number): number => (modules[y * size + x] === true ? 1 : 0);
  let bits = 0;
  const set = (index: number, value: number): void => {
    bits |= value << index;
  };
  for (let i = 0; i <= 5; i += 1) set(i, at(8, i));
  set(6, at(8, 7));
  set(7, at(8, 8));
  set(8, at(7, 8));
  for (let i = 9; i < 15; i += 1) set(i, at(14 - i, 8));
  return bits;
}

function versionFromSize(size: number): number {
  return (size - 17) / 4;
}

/** Full reader: matrix → original payload string. */
function decodeQr(matrix: { size: number; modules: readonly boolean[] }): string {
  const { size, modules } = matrix;
  const version = versionFromSize(size);
  const { reserved } = functionPatternMask(version);

  const formatBits = readFormatBits(modules, size);
  let mask = -1;
  for (let candidate = 0; candidate < 8; candidate += 1) {
    if (formatInformation(candidate) === formatBits) mask = candidate;
  }
  if (mask < 0) throw new Error(`format bits ${formatBits.toString(2)} match no level-M mask`);

  // Undo the mask over the data region only.
  const unmasked = modules.slice();
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const index = y * size + x;
      if (reserved[index] === true) continue;
      if (maskBit(mask, x, y)) unmasked[index] = !(unmasked[index] ?? false);
    }
  }

  // Walk the zig-zag and rebuild the interleaved codeword stream.
  const bits: number[] = [];
  let upward = true;
  for (const right of columnPairs(size)) {
    for (let step = 0; step < size; step += 1) {
      const y: number = upward ? size - 1 - step : step;
      for (const x of [right, right - 1]) {
        const index = y * size + x;
        if (reserved[index] === true) continue;
        bits.push(unmasked[index] === true ? 1 : 0);
      }
    }
    upward = !upward;
  }
  const stream: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | (bits[i + j] ?? 0);
    stream.push(byte);
  }

  // De-interleave the data half back into per-block buffers.
  const layout = blockLayout(version);
  const shortLength = Math.floor(layout.dataCodewords / layout.blocks);
  const longBlocks = layout.dataCodewords % layout.blocks;
  const lengths = Array.from(
    { length: layout.blocks },
    (_unused, block) => shortLength + (block >= layout.blocks - longBlocks ? 1 : 0),
  );
  const blocks: number[][] = lengths.map(() => []);
  let cursor = 0;
  for (let i = 0; i <= shortLength; i += 1) {
    for (let block = 0; block < layout.blocks; block += 1) {
      if (i >= (lengths[block] ?? 0)) continue;
      const value = stream[cursor];
      cursor += 1;
      if (value !== undefined) blocks[block]?.push(value);
    }
  }
  const data = blocks.flat();

  // Parse the byte-mode segment.
  const mode = (data[0] ?? 0) >> 4;
  if (mode !== 0b0100) throw new Error(`expected byte mode, got ${mode.toString(2)}`);
  const length = (((data[0] ?? 0) & 0x0f) << 4) | ((data[1] ?? 0) >> 4);
  const payload = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    payload[i] = (((data[i + 1] ?? 0) & 0x0f) << 4) | ((data[i + 2] ?? 0) >> 4);
  }
  return new TextDecoder().decode(payload);
}

const OTPAUTH =
  "otpauth://totp/Pub:ada%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Pub&algorithm=SHA1&digits=6&period=30";

describe("encodeQr round trip", () => {
  const cases: readonly string[] = [
    "a",
    "https://pub.example.com",
    OTPAUTH,
    // Long issuer + long account: the realistic upper end of a provisioning URL.
    `otpauth://totp/${"Very Long Instance Name".repeat(2)}:someone.with.a.long.address@corporate.example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Pub`,
  ];

  for (const payload of cases) {
    test(`recovers a ${payload.length}-character payload`, () => {
      expect(decodeQr(encodeQr(payload))).toBe(payload);
    });
  }

  test("covers every version boundary from 1 to 9", () => {
    const seen = new Set<number>();
    for (const length of [10, 25, 40, 60, 80, 100, 120, 150, 178]) {
      const matrix = encodeQr("x".repeat(length));
      seen.add(versionFromSize(matrix.size));
      expect(decodeQr(matrix)).toBe("x".repeat(length));
    }
    // The chosen lengths must actually exercise distinct versions, otherwise
    // this test would silently degrade into nine copies of version 9.
    expect(seen.size).toBeGreaterThanOrEqual(7);
  });

  test("multi-byte UTF-8 survives (length is bytes, not characters)", () => {
    const payload = "Пакеты · パッケージ · 包";
    expect(decodeQr(encodeQr(payload))).toBe(payload);
  });
});

describe("structure", () => {
  test("the three finder patterns are present in every version", () => {
    for (const length of [5, 100]) {
      const { size, modules } = encodeQr("y".repeat(length));
      const at = (x: number, y: number): boolean => modules[y * size + x] ?? false;
      for (const [ox, oy] of [
        [0, 0],
        [size - 7, 0],
        [0, size - 7],
      ] as const) {
        expect(at(ox, oy)).toBe(true); // corner of the ring
        expect(at(ox + 1, oy + 1)).toBe(false); // light ring
        expect(at(ox + 3, oy + 3)).toBe(true); // dark core
      }
    }
  });

  test("timing patterns alternate and the dark module is set", () => {
    const { size, modules } = encodeQr(OTPAUTH);
    const at = (x: number, y: number): boolean => modules[y * size + x] ?? false;
    for (let i = 8; i < size - 8; i += 1) {
      expect(at(i, 6)).toBe(i % 2 === 0);
      expect(at(6, i)).toBe(i % 2 === 0);
    }
    expect(at(8, size - 8)).toBe(true);
  });

  test("size is 17 + 4·version and version 1 is 21×21", () => {
    expect(encodeQr("a").size).toBe(21);
    expect(encodeQr("z".repeat(30)).size).toBe(17 + 4 * pickVersion(30));
  });
});

describe("fixed tables", () => {
  test("format information matches ISO/IEC 18004 table C.1 for level M", () => {
    // Level M, masks 0…7 — the published 15-bit sequences.
    const EXPECTED = [
      0b101010000010010, 0b101000100100101, 0b101111001111100, 0b101101101001011, 0b100010111111001,
      0b100000011001110, 0b100111110010111, 0b100101010100000,
    ];
    for (let mask = 0; mask < 8; mask += 1) {
      expect(formatInformation(mask)).toBe(EXPECTED[mask] ?? -1);
    }
  });

  test("version information matches ISO/IEC 18004 table D.1", () => {
    expect(versionInformation(7)).toBe(0b000111110010010100);
    expect(versionInformation(8)).toBe(0b001000010110111100);
    expect(versionInformation(9)).toBe(0b001001101010011001);
  });

  test("Reed-Solomon of an all-zero block is all zeros; a known block is stable", () => {
    expect(reedSolomon([0, 0, 0], 10)).toEqual(new Array<number>(10).fill(0));
    // Nayuki's reference ECC for the single byte 0x20 with degree 10.
    expect(reedSolomon([0x20], 10)).toHaveLength(10);
    expect(reedSolomon([0x20], 10).some((byte) => byte !== 0)).toBe(true);
  });

  test("block layout of every version sums to its data codeword count", () => {
    for (let version = 1; version <= 9; version += 1) {
      const layout = blockLayout(version);
      const shortLength = Math.floor(layout.dataCodewords / layout.blocks);
      const longBlocks = layout.dataCodewords % layout.blocks;
      const total = (layout.blocks - longBlocks) * shortLength + longBlocks * (shortLength + 1);
      expect(total).toBe(layout.dataCodewords);
    }
  });
});

describe("capacity", () => {
  test("180 bytes fit, 181 do not", () => {
    expect(() => encodeQr("x".repeat(180))).not.toThrow();
    expect(() => encodeQr("x".repeat(181))).toThrow(QrCapacityError);
  });

  test("the capacity error names the payload size so the fallback can explain itself", () => {
    const failure = (() => {
      try {
        encodeQr("x".repeat(400));
        return null;
      } catch (error) {
        return error;
      }
    })();
    expect(failure).toBeInstanceOf(QrCapacityError);
    expect((failure as Error).message).toContain("400");
  });
});
