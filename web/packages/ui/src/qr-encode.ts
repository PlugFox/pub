/*
 * Minimal QR Code encoder — byte mode, error-correction level M, versions 1–9.
 *
 * Why hand-rolled: the only QR this product renders is the `otpauth://`
 * provisioning URL on the 2FA enrollment screen (S-05.a). That payload is one
 * short ASCII URL, which needs byte mode and nothing else — no alphanumeric or
 * kanji modes, no ECI, no structured append. A library would add a few hundred
 * kilobytes of generality we never use to a security screen, against a bundle
 * budget (docs/product.md “Lightweight frontend”).
 *
 * Implemented per ISO/IEC 18004:
 *   - byte-mode segment: mode nibble 0100, 8-bit character count (valid for
 *     versions 1–9), terminator, byte alignment, 0xEC/0x11 padding;
 *   - Reed–Solomon ECC over GF(256) with primitive polynomial 0x11D, block
 *     split and interleaving as tabulated for level M;
 *   - function patterns (finders, separators, timing, alignment, dark module),
 *     format information (BCH(15,5), mask 0x5412) and, for versions ≥ 7,
 *     version information (BCH(18,6), 0x1F25);
 *   - all eight data masks scored with the four standard penalty rules.
 *
 * Version 9-M holds 182 data codewords = 180 bytes of payload; a realistic
 * `otpauth://` URL is ~130. Anything larger throws {@link QrCapacityError} and
 * the enrollment screen falls back to manual secret entry.
 */

/** A square matrix of modules in row-major order; `true` is dark. */
export type QrMatrix = {
  readonly size: number;
  readonly modules: readonly boolean[];
};

/** Payload longer than version 9-M can hold. The caller shows a manual-entry fallback. */
export class QrCapacityError extends Error {
  constructor(byteLength: number) {
    super(`payload of ${byteLength} bytes exceeds QR version 9-M capacity (180 bytes)`);
    this.name = "QrCapacityError";
  }
}

export const MAX_QR_BYTES = 180;

/** Data codewords for level M, versions 1–9 (ISO/IEC 18004 tables 7 and 9). */
const M_DATA_CODEWORDS = [16, 28, 44, 64, 86, 108, 124, 154, 182] as const;
/** ECC codewords per block for level M, versions 1–9. */
const M_ECC_PER_BLOCK = [10, 16, 26, 18, 24, 16, 18, 22, 22] as const;
/** Error-correction block count for level M, versions 1–9. */
const M_BLOCKS = [1, 1, 1, 2, 2, 4, 4, 4, 5] as const;
/** Alignment-pattern centre coordinates per version (version 1 has none). */
const ALIGNMENT_CENTERS: readonly (readonly number[])[] = [
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
];

// --- GF(256) arithmetic, primitive polynomial 0x11D ---

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let value = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP[i] = value;
    LOG[value] = i;
    value <<= 1;
    if ((value & 0x100) !== 0) value ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) EXP[i] = EXP[i - 255] ?? 0;
}

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[((LOG[a] ?? 0) + (LOG[b] ?? 0)) % 255] ?? 0;
}

/** Generator polynomial of the given degree, coefficients high-order first. */
function generatorPoly(degree: number): number[] {
  let poly = [1];
  for (let i = 0; i < degree; i += 1) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j += 1) {
      const coefficient = poly[j] ?? 0;
      next[j] = (next[j] ?? 0) ^ coefficient;
      next[j + 1] = (next[j + 1] ?? 0) ^ gfMul(coefficient, EXP[i] ?? 0);
    }
    poly = next;
  }
  return poly;
}

/** Remainder of `data · x^degree` modulo the generator — the ECC codewords. */
export function reedSolomon(data: readonly number[], degree: number): number[] {
  const generator = generatorPoly(degree);
  const remainder = new Array<number>(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ (remainder[0] ?? 0);
    remainder.shift();
    remainder.push(0);
    for (let i = 0; i < degree; i += 1) {
      remainder[i] = (remainder[i] ?? 0) ^ gfMul(generator[i + 1] ?? 0, factor);
    }
  }
  return remainder;
}

// --- encoding ---

/** Smallest version (1–9) whose level-M capacity fits `byteLength`. */
export function pickVersion(byteLength: number): number {
  for (let version = 1; version <= M_DATA_CODEWORDS.length; version += 1) {
    // mode (4 bits) + character count (8 bits, byte mode below version 10) + data.
    if (4 + 8 + byteLength * 8 <= (M_DATA_CODEWORDS[version - 1] ?? 0) * 8) return version;
  }
  throw new QrCapacityError(byteLength);
}

/** Byte-mode bit stream, terminated and padded to the version's data capacity. */
function buildDataCodewords(bytes: Uint8Array, version: number): number[] {
  const totalData = M_DATA_CODEWORDS[version - 1] ?? 0;
  const bits: number[] = [];
  const push = (value: number, width: number): void => {
    for (let i = width - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };

  push(0b0100, 4);
  push(bytes.length, 8);
  for (const byte of bytes) push(byte, 8);
  push(0, Math.min(4, totalData * 8 - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | (bits[i + j] ?? 0);
    codewords.push(byte);
  }
  const PAD = [0xec, 0x11];
  for (let pad = 0; codewords.length < totalData; pad += 1) {
    codewords.push(PAD[pad % 2] ?? 0xec);
  }
  return codewords;
}

/** Splits into blocks, appends ECC, and interleaves as the standard requires. */
function interleave(dataCodewords: readonly number[], version: number): number[] {
  const blockCount = M_BLOCKS[version - 1] ?? 1;
  const eccPerBlock = M_ECC_PER_BLOCK[version - 1] ?? 10;
  const shortLength = Math.floor(dataCodewords.length / blockCount);
  const longBlocks = dataCodewords.length % blockCount;

  const dataBlocks: number[][] = [];
  const eccBlocks: number[][] = [];
  let offset = 0;
  for (let block = 0; block < blockCount; block += 1) {
    const length = shortLength + (block >= blockCount - longBlocks ? 1 : 0);
    const slice = dataCodewords.slice(offset, offset + length);
    offset += length;
    dataBlocks.push(slice);
    eccBlocks.push(reedSolomon(slice, eccPerBlock));
  }

  const result: number[] = [];
  for (let i = 0; i <= shortLength; i += 1) {
    for (const block of dataBlocks) {
      const value = block[i];
      if (value !== undefined) result.push(value);
    }
  }
  for (let i = 0; i < eccPerBlock; i += 1) {
    for (const block of eccBlocks) result.push(block[i] ?? 0);
  }
  return result;
}

// --- matrix construction ---

type Grid = {
  readonly size: number;
  readonly modules: boolean[];
  readonly reserved: boolean[];
};

function createGrid(size: number): Grid {
  return {
    size,
    modules: new Array<boolean>(size * size).fill(false),
    reserved: new Array<boolean>(size * size).fill(false),
  };
}

function setModule(grid: Grid, x: number, y: number, dark: boolean): void {
  if (x < 0 || y < 0 || x >= grid.size || y >= grid.size) return;
  const index = y * grid.size + x;
  grid.modules[index] = dark;
  grid.reserved[index] = true;
}

function placeFinder(grid: Grid, originX: number, originY: number): void {
  for (let dy = -1; dy <= 7; dy += 1) {
    for (let dx = -1; dx <= 7; dx += 1) {
      const inRing = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6;
      const onBorder = inRing && (dx === 0 || dx === 6 || dy === 0 || dy === 6);
      const inCore = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
      setModule(grid, originX + dx, originY + dy, onBorder || inCore);
    }
  }
}

function placeAlignment(grid: Grid, version: number): void {
  const centers = ALIGNMENT_CENTERS[version - 1] ?? [];
  const last = grid.size - 7;
  for (const cy of centers) {
    for (const cx of centers) {
      const overlapsFinder =
        (cx === 6 && cy === 6) || (cx === 6 && cy === last) || (cx === last && cy === 6);
      if (overlapsFinder) continue;
      for (let dy = -2; dy <= 2; dy += 1) {
        for (let dx = -2; dx <= 2; dx += 1) {
          setModule(grid, cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
  }
}

/** BCH(18,6) version information for versions 7 and above. */
export function versionInformation(version: number): number {
  let remainder = version;
  for (let i = 0; i < 12; i += 1) {
    remainder = (remainder << 1) ^ ((remainder >> 11) * 0x1f25);
  }
  return ((version << 12) | (remainder & 0xfff)) & 0x3ffff;
}

function placeVersionInformation(grid: Grid, version: number): void {
  if (version < 7) return;
  const bits = versionInformation(version);
  for (let i = 0; i < 18; i += 1) {
    const dark = ((bits >> i) & 1) === 1;
    const a = grid.size - 11 + (i % 3);
    const b = Math.floor(i / 3);
    setModule(grid, a, b, dark);
    setModule(grid, b, a, dark);
  }
}

function placeFunctionPatterns(grid: Grid, version: number): void {
  placeFinder(grid, 0, 0);
  placeFinder(grid, grid.size - 7, 0);
  placeFinder(grid, 0, grid.size - 7);
  for (let i = 8; i < grid.size - 8; i += 1) {
    const dark = i % 2 === 0;
    setModule(grid, i, 6, dark);
    setModule(grid, 6, i, dark);
  }
  placeAlignment(grid, version);
  placeVersionInformation(grid, version);

  // The two format strips are reserved here and written after masking; the
  // dark module at (8, size-8) is permanently set.
  for (let i = 0; i <= 8; i += 1) {
    if (i !== 6) {
      setModule(grid, 8, i, false);
      setModule(grid, i, 8, false);
    }
  }
  for (let i = 0; i < 8; i += 1) setModule(grid, grid.size - 1 - i, 8, false);
  for (let i = 0; i < 7; i += 1) setModule(grid, 8, grid.size - 1 - i, false);
  setModule(grid, 8, grid.size - 8, true);
}

/**
 * Which modules of a version belong to function patterns and are therefore
 * never masked and never carry data. Exported so a reader (the round-trip
 * test) can walk the same layout the writer used, instead of re-deriving it.
 */
export function functionPatternMask(version: number): {
  size: number;
  reserved: readonly boolean[];
} {
  const size = 17 + version * 4;
  const grid = createGrid(size);
  placeFunctionPatterns(grid, version);
  return { size, reserved: grid.reserved };
}

/** Level-M block structure of a version: data codewords, ECC per block, block count. */
export function blockLayout(version: number): {
  dataCodewords: number;
  eccPerBlock: number;
  blocks: number;
} {
  return {
    dataCodewords: M_DATA_CODEWORDS[version - 1] ?? 0,
    eccPerBlock: M_ECC_PER_BLOCK[version - 1] ?? 0,
    blocks: M_BLOCKS[version - 1] ?? 1,
  };
}

/** Column pairs, right to left, skipping the vertical timing column (6). */
export function columnPairs(size: number): number[] {
  const columns: number[] = [];
  let x = size - 1;
  while (x >= 1) {
    columns.push(x === 6 ? 5 : x);
    x -= x === 6 ? 3 : 2;
  }
  return columns;
}

/** Zig-zag placement of the interleaved codewords into the unreserved modules. */
function placeData(grid: Grid, codewords: readonly number[]): void {
  let bitIndex = 0;
  let upward = true;
  for (const right of columnPairs(grid.size)) {
    for (let step = 0; step < grid.size; step += 1) {
      const y: number = upward ? grid.size - 1 - step : step;
      for (const x of [right, right - 1]) {
        const index = y * grid.size + x;
        if (grid.reserved[index] === true) continue;
        const byte = codewords[bitIndex >> 3] ?? 0;
        grid.modules[index] = ((byte >> (7 - (bitIndex & 7))) & 1) === 1;
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

/** The eight standard data masks; `true` flips the module at (x, y). */
export function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
}

function applyMask(grid: Grid, mask: number): boolean[] {
  const masked = grid.modules.slice();
  for (let y = 0; y < grid.size; y += 1) {
    for (let x = 0; x < grid.size; x += 1) {
      const index = y * grid.size + x;
      if (grid.reserved[index] === true) continue;
      if (maskBit(mask, x, y)) masked[index] = !(masked[index] ?? false);
    }
  }
  return masked;
}

/** BCH(15,5) format information for level M and the chosen mask, XOR-masked. */
export function formatInformation(mask: number): number {
  const LEVEL_M = 0b00;
  const data = (LEVEL_M << 3) | mask;
  let remainder = data;
  for (let i = 0; i < 10; i += 1) {
    remainder = (remainder << 1) ^ ((remainder >> 9) * 0x537);
  }
  return (((data << 10) | (remainder & 0x3ff)) ^ 0x5412) & 0x7fff;
}

function writeFormat(modules: boolean[], size: number, mask: number): void {
  const bits = formatInformation(mask);
  const bit = (index: number): boolean => ((bits >> index) & 1) === 1;
  const set = (x: number, y: number, dark: boolean): void => {
    modules[y * size + x] = dark;
  };
  for (let i = 0; i <= 5; i += 1) set(8, i, bit(i));
  set(8, 7, bit(6));
  set(8, 8, bit(7));
  set(7, 8, bit(8));
  for (let i = 9; i < 15; i += 1) set(14 - i, 8, bit(i));
  for (let i = 0; i < 8; i += 1) set(size - 1 - i, 8, bit(i));
  for (let i = 8; i < 15; i += 1) set(8, size - 15 + i, bit(i));
  set(8, size - 8, true);
}

/** The four standard penalty rules; lower is better. */
function penalty(modules: readonly boolean[], size: number): number {
  const at = (x: number, y: number): boolean => modules[y * size + x] ?? false;
  let score = 0;

  for (let i = 0; i < size; i += 1) {
    for (const horizontal of [true, false]) {
      let run = 1;
      for (let j = 1; j < size; j += 1) {
        const current = horizontal ? at(j, i) : at(i, j);
        const previous = horizontal ? at(j - 1, i) : at(i, j - 1);
        if (current === previous) {
          run += 1;
          if (run === 5) score += 3;
          else if (run > 5) score += 1;
        } else {
          run = 1;
        }
      }
    }
  }

  for (let y = 0; y < size - 1; y += 1) {
    for (let x = 0; x < size - 1; x += 1) {
      const first = at(x, y);
      if (first === at(x + 1, y) && first === at(x, y + 1) && first === at(x + 1, y + 1)) {
        score += 3;
      }
    }
  }

  const FINDER = [true, false, true, true, true, false, true];
  const looksLikeFinder = (get: (offset: number) => boolean | undefined): boolean => {
    for (let i = 0; i < 7; i += 1) if (get(i) !== FINDER[i]) return false;
    const quiet = (offsets: readonly number[]): boolean =>
      offsets.every((offset) => get(offset) !== true);
    return quiet([-1, -2, -3, -4]) || quiet([7, 8, 9, 10]);
  };
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const inRange = (value: number): boolean => value >= 0 && value < size;
      if (x + 6 < size && looksLikeFinder((o) => (inRange(x + o) ? at(x + o, y) : undefined))) {
        score += 40;
      }
      if (y + 6 < size && looksLikeFinder((o) => (inRange(y + o) ? at(x, y + o) : undefined))) {
        score += 40;
      }
    }
  }

  const dark = modules.reduce((sum, module) => sum + (module ? 1 : 0), 0);
  score += Math.floor(Math.abs((dark * 100) / (size * size) - 50) / 5) * 10;
  return score;
}

/**
 * Encodes `text` as a QR matrix (byte mode, level M, smallest fitting version).
 *
 * Throws {@link QrCapacityError} when the payload exceeds version 9.
 */
export function encodeQr(text: string): QrMatrix {
  const bytes = new TextEncoder().encode(text);
  const version = pickVersion(bytes.length);
  const size = 17 + version * 4;

  const grid = createGrid(size);
  placeFunctionPatterns(grid, version);
  placeData(grid, interleave(buildDataCodewords(bytes, version), version));

  let best = grid.modules;
  let bestScore = Number.POSITIVE_INFINITY;
  for (let mask = 0; mask < 8; mask += 1) {
    const candidate = applyMask(grid, mask);
    writeFormat(candidate, size, mask);
    const score = penalty(candidate, size);
    if (score < bestScore) {
      bestScore = score;
      best = candidate;
    }
  }
  return { size, modules: best };
}
