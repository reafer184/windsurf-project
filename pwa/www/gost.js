/**
 * GOST R 34.12-2015 "Grasshopper" (Kuznyechik) block cipher
 * GOST R 34.11-2012 "Streebog-256" hash function
 * Pure JavaScript implementation, no external dependencies
 * All data stays local — no network calls
 *
 * References:
 *   RFC 7801 — GOST R 34.12-2015
 *   RFC 6986 — GOST R 34.11-2012
 */

// ─── GOST R 34.11-2012 Streebog-256 ──────────────────────────────────────────

const STREEBOG_IV_256 = new Uint8Array(64).fill(0x01);

const STREEBOG_C = [
  new Uint8Array([0xb1,0x08,0x5b,0xda,0x1e,0xca,0xda,0xe9,0xeb,0xcb,0x2f,0x81,0xc0,0x65,0x7c,0x1f,0x2f,0x6a,0x76,0x43,0x2e,0x45,0xd0,0x16,0x71,0x4e,0xb8,0x8d,0x75,0x85,0xc4,0xfc,0x4b,0x7c,0xe0,0x91,0x92,0x67,0x69,0x01,0xa2,0x42,0x2a,0x08,0xa4,0x60,0xd3,0x15,0x05,0x76,0x74,0x36,0xcc,0x74,0x4d,0x23,0xdd,0x80,0x65,0x59,0xf2,0xa6,0x45,0x07]),
  new Uint8Array([0x6f,0xa3,0xb5,0x8a,0xa9,0x9d,0x2f,0x1a,0x4f,0xe3,0x9d,0x46,0x0f,0x70,0xb5,0xd7,0xf3,0xfe,0xea,0x72,0x0a,0x23,0x2b,0x98,0x61,0xd5,0x5e,0x0f,0x16,0xb5,0x01,0x31,0x9a,0xb5,0x17,0x6b,0x12,0xd6,0x99,0x58,0x5c,0xb5,0x61,0xc2,0xdb,0x0a,0xa7,0xca,0x55,0xdd,0xa2,0x1b,0xd7,0xcb,0xcd,0x56,0xe6,0x79,0x04,0x70,0x21,0xb1,0x9b,0xb7]),
  new Uint8Array([0xf5,0x74,0xdc,0xac,0x2b,0xce,0x2f,0xc7,0x0a,0x39,0xfc,0x28,0x6a,0x3d,0x84,0x35,0x06,0xf1,0x5e,0x5f,0x52,0x9c,0x1f,0x8b,0xf2,0xea,0x75,0x14,0xb1,0x29,0x7b,0x7b,0xd3,0xe2,0x0f,0xe4,0x90,0x35,0x9e,0xb1,0xc1,0xc9,0x3a,0x37,0x60,0x62,0xdb,0x09,0xc2,0xce,0x78,0x96,0x25,0x0e,0x0a,0x07,0x06,0x46,0x48,0x21,0xcc,0xa9,0x05,0x0d]),
  new Uint8Array([0xca,0x84,0xa8,0x9f,0x9b,0xcf,0xc1,0x4c,0x56,0x59,0x08,0xd9,0x31,0xba,0x56,0x56,0xca,0x84,0xa8,0x9f,0x9b,0xcf,0xc1,0x4c,0x56,0x59,0x08,0xd9,0x31,0xba,0x56,0x56,0xca,0x84,0xa8,0x9f,0x9b,0xcf,0xc1,0x4c,0x56,0x59,0x08,0xd9,0x31,0xba,0x56,0x56,0xca,0x84,0xa8,0x9f,0x9b,0xcf,0xc1,0x4c,0x56,0x59,0x08,0xd9,0x31,0xba,0x56,0x56]),
];

// Streebog S-box
const STREEBOG_SBOX = new Uint8Array([
  0xfc,0xee,0xdd,0x11,0xcf,0x6e,0x31,0x16,0xfb,0xc4,0xfa,0xda,0x23,0xc5,0x04,0x4d,
  0xe9,0x77,0xf0,0xdb,0x93,0x2e,0x99,0xba,0x17,0x36,0xf1,0xbb,0x14,0xcd,0x5f,0xc1,
  0xf9,0x18,0x65,0x5a,0xe2,0x5c,0xef,0x21,0x81,0x1c,0x3c,0x42,0x8b,0x01,0x8e,0x4f,
  0x05,0x84,0x02,0xae,0xe3,0x6a,0x8f,0xa0,0x06,0x0b,0xed,0x98,0x7f,0xd4,0xd3,0x1f,
  0xeb,0x34,0x2c,0x51,0xea,0xc8,0x48,0xab,0xf2,0x2a,0x68,0xa2,0xfd,0x3a,0xce,0xcc,
  0xb5,0x70,0x0e,0x56,0x08,0x0c,0x76,0x12,0xbf,0x72,0x13,0x47,0x9c,0xb7,0x5d,0x87,
  0x15,0xa1,0x96,0x29,0x10,0x7b,0x9e,0xc6,0x0f,0xd1,0xcb,0x2b,0xad,0xa4,0x4b,0xb8,
  0x1a,0xbc,0xb6,0x66,0x80,0x60,0x00,0x3f,0xec,0xb2,0x78,0xb3,0x74,0x90,0xfe,0x86,
  0xa8,0xd8,0x35,0x25,0xe5,0xa3,0xdb,0xdf,0x94,0x38,0x97,0xe9,0x1e,0x33,0x6b,0xd7,
  0xde,0xac,0x4a,0x39,0x52,0x7e,0xa7,0xd0,0x45,0xf3,0x8c,0xb9,0xf8,0xe7,0x75,0xea,
  0x9f,0x58,0xa6,0x64,0xf4,0xc2,0x1b,0x40,0x53,0x7c,0x3e,0x1d,0x6d,0xd2,0x43,0x9b,
  0x9d,0x30,0x37,0xbe,0x22,0x69,0xd5,0x82,0x67,0xb4,0x32,0xff,0x19,0x8a,0x8d,0xd6,
  0x9a,0xc9,0x44,0x3b,0x54,0x50,0xa9,0xaf,0xca,0x6f,0x28,0x07,0x09,0x5e,0x63,0xe1,
  0xe6,0x55,0x71,0x7a,0xb1,0x2d,0xf6,0x7d,0x0d,0x57,0xb2,0x3d,0x46,0x8e,0x03,0xdc,
  0xae,0xa0,0x41,0x73,0x20,0xe8,0xf5,0x26,0xc3,0x24,0xf7,0x27,0x92,0x5f,0x6c,0xd9,
  0xa5,0xe4,0x79,0xc7,0x88,0x91,0xf6,0xe1,0xad,0xb0,0x83,0x6c,0x4c,0x2a,0x62,0x89,
]);

const STREEBOG_PS = new Uint8Array(64);
for (let i = 0; i < 64; i++) {
  const col = i & 7;
  const row = i >> 3;
  STREEBOG_PS[i] = STREEBOG_SBOX[((row + col * 8) & 63) | (i & ~63 ? 0 : 0)];
}

// GF(2^8) multiplication for Streebog L-transform
const STREEBOG_MUL_TABLE = (() => {
  const irreducible = 0x1C3;
  const t = new Uint8Array(256 * 256);
  for (let a = 0; a < 256; a++) {
    for (let b = 0; b < 256; b++) {
      let result = 0, aa = a, bb = b;
      for (let i = 0; i < 8; i++) {
        if (bb & 1) result ^= aa;
        const hi = aa & 0x80;
        aa = (aa << 1) & 0xff;
        if (hi) aa ^= (irreducible & 0xff);
        bb >>= 1;
      }
      t[a * 256 + b] = result;
    }
  }
  return t;
})();

// Streebog L-transform coefficients
const STREEBOG_L_COEF = new Uint8Array([
  0x94,0x20,0x85,0x10,0xc2,0xc0,0x01,0xfb
]);

function streebogL(block) {
  // Apply L-transform to 64-byte block (8 rows of 8 bytes)
  const out = new Uint8Array(64);
  for (let col = 0; col < 8; col++) {
    for (let row = 0; row < 8; row++) {
      let val = 0;
      for (let k = 0; k < 8; k++) {
        val ^= STREEBOG_MUL_TABLE[block[k * 8 + col] * 256 + STREEBOG_L_COEF[(row + k) & 7]];
      }
      out[row * 8 + col] = val;
    }
  }
  return out;
}

function streebogS(block) {
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = STREEBOG_SBOX[block[i]];
  return out;
}

function streebogP(block) {
  const out = new Uint8Array(64);
  const tau = [
    0,8,16,24,32,40,48,56, 1,9,17,25,33,41,49,57,
    2,10,18,26,34,42,50,58, 3,11,19,27,35,43,51,59,
    4,12,20,28,36,44,52,60, 5,13,21,29,37,45,53,61,
    6,14,22,30,38,46,54,62, 7,15,23,31,39,47,55,63
  ];
  for (let i = 0; i < 64; i++) out[i] = block[tau[i]];
  return out;
}

function streebogXor(a, b) {
  const out = new Uint8Array(64);
  for (let i = 0; i < 64; i++) out[i] = a[i] ^ b[i];
  return out;
}

function streebogE(K, m) {
  let state = streebogXor(K, m);
  for (let r = 0; r < 12; r++) {
    state = streebogL(streebogP(streebogS(state)));
    // Key schedule: apply round constant
    let Kn = streebogXor(K, STREEBOG_C[r % STREEBOG_C.length]);
    Kn = streebogL(streebogP(streebogS(Kn)));
    K = Kn;
    state = streebogXor(state, K);
  }
  return state;
}

function streebogG(h, N, m) {
  const Nxh = streebogXor(N, h);
  const K = streebogL(streebogP(streebogS(Nxh)));
  const t = streebogE(K, m);
  return streebogXor(streebogXor(t, h), m);
}

function streebogAddMod512(a, b) {
  const out = new Uint8Array(64);
  let carry = 0;
  for (let i = 63; i >= 0; i--) {
    const sum = a[i] + b[i] + carry;
    out[i] = sum & 0xff;
    carry = sum >> 8;
  }
  return out;
}

/**
 * GOST R 34.11-2012 Streebog-256
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte digest
 */
export function streebog256(data) {
  // Initialization
  let h = new Uint8Array(64).fill(0x01); // IV for 256-bit
  let N = new Uint8Array(64);
  let Sigma = new Uint8Array(64);

  let offset = 0;
  const msgLen = data.length;

  // Process full 512-bit (64-byte) blocks
  while (offset + 64 <= msgLen) {
    const block = data.slice(offset, offset + 64);
    // Reverse block (little-endian per spec)
    const m = block.slice().reverse();
    h = streebogG(h, N, m);
    // N += 512
    const cnt = new Uint8Array(64);
    cnt[63] = 0x02; cnt[62] = 0x00; // 512 in bits = 0x0200
    N = streebogAddMod512(N, cnt);
    Sigma = streebogAddMod512(Sigma, m);
    offset += 64;
  }

  // Padding
  const remaining = msgLen - offset;
  const lastBlock = new Uint8Array(64);
  for (let i = 0; i < remaining; i++) lastBlock[63 - i] = data[msgLen - 1 - i];
  lastBlock[63 - remaining] = 0x01;

  h = streebogG(h, N, lastBlock);

  const bitLen = new Uint8Array(64);
  const totalBits = msgLen * 8;
  bitLen[63] = totalBits & 0xff;
  bitLen[62] = (totalBits >> 8) & 0xff;
  bitLen[61] = (totalBits >> 16) & 0xff;
  bitLen[60] = (totalBits >> 24) & 0xff;
  N = streebogAddMod512(N, bitLen);
  Sigma = streebogAddMod512(Sigma, lastBlock);

  h = streebogG(h, new Uint8Array(64), N);
  h = streebogG(h, new Uint8Array(64), Sigma);

  // Return first 32 bytes (256-bit digest), reversed back
  return h.slice(0, 32).reverse();
}

// ─── GOST R 34.12-2015 Grasshopper (Kuznyechik) ───────────────────────────────

// Grasshopper S-box (pi)
const GH_PI = new Uint8Array([
  0xFC,0xEE,0xDD,0x11,0xCF,0x6E,0x31,0x16,0xFB,0xC4,0xFA,0xDA,0x23,0xC5,0x04,0x4D,
  0xE9,0x77,0xF0,0xDB,0x93,0x2E,0x99,0xBA,0x17,0x36,0xF1,0xBB,0x14,0xCD,0x5F,0xC1,
  0xF9,0x18,0x65,0x5A,0xE2,0x5C,0xEF,0x21,0x81,0x1C,0x3C,0x42,0x8B,0x01,0x8E,0x4F,
  0x05,0x84,0x02,0xAE,0xE3,0x6A,0x8F,0xA0,0x06,0x0B,0xED,0x98,0x7F,0xD4,0xD3,0x1F,
  0xEB,0x34,0x2C,0x51,0xEA,0xC8,0x48,0xAB,0xF2,0x2A,0x68,0xA2,0xFD,0x3A,0xCE,0xCC,
  0xB5,0x70,0x0E,0x56,0x08,0x0C,0x76,0x12,0xBF,0x72,0x13,0x47,0x9C,0xB7,0x5D,0x87,
  0x15,0xA1,0x96,0x29,0x10,0x7B,0x9E,0xC6,0x0F,0xD1,0xCB,0x2B,0xAD,0xA4,0x4B,0xB8,
  0x1A,0xBC,0xB6,0x66,0x80,0x60,0x00,0x3F,0xEC,0xB2,0x78,0xB3,0x74,0x90,0xFE,0x86,
  0xA8,0xD8,0x35,0x25,0xE5,0xA3,0xDB,0xDF,0x94,0x38,0x97,0xE9,0x1E,0x33,0x6B,0xD7,
  0xDE,0xAC,0x4A,0x39,0x52,0x7E,0xA7,0xD0,0x45,0xF3,0x8C,0xB9,0xF8,0xE7,0x75,0xEA,
  0x9F,0x58,0xA6,0x64,0xF4,0xC2,0x1B,0x40,0x53,0x7C,0x3E,0x1D,0x6D,0xD2,0x43,0x9B,
  0x9D,0x30,0x37,0xBE,0x22,0x69,0xD5,0x82,0x67,0xB4,0x32,0xFF,0x19,0x8A,0x8D,0xD6,
  0x9A,0xC9,0x44,0x3B,0x54,0x50,0xA9,0xAF,0xCA,0x6F,0x28,0x07,0x09,0x5E,0x63,0xE1,
  0xE6,0x55,0x71,0x7A,0xB1,0x2D,0xF6,0x7D,0x0D,0x57,0xB2,0x3D,0x46,0x8E,0x03,0xDC,
  0xAE,0xA0,0x41,0x73,0x20,0xE8,0xF5,0x26,0xC3,0x24,0xF7,0x27,0x92,0x5F,0x6C,0xD9,
  0xA5,0xE4,0x79,0xC7,0x88,0x91,0xF6,0xE1,0xAD,0xB0,0x83,0x6C,0x4C,0x2A,0x62,0x89,
]);

// Inverse S-box
const GH_PI_INV = new Uint8Array(256);
for (let i = 0; i < 256; i++) GH_PI_INV[GH_PI[i]] = i;

// GF(2^8) multiply for Grasshopper (poly: x^8 + x^7 + x^6 + x + 1 = 0x1C3)
const GH_GF_MUL = (a, b) => {
  let result = 0;
  let aa = a, bb = b;
  for (let i = 0; i < 8; i++) {
    if (bb & 1) result ^= aa;
    const hi = aa & 0x80;
    aa = (aa << 1) & 0xff;
    if (hi) aa ^= 0xc3; // 0x1C3 & 0xff = 0xc3
    bb >>= 1;
  }
  return result;
};

// L-transform coefficients (from RFC 7801)
const GH_L_COEF = new Uint8Array([0x94,0x20,0x85,0x10,0xc2,0xc0,0x01,0xfb,0x01,0xc0,0xc2,0x10,0x85,0x20,0x94,0x01]);

function ghR(block) {
  // R-transform: LFSR shift with feedback
  let feedback = 0;
  for (let i = 0; i < 16; i++) feedback ^= GH_GF_MUL(block[i], GH_L_COEF[i]);
  const out = new Uint8Array(16);
  out[0] = feedback;
  for (let i = 1; i < 16; i++) out[i] = block[i - 1];
  return out;
}

function ghRInv(block) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 15; i++) out[i] = block[i + 1];
  out[15] = 0;
  let feedback = 0;
  for (let i = 0; i < 16; i++) feedback ^= GH_GF_MUL(out[i], GH_L_COEF[i]);
  out[15] = feedback ^ block[0];
  return out;
}

function ghL(block) {
  let state = block.slice();
  for (let i = 0; i < 16; i++) state = ghR(state);
  return state;
}

function ghLInv(block) {
  let state = block.slice();
  for (let i = 0; i < 16; i++) state = ghRInv(state);
  return state;
}

function ghS(block) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = GH_PI[block[i]];
  return out;
}

function ghSInv(block) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = GH_PI_INV[block[i]];
  return out;
}

function ghX(a, b) {
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = a[i] ^ b[i];
  return out;
}

// Constants C[i] for key schedule
const GH_C = (() => {
  const c = [];
  for (let i = 1; i <= 32; i++) {
    const v = new Uint8Array(16);
    v[15] = i;
    c.push(ghL(v));
  }
  return c;
})();

/**
 * Expand 256-bit key into 10 round keys
 * @param {Uint8Array} key - 32 bytes
 * @returns {Uint8Array[]} 10 round keys, each 16 bytes
 */
export function ghKeySchedule(key) {
  const K = [];
  K[0] = key.slice(0, 16);
  K[1] = key.slice(16, 32);
  const roundKeys = [K[0].slice(), K[1].slice()];
  for (let i = 0; i < 4; i++) {
    let a = K[0].slice(), b = K[1].slice();
    for (let j = 0; j < 8; j++) {
      const c = GH_C[8 * i + j];
      const t = ghL(ghS(ghX(a, c)));
      const newA = ghX(t, b);
      b = a;
      a = newA;
    }
    K[0] = a;
    K[1] = b;
    roundKeys.push(K[0].slice());
    roundKeys.push(K[1].slice());
  }
  return roundKeys;
}

/**
 * Encrypt one 16-byte block with Grasshopper
 * @param {Uint8Array} block - 16 bytes plaintext
 * @param {Uint8Array[]} roundKeys - from ghKeySchedule
 * @returns {Uint8Array} 16 bytes ciphertext
 */
export function ghEncryptBlock(block, roundKeys) {
  let state = block.slice();
  for (let i = 0; i < 9; i++) {
    state = ghL(ghS(ghX(state, roundKeys[i])));
  }
  return ghX(state, roundKeys[9]);
}

/**
 * Decrypt one 16-byte block with Grasshopper
 */
export function ghDecryptBlock(block, roundKeys) {
  let state = block.slice();
  for (let i = 9; i > 0; i--) {
    state = ghSInv(ghLInv(ghX(state, roundKeys[i])));
  }
  return ghX(state, roundKeys[0]);
}

// ─── CTR mode (counter) ──────────────────────────────────────────────────────
// ГОСТ Р 34.13-2015, режим гаммирования (CTR)
// IV = 8 bytes, counter appended as 8-byte little-endian

function ctrIncrement(counter) {
  const out = counter.slice();
  for (let i = 15; i >= 8; i--) {
    out[i] = (out[i] + 1) & 0xff;
    if (out[i] !== 0) break;
  }
  return out;
}

/**
 * Grasshopper CTR encrypt/decrypt (symmetric operation)
 * @param {Uint8Array} data
 * @param {Uint8Array[]} roundKeys
 * @param {Uint8Array} iv - 8 bytes
 * @returns {Uint8Array}
 */
export function ghCTR(data, roundKeys, iv) {
  const counter = new Uint8Array(16);
  counter.set(iv, 0); // upper 8 bytes = IV, lower 8 = counter (starts at 0)
  const out = new Uint8Array(data.length);
  let pos = 0;
  while (pos < data.length) {
    const keystream = ghEncryptBlock(counter, roundKeys);
    const blockLen = Math.min(16, data.length - pos);
    for (let i = 0; i < blockLen; i++) out[pos + i] = data[pos + i] ^ keystream[i];
    pos += blockLen;
    // increment lower 8 bytes as little-endian counter
    for (let i = 15; i >= 8; i--) {
      counter[i] = (counter[i] + 1) & 0xff;
      if (counter[i] !== 0) break;
    }
  }
  return out;
}

// ─── MAC (OMAC / CMAC over Grasshopper) ──────────────────────────────────────
// ГОСТ Р 34.13-2015, режим имитовставки

function ghOMAC(data, roundKeys) {
  const zero = new Uint8Array(16);
  const L = ghEncryptBlock(zero, roundKeys);

  const genSubkey = (key) => {
    const out = new Uint8Array(16);
    const msb = (key[0] & 0x80) !== 0;
    for (let i = 0; i < 15; i++) out[i] = ((key[i] << 1) | (key[i + 1] >> 7)) & 0xff;
    out[15] = (key[15] << 1) & 0xff;
    if (msb) out[15] ^= 0x87;
    return out;
  };

  const K1 = genSubkey(L);
  const K2 = genSubkey(K1);

  const n = Math.max(1, Math.ceil(data.length / 16));
  const lastLen = ((data.length - 1) & 15) + 1;
  const flag = data.length % 16 === 0 && data.length > 0;

  const last = new Uint8Array(16);
  last.set(data.slice((n - 1) * 16, (n - 1) * 16 + lastLen));
  if (!flag) last[lastLen] = 0x80;

  const subkey = flag ? K1 : K2;
  for (let i = 0; i < 16; i++) last[i] ^= subkey[i];

  let mac = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) {
    const block = data.slice(i * 16, (i + 1) * 16);
    for (let j = 0; j < 16; j++) mac[j] ^= block[j];
    mac = ghEncryptBlock(mac, roundKeys);
  }
  for (let j = 0; j < 16; j++) mac[j] ^= last[j];
  return ghEncryptBlock(mac, roundKeys);
}

// ─── High-level API ──────────────────────────────────────────────────────────

const PBKDF2_ITERATIONS = 100000; // ГОСТ-совместимый KDF
const SALT_STATIC = new TextEncoder().encode('gosuslugi-totp-salt-v1-gost');

/**
 * Derive 32-byte key from password using Streebog-256 + PBKDF2-like stretching
 * (PBKDF2 with Streebog-256 as PRF — аналог RFC 8018 с ГОСТ хэшем)
 */
export async function deriveKeyGOST(password) {
  const passBytes = new TextEncoder().encode(password);

  // Round 0: H(password || salt)
  const combined = new Uint8Array(passBytes.length + SALT_STATIC.length);
  combined.set(passBytes);
  combined.set(SALT_STATIC, passBytes.length);
  let key = streebog256(combined);

  // Stretch: 100 000 iterations of Streebog-256
  for (let i = 0; i < PBKDF2_ITERATIONS; i++) {
    const iBytes = new Uint8Array(4);
    iBytes[0] = (i >> 24) & 0xff;
    iBytes[1] = (i >> 16) & 0xff;
    iBytes[2] = (i >> 8) & 0xff;
    iBytes[3] = i & 0xff;
    const round = new Uint8Array(key.length + iBytes.length);
    round.set(key);
    round.set(iBytes, key.length);
    key = streebog256(round);
  }
  return key; // 32 bytes
}

/**
 * Encrypt plaintext string with Grasshopper CTR + OMAC integrity tag
 * Returns { ciphertext: base64, iv: base64, mac: base64, algo: 'GOST-R-34.12-2015' }
 */
export async function gostEncrypt(plaintext, password) {
  const key = await deriveKeyGOST(password);
  const roundKeys = ghKeySchedule(key);

  const iv = crypto.getRandomValues(new Uint8Array(8));
  const data = new TextEncoder().encode(plaintext);

  const ciphertext = ghCTR(data, roundKeys, iv);
  const mac = ghOMAC(ciphertext, roundKeys).slice(0, 8); // 64-bit imito tag

  const toB64 = (bytes) => btoa(String.fromCharCode(...bytes));
  return {
    ciphertext: toB64(ciphertext),
    iv: toB64(iv),
    mac: toB64(mac),
    algo: 'GOST-R-34.12-2015'
  };
}

/**
 * Decrypt, verifying MAC
 */
export async function gostDecrypt(ciphertext, iv, mac, password) {
  const fromB64 = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0));

  const key = await deriveKeyGOST(password);
  const roundKeys = ghKeySchedule(key);

  const ciphertextBytes = fromB64(ciphertext);
  const ivBytes = fromB64(iv);
  const macBytes = fromB64(mac);

  // Verify MAC first
  const expectedMac = ghOMAC(ciphertextBytes, roundKeys).slice(0, 8);
  let macOk = true;
  for (let i = 0; i < 8; i++) {
    if (expectedMac[i] !== macBytes[i]) { macOk = false; break; }
  }
  if (!macOk) throw new Error('Ошибка целостности: имитовставка не совпадает. Неверный пароль или повреждённые данные.');

  const plaintext = ghCTR(ciphertextBytes, roundKeys, ivBytes);
  return new TextDecoder().decode(plaintext);
}
