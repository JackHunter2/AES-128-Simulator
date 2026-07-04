/* =====================================================================
   aes.js — MESIN AES-128 (WAJIB DIISI SENDIRI)
   =====================================================================
   File ini adalah bagian yang dinilai sebagai "kebenaran algoritma".
   Sesuai ketentuan tugas, kamu WAJIB menulis sendiri:
     - keyExpansion
     - subBytes / invSubBytes
     - shiftRows / invShiftRows
     - mixColumns / invMixColumns
     - addRoundKey
     - gmul (perkalian GF(2^8), dipakai di dalam mixColumns)
     - encryptBlock / decryptBlock (orkestrasi round)

   Tabel SBOX, INV_SBOX, RCON sudah tersedia dari aes-tables.js.

   KONTRAK DENGAN UI (app.js) — ini bagian PENTING, jangan diubah
   bentuk return-nya, supaya visualisasi State Matrix otomatis bekerja
   begitu fungsi kamu benar:

   AES.keyExpansion(keyBytes)  // keyBytes: Uint8Array(16)
     -> {
          roundKeys: [Uint8Array(16), ...] panjang 11  // RK0 .. RK10
          words:     [Uint8Array(4), ...]  panjang 44  // W0 .. W43
          log: [                                        // hanya untuk word "g"
            {
              wordIndex,          // 4, 8, 12, ... 40
              prevWord,           // W[i-1] sebelum diproses (Uint8Array(4))
              rotWord,            // hasil RotWord(prevWord)
              subWord,            // hasil SubWord(rotWord)
              rcon,               // [Rcon[i/4],0,0,0]
              xorResult           // subWord XOR rcon  (ini yang di-XOR ke W[i-4])
            }, ...
          ]
        }

   AES.subBytes(state)      -> Uint8Array(16)   // state: Uint8Array(16)
   AES.invSubBytes(state)   -> Uint8Array(16)
   AES.shiftRows(state)     -> Uint8Array(16)
   AES.invShiftRows(state)  -> Uint8Array(16)
   AES.mixColumns(state)    -> Uint8Array(16)
   AES.invMixColumns(state) -> Uint8Array(16)
   AES.addRoundKey(state, roundKey) -> Uint8Array(16)
   AES.gmul(a, b) -> number (0-255)

   AES.encryptBlock(plaintext, key)  // keduanya Uint8Array(16)
     -> {
          ciphertext: Uint8Array(16),
          keyExpansion: <hasil AES.keyExpansion>,
          rounds: [
            {
              index: 0, label: 'Initial Round',
              steps: [
                { op: 'AddRoundKey', before: Uint8Array(16), after: Uint8Array(16), roundKeyIndex: 0 }
              ]
            },
            {
              index: 1, label: 'Round 1',
              steps: [
                { op: 'SubBytes',    before, after },
                { op: 'ShiftRows',   before, after },
                { op: 'MixColumns',  before, after },
                { op: 'AddRoundKey', before, after, roundKeyIndex: 1 }
              ]
            },
            ... sampai index 9 ...
            {
              index: 10, label: 'Round 10 (Final)',
              steps: [
                { op: 'SubBytes',    before, after },
                { op: 'ShiftRows',   before, after },
                { op: 'AddRoundKey', before, after, roundKeyIndex: 10 }   // tanpa MixColumns
              ]
            }
          ]
        }

   AES.decryptBlock(ciphertext, key) -> bentuk serupa, gunakan op:
        'AddRoundKey' | 'InvShiftRows' | 'InvSubBytes' | 'InvMixColumns'
        urutan sesuai C.3(c) pada soal.

   Semua array "before"/"after" merepresentasikan STATE 16 byte dalam
   urutan KOLOM (column-major), sama seperti definisi FIPS-197:
     state[0] state[4] state[8]  state[12]
     state[1] state[5] state[9]  state[13]
     state[2] state[6] state[10] state[14]
     state[3] state[7] state[11] state[15]
   ===================================================================== */

const AES = {};

function cloneState(state) {
  return new Uint8Array(state);
}

function xorBytes(left, right) {
  const result = new Uint8Array(left.length);
  for (let i = 0; i < left.length; i++) {
    result[i] = left[i] ^ right[i];
  }
  return result;
}

function rotWord(word) {
  return new Uint8Array([word[1], word[2], word[3], word[0]]);
}

function subWord(word) {
  return new Uint8Array([
    SBOX[word[0]],
    SBOX[word[1]],
    SBOX[word[2]],
    SBOX[word[3]],
  ]);
}

function makeStep(op, before, after, extra) {
  return Object.assign({ op, before, after }, extra || {});
}

/* ---------------------------------------------------------------------
 * 1) GALOIS FIELD MULTIPLICATION — GF(2^8)
 * ---------------------------------------------------------------------
 * Dasar dari MixColumns. Kalikan dua byte di dalam field GF(2^8) dengan
 * polinomial irreducible x^8 + x^4 + x^3 + x + 1 (0x11B), sebagaimana
 * dijelaskan di bagian G.3 soal.
 *
 * Konsep (bukan kode): perkalian biasa antar dua bilangan biner, lalu
 * setiap kali hasil sementara melebihi 8 bit, hasil di-reduce dengan
 * meng-XOR-kan 0x11B pada posisi bit yang meluap. Cara umum: algoritma
 * "peasant multiplication" — geser & XOR bit demi bit (8 iterasi).
 * ------------------------------------------------------------------- */
AES.gmul = function (a, b) {
  a &= 0xff;
  b &= 0xff;
  let product = 0;

  for (let i = 0; i < 8; i++) {
    if (b & 1) {
      product ^= a;
    }

    const carry = a & 0x80;
    a = (a << 1) & 0xff;
    if (carry) {
      a ^= 0x1b;
    }
    b >>= 1;
  }

  return product & 0xff;
};

/* ---------------------------------------------------------------------
 * 2) SUBBYTES / INVSUBBYTES
 * ---------------------------------------------------------------------
 * SubBytes mengganti setiap byte pada State dengan nilai pada SBOX di
 * posisi yang sama dengan nilai byte tersebut (byte 0x53 -> SBOX[0x53]).
 * InvSubBytes melakukan hal yang sama tapi dengan INV_SBOX.
 * ------------------------------------------------------------------- */
AES.subBytes = function (state) {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = SBOX[state[i]];
  }
  return result;
};

AES.invSubBytes = function (state) {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = INV_SBOX[state[i]];
  }
  return result;
};

/* ---------------------------------------------------------------------
 * 3) SHIFTROWS / INVSHIFTROWS
 * ---------------------------------------------------------------------
 * State dipandang sebagai matriks 4x4 (column-major, lihat catatan di
 * atas). ShiftRows menggeser tiap BARIS secara siklik ke KIRI:
 *   baris 0 -> geser 0   baris 1 -> geser 1
 *   baris 2 -> geser 2   baris 3 -> geser 3
 * InvShiftRows menggeser ke arah sebaliknya (kanan) dengan jumlah yang sama.
 * ------------------------------------------------------------------- */
AES.shiftRows = function (state) {
  const result = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let column = 0; column < 4; column++) {
      result[column * 4 + row] = state[((column + row) % 4) * 4 + row];
    }
  }
  return result;
};

AES.invShiftRows = function (state) {
  const result = new Uint8Array(16);
  for (let row = 0; row < 4; row++) {
    for (let column = 0; column < 4; column++) {
      result[column * 4 + row] = state[((column - row + 4) % 4) * 4 + row];
    }
  }
  return result;
};

/* ---------------------------------------------------------------------
 * 4) MIXCOLUMNS / INVMIXCOLUMNS
 * ---------------------------------------------------------------------
 * Setiap KOLOM (4 byte) State dikalikan dengan matriks tetap di GF(2^8)
 * (lihat bagian G.3 soal untuk matriks forward; matriks invers untuk
 * InvMixColumns adalah [0E 0B 0D 09 / 09 0E 0B 0D / 0D 09 0E 0B /
 * 0B 0D 09 0E]). Gunakan AES.gmul yang sudah kamu isi di atas.
 * ------------------------------------------------------------------- */
AES.mixColumns = function (state) {
  const result = new Uint8Array(16);

  for (let column = 0; column < 4; column++) {
    const offset = column * 4;
    const s0 = state[offset];
    const s1 = state[offset + 1];
    const s2 = state[offset + 2];
    const s3 = state[offset + 3];

    result[offset] = AES.gmul(0x02, s0) ^ AES.gmul(0x03, s1) ^ s2 ^ s3;
    result[offset + 1] = s0 ^ AES.gmul(0x02, s1) ^ AES.gmul(0x03, s2) ^ s3;
    result[offset + 2] = s0 ^ s1 ^ AES.gmul(0x02, s2) ^ AES.gmul(0x03, s3);
    result[offset + 3] = AES.gmul(0x03, s0) ^ s1 ^ s2 ^ AES.gmul(0x02, s3);
  }

  return result;
};

AES.invMixColumns = function (state) {
  const result = new Uint8Array(16);

  for (let column = 0; column < 4; column++) {
    const offset = column * 4;
    const s0 = state[offset];
    const s1 = state[offset + 1];
    const s2 = state[offset + 2];
    const s3 = state[offset + 3];

    result[offset] = AES.gmul(0x0e, s0) ^ AES.gmul(0x0b, s1) ^ AES.gmul(0x0d, s2) ^ AES.gmul(0x09, s3);
    result[offset + 1] = AES.gmul(0x09, s0) ^ AES.gmul(0x0e, s1) ^ AES.gmul(0x0b, s2) ^ AES.gmul(0x0d, s3);
    result[offset + 2] = AES.gmul(0x0d, s0) ^ AES.gmul(0x09, s1) ^ AES.gmul(0x0e, s2) ^ AES.gmul(0x0b, s3);
    result[offset + 3] = AES.gmul(0x0b, s0) ^ AES.gmul(0x0d, s1) ^ AES.gmul(0x09, s2) ^ AES.gmul(0x0e, s3);
  }

  return result;
};

/* ---------------------------------------------------------------------
 * 5) ADDROUNDKEY
 * ---------------------------------------------------------------------
 * XOR State dengan Round Key yang bersesuaian, byte demi byte.
 * ------------------------------------------------------------------- */
AES.addRoundKey = function (state, roundKey) {
  return xorBytes(state, roundKey);
};

/* ---------------------------------------------------------------------
 * 6) KEY EXPANSION
 * ---------------------------------------------------------------------
 * Membangkitkan 44 word (W0..W43) dari 4 word kunci awal (W0..W3).
 * Untuk setiap i kelipatan 4 (i = 4,8,...,40):
 *   temp = W[i-1]
 *   temp = SubWord(RotWord(temp)) XOR Rcon[i/4]
 *   W[i] = W[i-4] XOR temp
 * Untuk i lainnya: W[i] = W[i-4] XOR W[i-1]
 *
 * RotWord([a,b,c,d]) = [b,c,d,a]
 * SubWord([a,b,c,d]) = [SBOX[a],SBOX[b],SBOX[c],SBOX[d]]
 *
 * Setiap 4 word berurutan (W[4k]..W[4k+3]) menjadi Round Key ke-k.
 *
 * Ingat: catat entri "log" untuk setiap word-g (lihat kontrak di atas)
 * agar tabel Key Expansion di UI bisa menampilkan RotWord/SubWord/Rcon.
 * ------------------------------------------------------------------- */
AES.keyExpansion = function (keyBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== 16) {
    throw new Error('AES.keyExpansion expects a Uint8Array(16)');
  }

  const words = new Array(44);
  const roundKeys = new Array(11);
  const log = [];

  for (let i = 0; i < 4; i++) {
    words[i] = keyBytes.slice(i * 4, i * 4 + 4);
  }

  for (let i = 4; i < 44; i++) {
    let temp = words[i - 1].slice();

    if (i % 4 === 0) {
      const prevWord = temp.slice();
      const rotated = rotWord(prevWord);
      const substituted = subWord(rotated);
      const rcon = new Uint8Array([RCON[i / 4], 0x00, 0x00, 0x00]);
      const xorResult = xorBytes(substituted, rcon);

      log.push({
        wordIndex: i,
        prevWord,
        rotWord: rotated,
        subWord: substituted,
        rcon,
        xorResult,
      });

      temp = xorResult;
    }

    words[i] = xorBytes(words[i - 4], temp);
  }

  for (let round = 0; round < 11; round++) {
    const roundKey = new Uint8Array(16);
    for (let wordIndex = 0; wordIndex < 4; wordIndex++) {
      roundKey.set(words[round * 4 + wordIndex], wordIndex * 4);
    }
    roundKeys[round] = roundKey;
  }

  return { roundKeys, words, log };
};

/* ---------------------------------------------------------------------
 * 7) ENCRYPT / DECRYPT ORCHESTRATION
 * ---------------------------------------------------------------------
 * Susun urutan operasi sesuai bagian C.3 pada soal:
 *
 *   ENKRIPSI:
 *     Initial Round : AddRoundKey(RK0)
 *     Round 1..9    : SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(RKi)
 *     Round 10      : SubBytes -> ShiftRows -> AddRoundKey(RK10)   (tanpa MixColumns)
 *
 *   DEKRIPSI (kebalikannya, mulai dari RK10):
 *     Initial        : AddRoundKey(RK10)
 *     Round 10..2    : InvShiftRows -> InvSubBytes -> AddRoundKey(RKi) -> InvMixColumns
 *     Round 1 (final): InvShiftRows -> InvSubBytes -> AddRoundKey(RK0)
 *
 * Bungkus setiap operasi menjadi objek { op, before, after, ... } dan
 * kelompokkan per ronde ke dalam array `rounds`, mengikuti bentuk pada
 * kontrak di bagian atas file ini — supaya app.js bisa merender State
 * Matrix setiap langkah secara otomatis.
 * ------------------------------------------------------------------- */
AES.encryptBlock = function (plaintext, key) {
  const keySchedule = AES.keyExpansion(key);
  const rounds = [];
  let state = cloneState(plaintext);

  {
    const before = cloneState(state);
    state = AES.addRoundKey(state, keySchedule.roundKeys[0]);
    rounds.push({
      index: 0,
      label: 'Initial Round',
      steps: [makeStep('AddRoundKey', before, cloneState(state), { roundKeyIndex: 0 })],
    });
  }

  for (let round = 1; round <= 9; round++) {
    const steps = [];

    let before = cloneState(state);
    state = AES.subBytes(state);
    steps.push(makeStep('SubBytes', before, cloneState(state)));

    before = cloneState(state);
    state = AES.shiftRows(state);
    steps.push(makeStep('ShiftRows', before, cloneState(state)));

    before = cloneState(state);
    state = AES.mixColumns(state);
    steps.push(makeStep('MixColumns', before, cloneState(state)));

    before = cloneState(state);
    state = AES.addRoundKey(state, keySchedule.roundKeys[round]);
    steps.push(makeStep('AddRoundKey', before, cloneState(state), { roundKeyIndex: round }));

    rounds.push({
      index: round,
      label: 'Round ' + round,
      steps,
    });
  }

  {
    const steps = [];

    let before = cloneState(state);
    state = AES.subBytes(state);
    steps.push(makeStep('SubBytes', before, cloneState(state)));

    before = cloneState(state);
    state = AES.shiftRows(state);
    steps.push(makeStep('ShiftRows', before, cloneState(state)));

    before = cloneState(state);
    state = AES.addRoundKey(state, keySchedule.roundKeys[10]);
    steps.push(makeStep('AddRoundKey', before, cloneState(state), { roundKeyIndex: 10 }));

    rounds.push({
      index: 10,
      label: 'Round 10 (Final)',
      steps,
    });
  }

  return {
    ciphertext: cloneState(state),
    keyExpansion: keySchedule,
    rounds,
  };
};

AES.decryptBlock = function (ciphertext, key) {
  const keySchedule = AES.keyExpansion(key);
  const rounds = [];
  let state = cloneState(ciphertext);

  {
    const before = cloneState(state);
    state = AES.addRoundKey(state, keySchedule.roundKeys[10]);
    rounds.push({
      index: 0,
      label: 'Initial Round',
      steps: [makeStep('AddRoundKey', before, cloneState(state), { roundKeyIndex: 10 })],
    });
  }

  for (let round = 9; round >= 1; round--) {
    const steps = [];

    let before = cloneState(state);
    state = AES.invShiftRows(state);
    steps.push(makeStep('InvShiftRows', before, cloneState(state)));

    before = cloneState(state);
    state = AES.invSubBytes(state);
    steps.push(makeStep('InvSubBytes', before, cloneState(state)));

    before = cloneState(state);
    state = AES.addRoundKey(state, keySchedule.roundKeys[round]);
    steps.push(makeStep('AddRoundKey', before, cloneState(state), { roundKeyIndex: round }));

    before = cloneState(state);
    state = AES.invMixColumns(state);
    steps.push(makeStep('InvMixColumns', before, cloneState(state)));

    rounds.push({
      index: 10 - round,
      label: 'Round ' + round,
      steps,
    });
  }

  {
    const steps = [];

    let before = cloneState(state);
    state = AES.invShiftRows(state);
    steps.push(makeStep('InvShiftRows', before, cloneState(state)));

    before = cloneState(state);
    state = AES.invSubBytes(state);
    steps.push(makeStep('InvSubBytes', before, cloneState(state)));

    before = cloneState(state);
    state = AES.addRoundKey(state, keySchedule.roundKeys[0]);
    steps.push(makeStep('AddRoundKey', before, cloneState(state), { roundKeyIndex: 0 }));

    rounds.push({
      index: 10,
      label: 'Round 1 (Final)',
      steps,
    });
  }

  return {
    plaintext: cloneState(state),
    keyExpansion: keySchedule,
    rounds,
  };
};