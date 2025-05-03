/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ 4599:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.BSIGMA = void 0;
exports.G1s = G1s;
exports.G2s = G2s;
/**
 * Internal helpers for blake hash.
 * @module
 */
const utils_ts_1 = __nccwpck_require__(4248);
/**
 * Internal blake variable.
 * For BLAKE2b, the two extra permutations for rounds 10 and 11 are SIGMA[10..11] = SIGMA[0..1].
 */
// prettier-ignore
exports.BSIGMA = Uint8Array.from([
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    // Blake1, unused in others
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
]);
// Mixing function G splitted in two halfs
function G1s(a, b, c, d, x) {
    a = (a + b + x) | 0;
    d = (0, utils_ts_1.rotr)(d ^ a, 16);
    c = (c + d) | 0;
    b = (0, utils_ts_1.rotr)(b ^ c, 12);
    return { a, b, c, d };
}
function G2s(a, b, c, d, x) {
    a = (a + b + x) | 0;
    d = (0, utils_ts_1.rotr)(d ^ a, 8);
    c = (c + d) | 0;
    b = (0, utils_ts_1.rotr)(b ^ c, 7);
    return { a, b, c, d };
}
//# sourceMappingURL=_blake.js.map

/***/ }),

/***/ 4901:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SHA512_IV = exports.SHA384_IV = exports.SHA224_IV = exports.SHA256_IV = exports.HashMD = void 0;
exports.setBigUint64 = setBigUint64;
exports.Chi = Chi;
exports.Maj = Maj;
/**
 * Internal Merkle-Damgard hash utils.
 * @module
 */
const utils_ts_1 = __nccwpck_require__(4248);
/** Polyfill for Safari 14. https://caniuse.com/mdn-javascript_builtins_dataview_setbiguint64 */
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
/** Choice: a ? b : c */
function Chi(a, b, c) {
    return (a & b) ^ (~a & c);
}
/** Majority function, true if any two inputs is true. */
function Maj(a, b, c) {
    return (a & b) ^ (a & c) ^ (b & c);
}
/**
 * Merkle-Damgard hash construction base class.
 * Could be used to create MD5, RIPEMD, SHA1, SHA2.
 */
class HashMD extends utils_ts_1.Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.buffer = new Uint8Array(blockLen);
        this.view = (0, utils_ts_1.createView)(this.buffer);
    }
    update(data) {
        (0, utils_ts_1.aexists)(this);
        data = (0, utils_ts_1.toBytes)(data);
        (0, utils_ts_1.abytes)(data);
        const { view, buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = (0, utils_ts_1.createView)(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.aoutput)(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        (0, utils_ts_1.clean)(this.buffer.subarray(pos));
        // we have less than padOffset left in buffer, so we cannot put length in
        // current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = (0, utils_ts_1.createView)(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
    clone() {
        return this._cloneInto();
    }
}
exports.HashMD = HashMD;
/**
 * Initial SHA-2 state: fractional parts of square roots of first 16 primes 2..53.
 * Check out `test/misc/sha2-gen-iv.js` for recomputation guide.
 */
/** Initial SHA256 state. Bits 0..32 of frac part of sqrt of primes 2..19 */
exports.SHA256_IV = Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
/** Initial SHA224 state. Bits 32..64 of frac part of sqrt of primes 23..53 */
exports.SHA224_IV = Uint32Array.from([
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
]);
/** Initial SHA384 state. Bits 0..64 of frac part of sqrt of primes 23..53 */
exports.SHA384_IV = Uint32Array.from([
    0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
    0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
]);
/** Initial SHA512 state. Bits 0..64 of frac part of sqrt of primes 2..19 */
exports.SHA512_IV = Uint32Array.from([
    0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
    0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]);
//# sourceMappingURL=_md.js.map

/***/ }),

/***/ 6255:
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.toBig = exports.shrSL = exports.shrSH = exports.rotrSL = exports.rotrSH = exports.rotrBL = exports.rotrBH = exports.rotr32L = exports.rotr32H = exports.rotlSL = exports.rotlSH = exports.rotlBL = exports.rotlBH = exports.add5L = exports.add5H = exports.add4L = exports.add4H = exports.add3L = exports.add3H = void 0;
exports.add = add;
exports.fromBig = fromBig;
exports.split = split;
/**
 * Internal helpers for u64. BigUint64Array is too slow as per 2025, so we implement it using Uint32Array.
 * @todo re-check https://issues.chromium.org/issues/42212588
 * @module
 */
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
exports.toBig = toBig;
// for Shift in [0, 32)
const shrSH = (h, _l, s) => h >>> s;
exports.shrSH = shrSH;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
exports.shrSL = shrSL;
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
exports.rotrSH = rotrSH;
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
exports.rotrSL = rotrSL;
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
exports.rotrBH = rotrBH;
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
exports.rotrBL = rotrBL;
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (_h, l) => l;
exports.rotr32H = rotr32H;
const rotr32L = (h, _l) => h;
exports.rotr32L = rotr32L;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
exports.rotlSH = rotlSH;
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
exports.rotlSL = rotlSL;
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
exports.rotlBH = rotlBH;
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
exports.rotlBL = rotlBL;
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
exports.add3L = add3L;
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
exports.add3H = add3H;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
exports.add4L = add4L;
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
exports.add4H = add4H;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
exports.add5L = add5L;
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
exports.add5H = add5H;
// prettier-ignore
const u64 = {
    fromBig, split, toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};
exports["default"] = u64;
//# sourceMappingURL=_u64.js.map

/***/ }),

/***/ 8412:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.blake2s = exports.BLAKE2s = exports.blake2b = exports.BLAKE2b = exports.BLAKE2 = void 0;
exports.compress = compress;
/**
 * blake2b (64-bit) & blake2s (8 to 32-bit) hash functions.
 * b could have been faster, but there is no fast u64 in js, so s is 1.5x faster.
 * @module
 */
const _blake_ts_1 = __nccwpck_require__(4599);
const _md_ts_1 = __nccwpck_require__(4901);
const u64 = __nccwpck_require__(6255);
// prettier-ignore
const utils_ts_1 = __nccwpck_require__(4248);
// Same as SHA512_IV, but swapped endianness: LE instead of BE. iv[1] is iv[0], etc.
const B2B_IV = /* @__PURE__ */ Uint32Array.from([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
]);
// Temporary buffer
const BBUF = /* @__PURE__ */ new Uint32Array(32);
// Mixing function G splitted in two halfs
function G1b(a, b, c, d, msg, x) {
    // NOTE: V is LE here
    const Xl = msg[x], Xh = msg[x + 1]; // prettier-ignore
    let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1]; // prettier-ignore
    let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1]; // prettier-ignore
    let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1]; // prettier-ignore
    let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1]; // prettier-ignore
    // v[a] = (v[a] + v[b] + x) | 0;
    let ll = u64.add3L(Al, Bl, Xl);
    Ah = u64.add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    // v[d] = rotr(v[d] ^ v[a], 32)
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: u64.rotr32H(Dh, Dl), Dl: u64.rotr32L(Dh, Dl) });
    // v[c] = (v[c] + v[d]) | 0;
    ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
    // v[b] = rotr(v[b] ^ v[c], 24)
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: u64.rotrSH(Bh, Bl, 24), Bl: u64.rotrSL(Bh, Bl, 24) });
    (BBUF[2 * a] = Al), (BBUF[2 * a + 1] = Ah);
    (BBUF[2 * b] = Bl), (BBUF[2 * b + 1] = Bh);
    (BBUF[2 * c] = Cl), (BBUF[2 * c + 1] = Ch);
    (BBUF[2 * d] = Dl), (BBUF[2 * d + 1] = Dh);
}
function G2b(a, b, c, d, msg, x) {
    // NOTE: V is LE here
    const Xl = msg[x], Xh = msg[x + 1]; // prettier-ignore
    let Al = BBUF[2 * a], Ah = BBUF[2 * a + 1]; // prettier-ignore
    let Bl = BBUF[2 * b], Bh = BBUF[2 * b + 1]; // prettier-ignore
    let Cl = BBUF[2 * c], Ch = BBUF[2 * c + 1]; // prettier-ignore
    let Dl = BBUF[2 * d], Dh = BBUF[2 * d + 1]; // prettier-ignore
    // v[a] = (v[a] + v[b] + x) | 0;
    let ll = u64.add3L(Al, Bl, Xl);
    Ah = u64.add3H(ll, Ah, Bh, Xh);
    Al = ll | 0;
    // v[d] = rotr(v[d] ^ v[a], 16)
    ({ Dh, Dl } = { Dh: Dh ^ Ah, Dl: Dl ^ Al });
    ({ Dh, Dl } = { Dh: u64.rotrSH(Dh, Dl, 16), Dl: u64.rotrSL(Dh, Dl, 16) });
    // v[c] = (v[c] + v[d]) | 0;
    ({ h: Ch, l: Cl } = u64.add(Ch, Cl, Dh, Dl));
    // v[b] = rotr(v[b] ^ v[c], 63)
    ({ Bh, Bl } = { Bh: Bh ^ Ch, Bl: Bl ^ Cl });
    ({ Bh, Bl } = { Bh: u64.rotrBH(Bh, Bl, 63), Bl: u64.rotrBL(Bh, Bl, 63) });
    (BBUF[2 * a] = Al), (BBUF[2 * a + 1] = Ah);
    (BBUF[2 * b] = Bl), (BBUF[2 * b + 1] = Bh);
    (BBUF[2 * c] = Cl), (BBUF[2 * c + 1] = Ch);
    (BBUF[2 * d] = Dl), (BBUF[2 * d + 1] = Dh);
}
function checkBlake2Opts(outputLen, opts = {}, keyLen, saltLen, persLen) {
    (0, utils_ts_1.anumber)(keyLen);
    if (outputLen < 0 || outputLen > keyLen)
        throw new Error('outputLen bigger than keyLen');
    const { key, salt, personalization } = opts;
    if (key !== undefined && (key.length < 1 || key.length > keyLen))
        throw new Error('key length must be undefined or 1..' + keyLen);
    if (salt !== undefined && salt.length !== saltLen)
        throw new Error('salt must be undefined or ' + saltLen);
    if (personalization !== undefined && personalization.length !== persLen)
        throw new Error('personalization must be undefined or ' + persLen);
}
/** Class, from which others are subclassed. */
class BLAKE2 extends utils_ts_1.Hash {
    constructor(blockLen, outputLen) {
        super();
        this.finished = false;
        this.destroyed = false;
        this.length = 0;
        this.pos = 0;
        (0, utils_ts_1.anumber)(blockLen);
        (0, utils_ts_1.anumber)(outputLen);
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.buffer = new Uint8Array(blockLen);
        this.buffer32 = (0, utils_ts_1.u32)(this.buffer);
    }
    update(data) {
        (0, utils_ts_1.aexists)(this);
        data = (0, utils_ts_1.toBytes)(data);
        (0, utils_ts_1.abytes)(data);
        // Main difference with other hashes: there is flag for last block,
        // so we cannot process current block before we know that there
        // is the next one. This significantly complicates logic and reduces ability
        // to do zero-copy processing
        const { blockLen, buffer, buffer32 } = this;
        const len = data.length;
        const offset = data.byteOffset;
        const buf = data.buffer;
        for (let pos = 0; pos < len;) {
            // If buffer is full and we still have input (don't process last block, same as blake2s)
            if (this.pos === blockLen) {
                (0, utils_ts_1.swap32IfBE)(buffer32);
                this.compress(buffer32, 0, false);
                (0, utils_ts_1.swap32IfBE)(buffer32);
                this.pos = 0;
            }
            const take = Math.min(blockLen - this.pos, len - pos);
            const dataOffset = offset + pos;
            // full block && aligned to 4 bytes && not last in input
            if (take === blockLen && !(dataOffset % 4) && pos + take < len) {
                const data32 = new Uint32Array(buf, dataOffset, Math.floor((len - pos) / 4));
                (0, utils_ts_1.swap32IfBE)(data32);
                for (let pos32 = 0; pos + blockLen < len; pos32 += buffer32.length, pos += blockLen) {
                    this.length += blockLen;
                    this.compress(data32, pos32, false);
                }
                (0, utils_ts_1.swap32IfBE)(data32);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            this.length += take;
            pos += take;
        }
        return this;
    }
    digestInto(out) {
        (0, utils_ts_1.aexists)(this);
        (0, utils_ts_1.aoutput)(out, this);
        const { pos, buffer32 } = this;
        this.finished = true;
        // Padding
        (0, utils_ts_1.clean)(this.buffer.subarray(pos));
        (0, utils_ts_1.swap32IfBE)(buffer32);
        this.compress(buffer32, 0, true);
        (0, utils_ts_1.swap32IfBE)(buffer32);
        const out32 = (0, utils_ts_1.u32)(out);
        this.get().forEach((v, i) => (out32[i] = (0, utils_ts_1.swap8IfBE)(v)));
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        const { buffer, length, finished, destroyed, outputLen, pos } = this;
        to || (to = new this.constructor({ dkLen: outputLen }));
        to.set(...this.get());
        to.buffer.set(buffer);
        to.destroyed = destroyed;
        to.finished = finished;
        to.length = length;
        to.pos = pos;
        // @ts-ignore
        to.outputLen = outputLen;
        return to;
    }
    clone() {
        return this._cloneInto();
    }
}
exports.BLAKE2 = BLAKE2;
class BLAKE2b extends BLAKE2 {
    constructor(opts = {}) {
        const olen = opts.dkLen === undefined ? 64 : opts.dkLen;
        super(128, olen);
        // Same as SHA-512, but LE
        this.v0l = B2B_IV[0] | 0;
        this.v0h = B2B_IV[1] | 0;
        this.v1l = B2B_IV[2] | 0;
        this.v1h = B2B_IV[3] | 0;
        this.v2l = B2B_IV[4] | 0;
        this.v2h = B2B_IV[5] | 0;
        this.v3l = B2B_IV[6] | 0;
        this.v3h = B2B_IV[7] | 0;
        this.v4l = B2B_IV[8] | 0;
        this.v4h = B2B_IV[9] | 0;
        this.v5l = B2B_IV[10] | 0;
        this.v5h = B2B_IV[11] | 0;
        this.v6l = B2B_IV[12] | 0;
        this.v6h = B2B_IV[13] | 0;
        this.v7l = B2B_IV[14] | 0;
        this.v7h = B2B_IV[15] | 0;
        checkBlake2Opts(olen, opts, 64, 16, 16);
        let { key, personalization, salt } = opts;
        let keyLength = 0;
        if (key !== undefined) {
            key = (0, utils_ts_1.toBytes)(key);
            keyLength = key.length;
        }
        this.v0l ^= this.outputLen | (keyLength << 8) | (0x01 << 16) | (0x01 << 24);
        if (salt !== undefined) {
            salt = (0, utils_ts_1.toBytes)(salt);
            const slt = (0, utils_ts_1.u32)(salt);
            this.v4l ^= (0, utils_ts_1.swap8IfBE)(slt[0]);
            this.v4h ^= (0, utils_ts_1.swap8IfBE)(slt[1]);
            this.v5l ^= (0, utils_ts_1.swap8IfBE)(slt[2]);
            this.v5h ^= (0, utils_ts_1.swap8IfBE)(slt[3]);
        }
        if (personalization !== undefined) {
            personalization = (0, utils_ts_1.toBytes)(personalization);
            const pers = (0, utils_ts_1.u32)(personalization);
            this.v6l ^= (0, utils_ts_1.swap8IfBE)(pers[0]);
            this.v6h ^= (0, utils_ts_1.swap8IfBE)(pers[1]);
            this.v7l ^= (0, utils_ts_1.swap8IfBE)(pers[2]);
            this.v7h ^= (0, utils_ts_1.swap8IfBE)(pers[3]);
        }
        if (key !== undefined) {
            // Pad to blockLen and update
            const tmp = new Uint8Array(this.blockLen);
            tmp.set(key);
            this.update(tmp);
        }
    }
    // prettier-ignore
    get() {
        let { v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h } = this;
        return [v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h];
    }
    // prettier-ignore
    set(v0l, v0h, v1l, v1h, v2l, v2h, v3l, v3h, v4l, v4h, v5l, v5h, v6l, v6h, v7l, v7h) {
        this.v0l = v0l | 0;
        this.v0h = v0h | 0;
        this.v1l = v1l | 0;
        this.v1h = v1h | 0;
        this.v2l = v2l | 0;
        this.v2h = v2h | 0;
        this.v3l = v3l | 0;
        this.v3h = v3h | 0;
        this.v4l = v4l | 0;
        this.v4h = v4h | 0;
        this.v5l = v5l | 0;
        this.v5h = v5h | 0;
        this.v6l = v6l | 0;
        this.v6h = v6h | 0;
        this.v7l = v7l | 0;
        this.v7h = v7h | 0;
    }
    compress(msg, offset, isLast) {
        this.get().forEach((v, i) => (BBUF[i] = v)); // First half from state.
        BBUF.set(B2B_IV, 16); // Second half from IV.
        let { h, l } = u64.fromBig(BigInt(this.length));
        BBUF[24] = B2B_IV[8] ^ l; // Low word of the offset.
        BBUF[25] = B2B_IV[9] ^ h; // High word.
        // Invert all bits for last block
        if (isLast) {
            BBUF[28] = ~BBUF[28];
            BBUF[29] = ~BBUF[29];
        }
        let j = 0;
        const s = _blake_ts_1.BSIGMA;
        for (let i = 0; i < 12; i++) {
            G1b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
            G2b(0, 4, 8, 12, msg, offset + 2 * s[j++]);
            G1b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
            G2b(1, 5, 9, 13, msg, offset + 2 * s[j++]);
            G1b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
            G2b(2, 6, 10, 14, msg, offset + 2 * s[j++]);
            G1b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
            G2b(3, 7, 11, 15, msg, offset + 2 * s[j++]);
            G1b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
            G2b(0, 5, 10, 15, msg, offset + 2 * s[j++]);
            G1b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
            G2b(1, 6, 11, 12, msg, offset + 2 * s[j++]);
            G1b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
            G2b(2, 7, 8, 13, msg, offset + 2 * s[j++]);
            G1b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
            G2b(3, 4, 9, 14, msg, offset + 2 * s[j++]);
        }
        this.v0l ^= BBUF[0] ^ BBUF[16];
        this.v0h ^= BBUF[1] ^ BBUF[17];
        this.v1l ^= BBUF[2] ^ BBUF[18];
        this.v1h ^= BBUF[3] ^ BBUF[19];
        this.v2l ^= BBUF[4] ^ BBUF[20];
        this.v2h ^= BBUF[5] ^ BBUF[21];
        this.v3l ^= BBUF[6] ^ BBUF[22];
        this.v3h ^= BBUF[7] ^ BBUF[23];
        this.v4l ^= BBUF[8] ^ BBUF[24];
        this.v4h ^= BBUF[9] ^ BBUF[25];
        this.v5l ^= BBUF[10] ^ BBUF[26];
        this.v5h ^= BBUF[11] ^ BBUF[27];
        this.v6l ^= BBUF[12] ^ BBUF[28];
        this.v6h ^= BBUF[13] ^ BBUF[29];
        this.v7l ^= BBUF[14] ^ BBUF[30];
        this.v7h ^= BBUF[15] ^ BBUF[31];
        (0, utils_ts_1.clean)(BBUF);
    }
    destroy() {
        this.destroyed = true;
        (0, utils_ts_1.clean)(this.buffer32);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
exports.BLAKE2b = BLAKE2b;
/**
 * Blake2b hash function. 64-bit. 1.5x slower than blake2s in JS.
 * @param msg - message that would be hashed
 * @param opts - dkLen output length, key for MAC mode, salt, personalization
 */
exports.blake2b = (0, utils_ts_1.createOptHasher)((opts) => new BLAKE2b(opts));
// prettier-ignore
function compress(s, offset, msg, rounds, v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) {
    let j = 0;
    for (let i = 0; i < rounds; i++) {
        ({ a: v0, b: v4, c: v8, d: v12 } = (0, _blake_ts_1.G1s)(v0, v4, v8, v12, msg[offset + s[j++]]));
        ({ a: v0, b: v4, c: v8, d: v12 } = (0, _blake_ts_1.G2s)(v0, v4, v8, v12, msg[offset + s[j++]]));
        ({ a: v1, b: v5, c: v9, d: v13 } = (0, _blake_ts_1.G1s)(v1, v5, v9, v13, msg[offset + s[j++]]));
        ({ a: v1, b: v5, c: v9, d: v13 } = (0, _blake_ts_1.G2s)(v1, v5, v9, v13, msg[offset + s[j++]]));
        ({ a: v2, b: v6, c: v10, d: v14 } = (0, _blake_ts_1.G1s)(v2, v6, v10, v14, msg[offset + s[j++]]));
        ({ a: v2, b: v6, c: v10, d: v14 } = (0, _blake_ts_1.G2s)(v2, v6, v10, v14, msg[offset + s[j++]]));
        ({ a: v3, b: v7, c: v11, d: v15 } = (0, _blake_ts_1.G1s)(v3, v7, v11, v15, msg[offset + s[j++]]));
        ({ a: v3, b: v7, c: v11, d: v15 } = (0, _blake_ts_1.G2s)(v3, v7, v11, v15, msg[offset + s[j++]]));
        ({ a: v0, b: v5, c: v10, d: v15 } = (0, _blake_ts_1.G1s)(v0, v5, v10, v15, msg[offset + s[j++]]));
        ({ a: v0, b: v5, c: v10, d: v15 } = (0, _blake_ts_1.G2s)(v0, v5, v10, v15, msg[offset + s[j++]]));
        ({ a: v1, b: v6, c: v11, d: v12 } = (0, _blake_ts_1.G1s)(v1, v6, v11, v12, msg[offset + s[j++]]));
        ({ a: v1, b: v6, c: v11, d: v12 } = (0, _blake_ts_1.G2s)(v1, v6, v11, v12, msg[offset + s[j++]]));
        ({ a: v2, b: v7, c: v8, d: v13 } = (0, _blake_ts_1.G1s)(v2, v7, v8, v13, msg[offset + s[j++]]));
        ({ a: v2, b: v7, c: v8, d: v13 } = (0, _blake_ts_1.G2s)(v2, v7, v8, v13, msg[offset + s[j++]]));
        ({ a: v3, b: v4, c: v9, d: v14 } = (0, _blake_ts_1.G1s)(v3, v4, v9, v14, msg[offset + s[j++]]));
        ({ a: v3, b: v4, c: v9, d: v14 } = (0, _blake_ts_1.G2s)(v3, v4, v9, v14, msg[offset + s[j++]]));
    }
    return { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 };
}
const B2S_IV = _md_ts_1.SHA256_IV;
class BLAKE2s extends BLAKE2 {
    constructor(opts = {}) {
        const olen = opts.dkLen === undefined ? 32 : opts.dkLen;
        super(64, olen);
        // Internal state, same as SHA-256
        this.v0 = B2S_IV[0] | 0;
        this.v1 = B2S_IV[1] | 0;
        this.v2 = B2S_IV[2] | 0;
        this.v3 = B2S_IV[3] | 0;
        this.v4 = B2S_IV[4] | 0;
        this.v5 = B2S_IV[5] | 0;
        this.v6 = B2S_IV[6] | 0;
        this.v7 = B2S_IV[7] | 0;
        checkBlake2Opts(olen, opts, 32, 8, 8);
        let { key, personalization, salt } = opts;
        let keyLength = 0;
        if (key !== undefined) {
            key = (0, utils_ts_1.toBytes)(key);
            keyLength = key.length;
        }
        this.v0 ^= this.outputLen | (keyLength << 8) | (0x01 << 16) | (0x01 << 24);
        if (salt !== undefined) {
            salt = (0, utils_ts_1.toBytes)(salt);
            const slt = (0, utils_ts_1.u32)(salt);
            this.v4 ^= (0, utils_ts_1.swap8IfBE)(slt[0]);
            this.v5 ^= (0, utils_ts_1.swap8IfBE)(slt[1]);
        }
        if (personalization !== undefined) {
            personalization = (0, utils_ts_1.toBytes)(personalization);
            const pers = (0, utils_ts_1.u32)(personalization);
            this.v6 ^= (0, utils_ts_1.swap8IfBE)(pers[0]);
            this.v7 ^= (0, utils_ts_1.swap8IfBE)(pers[1]);
        }
        if (key !== undefined) {
            // Pad to blockLen and update
            (0, utils_ts_1.abytes)(key);
            const tmp = new Uint8Array(this.blockLen);
            tmp.set(key);
            this.update(tmp);
        }
    }
    get() {
        const { v0, v1, v2, v3, v4, v5, v6, v7 } = this;
        return [v0, v1, v2, v3, v4, v5, v6, v7];
    }
    // prettier-ignore
    set(v0, v1, v2, v3, v4, v5, v6, v7) {
        this.v0 = v0 | 0;
        this.v1 = v1 | 0;
        this.v2 = v2 | 0;
        this.v3 = v3 | 0;
        this.v4 = v4 | 0;
        this.v5 = v5 | 0;
        this.v6 = v6 | 0;
        this.v7 = v7 | 0;
    }
    compress(msg, offset, isLast) {
        const { h, l } = u64.fromBig(BigInt(this.length));
        // prettier-ignore
        const { v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 } = compress(_blake_ts_1.BSIGMA, offset, msg, 10, this.v0, this.v1, this.v2, this.v3, this.v4, this.v5, this.v6, this.v7, B2S_IV[0], B2S_IV[1], B2S_IV[2], B2S_IV[3], l ^ B2S_IV[4], h ^ B2S_IV[5], isLast ? ~B2S_IV[6] : B2S_IV[6], B2S_IV[7]);
        this.v0 ^= v0 ^ v8;
        this.v1 ^= v1 ^ v9;
        this.v2 ^= v2 ^ v10;
        this.v3 ^= v3 ^ v11;
        this.v4 ^= v4 ^ v12;
        this.v5 ^= v5 ^ v13;
        this.v6 ^= v6 ^ v14;
        this.v7 ^= v7 ^ v15;
    }
    destroy() {
        this.destroyed = true;
        (0, utils_ts_1.clean)(this.buffer32);
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
    }
}
exports.BLAKE2s = BLAKE2s;
/**
 * Blake2s hash function. Focuses on 8-bit to 32-bit platforms. 1.5x faster than blake2b in JS.
 * @param msg - message that would be hashed
 * @param opts - dkLen output length, key for MAC mode, salt, personalization
 */
exports.blake2s = (0, utils_ts_1.createOptHasher)((opts) => new BLAKE2s(opts));
//# sourceMappingURL=blake2.js.map

/***/ }),

/***/ 5596:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.blake2b = exports.BLAKE2b = void 0;
/**
 * Blake2b hash function. Focuses on 64-bit platforms, but in JS speed different from Blake2s is negligible.
 * @module
 * @deprecated
 */
const blake2_ts_1 = __nccwpck_require__(8412);
/** @deprecated Use import from `noble/hashes/blake2` module */
exports.BLAKE2b = blake2_ts_1.BLAKE2b;
/** @deprecated Use import from `noble/hashes/blake2` module */
exports.blake2b = blake2_ts_1.blake2b;
//# sourceMappingURL=blake2b.js.map

/***/ }),

/***/ 5048:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.crypto = void 0;
/**
 * Internal webcrypto alias.
 * We prefer WebCrypto aka globalThis.crypto, which exists in node.js 16+.
 * Falls back to Node.js built-in crypto for Node.js <=v14.
 * See utils.ts for details.
 * @module
 */
// @ts-ignore
const nc = __nccwpck_require__(7598);
exports.crypto = nc && typeof nc === 'object' && 'webcrypto' in nc
    ? nc.webcrypto
    : nc && typeof nc === 'object' && 'randomBytes' in nc
        ? nc
        : undefined;
//# sourceMappingURL=cryptoNode.js.map

/***/ }),

/***/ 4248:
/***/ ((__unused_webpack_module, exports, __nccwpck_require__) => {


/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.wrapXOFConstructorWithOpts = exports.wrapConstructorWithOpts = exports.wrapConstructor = exports.Hash = exports.nextTick = exports.swap32IfBE = exports.byteSwapIfBE = exports.swap8IfBE = exports.isLE = void 0;
exports.isBytes = isBytes;
exports.anumber = anumber;
exports.abytes = abytes;
exports.ahash = ahash;
exports.aexists = aexists;
exports.aoutput = aoutput;
exports.u8 = u8;
exports.u32 = u32;
exports.clean = clean;
exports.createView = createView;
exports.rotr = rotr;
exports.rotl = rotl;
exports.byteSwap = byteSwap;
exports.byteSwap32 = byteSwap32;
exports.bytesToHex = bytesToHex;
exports.hexToBytes = hexToBytes;
exports.asyncLoop = asyncLoop;
exports.utf8ToBytes = utf8ToBytes;
exports.bytesToUtf8 = bytesToUtf8;
exports.toBytes = toBytes;
exports.kdfInputToBytes = kdfInputToBytes;
exports.concatBytes = concatBytes;
exports.checkOpts = checkOpts;
exports.createHasher = createHasher;
exports.createOptHasher = createOptHasher;
exports.createXOFer = createXOFer;
exports.randomBytes = randomBytes;
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated (2025-04-30), we can just drop the import.
const crypto_1 = __nccwpck_require__(5048);
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is positive integer. */
function anumber(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error('positive integer expected, got ' + n);
}
/** Asserts something is Uint8Array. */
function abytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}
/** Asserts something is hash */
function ahash(h) {
    if (typeof h !== 'function' || typeof h.create !== 'function')
        throw new Error('Hash should be wrapped by utils.createHasher');
    anumber(h.outputLen);
    anumber(h.blockLen);
}
/** Asserts a hash instance has not been destroyed / finished */
function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/** Asserts output is properly-sized byte array */
function aoutput(out, instance) {
    abytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('digestInto() expects output buffer of length at least ' + min);
    }
}
/** Cast u8 / u16 / u32 to u8. */
function u8(arr) {
    return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** Cast u8 / u16 / u32 to u32. */
function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Create DataView of an array for easy byte-level manipulation. */
function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** The rotate right (circular right shift) operation for uint32 */
function rotr(word, shift) {
    return (word << (32 - shift)) | (word >>> shift);
}
/** The rotate left (circular left shift) operation for uint32 */
function rotl(word, shift) {
    return (word << shift) | ((word >>> (32 - shift)) >>> 0);
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
exports.isLE = (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
/** The byte swap operation for uint32 */
function byteSwap(word) {
    return (((word << 24) & 0xff000000) |
        ((word << 8) & 0xff0000) |
        ((word >>> 8) & 0xff00) |
        ((word >>> 24) & 0xff));
}
/** Conditionally byte swap if on a big-endian platform */
exports.swap8IfBE = exports.isLE
    ? (n) => n
    : (n) => byteSwap(n);
/** @deprecated */
exports.byteSwapIfBE = exports.swap8IfBE;
/** In place byte swap for Uint32Array */
function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap(arr[i]);
    }
    return arr;
}
exports.swap32IfBE = exports.isLE
    ? (u) => u
    : byteSwap32;
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin = /* @__PURE__ */ (() => 
// @ts-ignore
typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')();
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * Convert byte array to hex string. Uses built-in function, when available.
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
function bytesToHex(bytes) {
    abytes(bytes);
    // @ts-ignore
    if (hasHexBuiltin)
        return bytes.toHex();
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0; // '2' => 50-48
    if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
    return;
}
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // @ts-ignore
    if (hasHexBuiltin)
        return Uint8Array.fromHex(hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
/**
 * There is no setImmediate in browser and setTimeout is slow.
 * Call of async fn will return Promise, which will be fullfiled only on
 * next scheduler queue processing step and this is exactly what we need.
 */
const nextTick = async () => { };
exports.nextTick = nextTick;
/** Returns control to thread each 'tick' ms to avoid blocking. */
async function asyncLoop(iters, tick, cb) {
    let ts = Date.now();
    for (let i = 0; i < iters; i++) {
        cb(i);
        // Date.now() is not monotonic, so in case if clock goes backwards we return return control too
        const diff = Date.now() - ts;
        if (diff >= 0 && diff < tick)
            continue;
        await (0, exports.nextTick)();
        ts += diff;
    }
}
/**
 * Converts string to bytes using UTF8 encoding.
 * @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error('string expected');
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Converts bytes to string using UTF8 encoding.
 * @example bytesToUtf8(Uint8Array.from([97, 98, 99])) // 'abc'
 */
function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    abytes(data);
    return data;
}
/**
 * Helper for KDFs: consumes uint8array or string.
 * When string is passed, does utf8 decoding, using TextDecoder.
 */
function kdfInputToBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    abytes(data);
    return data;
}
/** Copies several Uint8Arrays into one. */
function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        abytes(a);
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
function checkOpts(defaults, opts) {
    if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
        throw new Error('options should be object or undefined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
/** For runtime check if class implements interface */
class Hash {
}
exports.Hash = Hash;
/** Wraps hash function, creating an interface on top of it */
function createHasher(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
}
function createOptHasher(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    return hashC;
}
function createXOFer(hashCons) {
    const hashC = (msg, opts) => hashCons(opts).update(toBytes(msg)).digest();
    const tmp = hashCons({});
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    return hashC;
}
exports.wrapConstructor = createHasher;
exports.wrapConstructorWithOpts = createOptHasher;
exports.wrapXOFConstructorWithOpts = createXOFer;
/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
function randomBytes(bytesLength = 32) {
    if (crypto_1.crypto && typeof crypto_1.crypto.getRandomValues === 'function') {
        return crypto_1.crypto.getRandomValues(new Uint8Array(bytesLength));
    }
    // Legacy Node.js compatibility
    if (crypto_1.crypto && typeof crypto_1.crypto.randomBytes === 'function') {
        return Uint8Array.from(crypto_1.crypto.randomBytes(bytesLength));
    }
    throw new Error('crypto.getRandomValues must be defined');
}
//# sourceMappingURL=utils.js.map

/***/ }),

/***/ 628:
/***/ ((__unused_webpack_module, exports) => {


/*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) */
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.bytes = exports.stringToBytes = exports.str = exports.bytesToString = exports.hex = exports.utf8 = exports.bech32m = exports.bech32 = exports.base58check = exports.createBase58check = exports.base58xmr = exports.base58xrp = exports.base58flickr = exports.base58 = exports.base64urlnopad = exports.base64url = exports.base64nopad = exports.base64 = exports.base32crockford = exports.base32hexnopad = exports.base32hex = exports.base32nopad = exports.base32 = exports.base16 = exports.utils = void 0;
function isBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is Uint8Array. */
function abytes(b, ...lengths) {
    if (!isBytes(b))
        throw new Error('Uint8Array expected');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error('Uint8Array expected of length ' + lengths + ', got length=' + b.length);
}
function isArrayOf(isString, arr) {
    if (!Array.isArray(arr))
        return false;
    if (arr.length === 0)
        return true;
    if (isString) {
        return arr.every((item) => typeof item === 'string');
    }
    else {
        return arr.every((item) => Number.isSafeInteger(item));
    }
}
// no abytes: seems to have 10% slowdown. Why?!
function afn(input) {
    if (typeof input !== 'function')
        throw new Error('function expected');
    return true;
}
function astr(label, input) {
    if (typeof input !== 'string')
        throw new Error(`${label}: string expected`);
    return true;
}
function anumber(n) {
    if (!Number.isSafeInteger(n))
        throw new Error(`invalid integer: ${n}`);
}
function aArr(input) {
    if (!Array.isArray(input))
        throw new Error('array expected');
}
function astrArr(label, input) {
    if (!isArrayOf(true, input))
        throw new Error(`${label}: array of strings expected`);
}
function anumArr(label, input) {
    if (!isArrayOf(false, input))
        throw new Error(`${label}: array of numbers expected`);
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function chain(...args) {
    const id = (a) => a;
    // Wrap call in closure so JIT can inline calls
    const wrap = (a, b) => (c) => a(b(c));
    // Construct chain of args[-1].encode(args[-2].encode([...]))
    const encode = args.map((x) => x.encode).reduceRight(wrap, id);
    // Construct chain of args[0].decode(args[1].decode(...))
    const decode = args.map((x) => x.decode).reduce(wrap, id);
    return { encode, decode };
}
/**
 * Encodes integer radix representation to array of strings using alphabet and back.
 * Could also be array of strings.
 * @__NO_SIDE_EFFECTS__
 */
function alphabet(letters) {
    // mapping 1 to "b"
    const lettersA = typeof letters === 'string' ? letters.split('') : letters;
    const len = lettersA.length;
    astrArr('alphabet', lettersA);
    // mapping "b" to 1
    const indexes = new Map(lettersA.map((l, i) => [l, i]));
    return {
        encode: (digits) => {
            aArr(digits);
            return digits.map((i) => {
                if (!Number.isSafeInteger(i) || i < 0 || i >= len)
                    throw new Error(`alphabet.encode: digit index outside alphabet "${i}". Allowed: ${letters}`);
                return lettersA[i];
            });
        },
        decode: (input) => {
            aArr(input);
            return input.map((letter) => {
                astr('alphabet.decode', letter);
                const i = indexes.get(letter);
                if (i === undefined)
                    throw new Error(`Unknown letter: "${letter}". Allowed: ${letters}`);
                return i;
            });
        },
    };
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function join(separator = '') {
    astr('join', separator);
    return {
        encode: (from) => {
            astrArr('join.decode', from);
            return from.join(separator);
        },
        decode: (to) => {
            astr('join.decode', to);
            return to.split(separator);
        },
    };
}
/**
 * Pad strings array so it has integer number of bits
 * @__NO_SIDE_EFFECTS__
 */
function padding(bits, chr = '=') {
    anumber(bits);
    astr('padding', chr);
    return {
        encode(data) {
            astrArr('padding.encode', data);
            while ((data.length * bits) % 8)
                data.push(chr);
            return data;
        },
        decode(input) {
            astrArr('padding.decode', input);
            let end = input.length;
            if ((end * bits) % 8)
                throw new Error('padding: invalid, string should have whole number of bytes');
            for (; end > 0 && input[end - 1] === chr; end--) {
                const last = end - 1;
                const byte = last * bits;
                if (byte % 8 === 0)
                    throw new Error('padding: invalid, string has too much padding');
            }
            return input.slice(0, end);
        },
    };
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function normalize(fn) {
    afn(fn);
    return { encode: (from) => from, decode: (to) => fn(to) };
}
/**
 * Slow: O(n^2) time complexity
 */
function convertRadix(data, from, to) {
    // base 1 is impossible
    if (from < 2)
        throw new Error(`convertRadix: invalid from=${from}, base cannot be less than 2`);
    if (to < 2)
        throw new Error(`convertRadix: invalid to=${to}, base cannot be less than 2`);
    aArr(data);
    if (!data.length)
        return [];
    let pos = 0;
    const res = [];
    const digits = Array.from(data, (d) => {
        anumber(d);
        if (d < 0 || d >= from)
            throw new Error(`invalid integer: ${d}`);
        return d;
    });
    const dlen = digits.length;
    while (true) {
        let carry = 0;
        let done = true;
        for (let i = pos; i < dlen; i++) {
            const digit = digits[i];
            const fromCarry = from * carry;
            const digitBase = fromCarry + digit;
            if (!Number.isSafeInteger(digitBase) ||
                fromCarry / from !== carry ||
                digitBase - digit !== fromCarry) {
                throw new Error('convertRadix: carry overflow');
            }
            const div = digitBase / to;
            carry = digitBase % to;
            const rounded = Math.floor(div);
            digits[i] = rounded;
            if (!Number.isSafeInteger(rounded) || rounded * to + carry !== digitBase)
                throw new Error('convertRadix: carry overflow');
            if (!done)
                continue;
            else if (!rounded)
                pos = i;
            else
                done = false;
        }
        res.push(carry);
        if (done)
            break;
    }
    for (let i = 0; i < data.length - 1 && data[i] === 0; i++)
        res.push(0);
    return res.reverse();
}
const gcd = (a, b) => (b === 0 ? a : gcd(b, a % b));
const radix2carry = /* @__NO_SIDE_EFFECTS__ */ (from, to) => from + (to - gcd(from, to));
const powers = /* @__PURE__ */ (() => {
    let res = [];
    for (let i = 0; i < 40; i++)
        res.push(2 ** i);
    return res;
})();
/**
 * Implemented with numbers, because BigInt is 5x slower
 */
function convertRadix2(data, from, to, padding) {
    aArr(data);
    if (from <= 0 || from > 32)
        throw new Error(`convertRadix2: wrong from=${from}`);
    if (to <= 0 || to > 32)
        throw new Error(`convertRadix2: wrong to=${to}`);
    if (radix2carry(from, to) > 32) {
        throw new Error(`convertRadix2: carry overflow from=${from} to=${to} carryBits=${radix2carry(from, to)}`);
    }
    let carry = 0;
    let pos = 0; // bitwise position in current element
    const max = powers[from];
    const mask = powers[to] - 1;
    const res = [];
    for (const n of data) {
        anumber(n);
        if (n >= max)
            throw new Error(`convertRadix2: invalid data word=${n} from=${from}`);
        carry = (carry << from) | n;
        if (pos + from > 32)
            throw new Error(`convertRadix2: carry overflow pos=${pos} from=${from}`);
        pos += from;
        for (; pos >= to; pos -= to)
            res.push(((carry >> (pos - to)) & mask) >>> 0);
        const pow = powers[pos];
        if (pow === undefined)
            throw new Error('invalid carry');
        carry &= pow - 1; // clean carry, otherwise it will cause overflow
    }
    carry = (carry << (to - pos)) & mask;
    if (!padding && pos >= from)
        throw new Error('Excess padding');
    if (!padding && carry > 0)
        throw new Error(`Non-zero padding: ${carry}`);
    if (padding && pos > 0)
        res.push(carry >>> 0);
    return res;
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function radix(num) {
    anumber(num);
    const _256 = 2 ** 8;
    return {
        encode: (bytes) => {
            if (!isBytes(bytes))
                throw new Error('radix.encode input should be Uint8Array');
            return convertRadix(Array.from(bytes), _256, num);
        },
        decode: (digits) => {
            anumArr('radix.decode', digits);
            return Uint8Array.from(convertRadix(digits, num, _256));
        },
    };
}
/**
 * If both bases are power of same number (like `2**8 <-> 2**64`),
 * there is a linear algorithm. For now we have implementation for power-of-two bases only.
 * @__NO_SIDE_EFFECTS__
 */
function radix2(bits, revPadding = false) {
    anumber(bits);
    if (bits <= 0 || bits > 32)
        throw new Error('radix2: bits should be in (0..32]');
    if (radix2carry(8, bits) > 32 || radix2carry(bits, 8) > 32)
        throw new Error('radix2: carry overflow');
    return {
        encode: (bytes) => {
            if (!isBytes(bytes))
                throw new Error('radix2.encode input should be Uint8Array');
            return convertRadix2(Array.from(bytes), 8, bits, !revPadding);
        },
        decode: (digits) => {
            anumArr('radix2.decode', digits);
            return Uint8Array.from(convertRadix2(digits, bits, 8, revPadding));
        },
    };
}
function unsafeWrapper(fn) {
    afn(fn);
    return function (...args) {
        try {
            return fn.apply(null, args);
        }
        catch (e) { }
    };
}
function checksum(len, fn) {
    anumber(len);
    afn(fn);
    return {
        encode(data) {
            if (!isBytes(data))
                throw new Error('checksum.encode: input should be Uint8Array');
            const sum = fn(data).slice(0, len);
            const res = new Uint8Array(data.length + len);
            res.set(data);
            res.set(sum, data.length);
            return res;
        },
        decode(data) {
            if (!isBytes(data))
                throw new Error('checksum.decode: input should be Uint8Array');
            const payload = data.slice(0, -len);
            const oldChecksum = data.slice(-len);
            const newChecksum = fn(payload).slice(0, len);
            for (let i = 0; i < len; i++)
                if (newChecksum[i] !== oldChecksum[i])
                    throw new Error('Invalid checksum');
            return payload;
        },
    };
}
// prettier-ignore
exports.utils = {
    alphabet, chain, checksum, convertRadix, convertRadix2, radix, radix2, join, padding,
};
// RFC 4648 aka RFC 3548
// ---------------------
/**
 * base16 encoding from RFC 4648.
 * @example
 * ```js
 * base16.encode(Uint8Array.from([0x12, 0xab]));
 * // => '12AB'
 * ```
 */
exports.base16 = chain(radix2(4), alphabet('0123456789ABCDEF'), join(''));
/**
 * base32 encoding from RFC 4648. Has padding.
 * Use `base32nopad` for unpadded version.
 * Also check out `base32hex`, `base32hexnopad`, `base32crockford`.
 * @example
 * ```js
 * base32.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'CKVQ===='
 * base32.decode('CKVQ====');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base32 = chain(radix2(5), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'), padding(5), join(''));
/**
 * base32 encoding from RFC 4648. No padding.
 * Use `base32` for padded version.
 * Also check out `base32hex`, `base32hexnopad`, `base32crockford`.
 * @example
 * ```js
 * base32nopad.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'CKVQ'
 * base32nopad.decode('CKVQ');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base32nopad = chain(radix2(5), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'), join(''));
/**
 * base32 encoding from RFC 4648. Padded. Compared to ordinary `base32`, slightly different alphabet.
 * Use `base32hexnopad` for unpadded version.
 * @example
 * ```js
 * base32hex.encode(Uint8Array.from([0x12, 0xab]));
 * // => '2ALG===='
 * base32hex.decode('2ALG====');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base32hex = chain(radix2(5), alphabet('0123456789ABCDEFGHIJKLMNOPQRSTUV'), padding(5), join(''));
/**
 * base32 encoding from RFC 4648. No padding. Compared to ordinary `base32`, slightly different alphabet.
 * Use `base32hex` for padded version.
 * @example
 * ```js
 * base32hexnopad.encode(Uint8Array.from([0x12, 0xab]));
 * // => '2ALG'
 * base32hexnopad.decode('2ALG');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base32hexnopad = chain(radix2(5), alphabet('0123456789ABCDEFGHIJKLMNOPQRSTUV'), join(''));
/**
 * base32 encoding from RFC 4648. Doug Crockford's version.
 * https://www.crockford.com/base32.html
 * @example
 * ```js
 * base32crockford.encode(Uint8Array.from([0x12, 0xab]));
 * // => '2ANG'
 * base32crockford.decode('2ANG');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base32crockford = chain(radix2(5), alphabet('0123456789ABCDEFGHJKMNPQRSTVWXYZ'), join(''), normalize((s) => s.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1')));
// Built-in base64 conversion https://caniuse.com/mdn-javascript_builtins_uint8array_frombase64
// TODO: temporarily set to false, trying to understand bugs
// prettier-ignore
const hasBase64Builtin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === 'function' &&
    typeof Uint8Array.fromBase64 === 'function')();
/**
 * base64 from RFC 4648. Padded.
 * Use `base64nopad` for unpadded version.
 * Also check out `base64url`, `base64urlnopad`.
 * Falls back to built-in function, when available.
 * @example
 * ```js
 * base64.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'Eqs='
 * base64.decode('Eqs=');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
// prettier-ignore
exports.base64 = hasBase64Builtin ? {
    encode(b) { abytes(b); return b.toBase64(); },
    decode(s) {
        astr('base64', s);
        return Uint8Array.fromBase64(s, { lastChunkHandling: 'strict' });
    },
} : chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), padding(6), join(''));
/**
 * base64 from RFC 4648. No padding.
 * Use `base64` for padded version.
 * @example
 * ```js
 * base64nopad.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'Eqs'
 * base64nopad.decode('Eqs');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base64nopad = chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'), join(''));
/**
 * base64 from RFC 4648, using URL-safe alphabet. Padded.
 * Use `base64urlnopad` for unpadded version.
 * Falls back to built-in function, when available.
 * @example
 * ```js
 * base64url.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'Eqs='
 * base64url.decode('Eqs=');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
// prettier-ignore
exports.base64url = hasBase64Builtin ? {
    encode(b) { abytes(b); return b.toBase64({ alphabet: 'base64url' }); },
    decode(s) { astr('base64', s); return Uint8Array.fromBase64(s, { alphabet: 'base64url' }); },
} : chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'), padding(6), join(''));
/**
 * base64 from RFC 4648, using URL-safe alphabet. No padding.
 * Use `base64url` for padded version.
 * @example
 * ```js
 * base64urlnopad.encode(Uint8Array.from([0x12, 0xab]));
 * // => 'Eqs'
 * base64urlnopad.decode('Eqs');
 * // => Uint8Array.from([0x12, 0xab])
 * ```
 */
exports.base64urlnopad = chain(radix2(6), alphabet('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'), join(''));
// base58 code
// -----------
const genBase58 = /* @__NO_SIDE_EFFECTS__ */ (abc) => chain(radix(58), alphabet(abc), join(''));
/**
 * base58: base64 without ambigous characters +, /, 0, O, I, l.
 * Quadratic (O(n^2)) - so, can't be used on large inputs.
 * @example
 * ```js
 * base58.decode('01abcdef');
 * // => '3UhJW'
 * ```
 */
exports.base58 = genBase58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
/**
 * base58: flickr version. Check out `base58`.
 */
exports.base58flickr = genBase58('123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ');
/**
 * base58: XRP version. Check out `base58`.
 */
exports.base58xrp = genBase58('rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz');
// Data len (index) -> encoded block len
const XMR_BLOCK_LEN = [0, 2, 3, 5, 6, 7, 9, 10, 11];
/**
 * base58: XMR version. Check out `base58`.
 * Done in 8-byte blocks (which equals 11 chars in decoding). Last (non-full) block padded with '1' to size in XMR_BLOCK_LEN.
 * Block encoding significantly reduces quadratic complexity of base58.
 */
exports.base58xmr = {
    encode(data) {
        let res = '';
        for (let i = 0; i < data.length; i += 8) {
            const block = data.subarray(i, i + 8);
            res += exports.base58.encode(block).padStart(XMR_BLOCK_LEN[block.length], '1');
        }
        return res;
    },
    decode(str) {
        let res = [];
        for (let i = 0; i < str.length; i += 11) {
            const slice = str.slice(i, i + 11);
            const blockLen = XMR_BLOCK_LEN.indexOf(slice.length);
            const block = exports.base58.decode(slice);
            for (let j = 0; j < block.length - blockLen; j++) {
                if (block[j] !== 0)
                    throw new Error('base58xmr: wrong padding');
            }
            res = res.concat(Array.from(block.slice(block.length - blockLen)));
        }
        return Uint8Array.from(res);
    },
};
/**
 * Method, which creates base58check encoder.
 * Requires function, calculating sha256.
 */
const createBase58check = (sha256) => chain(checksum(4, (data) => sha256(sha256(data))), exports.base58);
exports.createBase58check = createBase58check;
/**
 * Use `createBase58check` instead.
 * @deprecated
 */
exports.base58check = exports.createBase58check;
const BECH_ALPHABET = chain(alphabet('qpzry9x8gf2tvdw0s3jn54khce6mua7l'), join(''));
const POLYMOD_GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
function bech32Polymod(pre) {
    const b = pre >> 25;
    let chk = (pre & 0x1ffffff) << 5;
    for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
        if (((b >> i) & 1) === 1)
            chk ^= POLYMOD_GENERATORS[i];
    }
    return chk;
}
function bechChecksum(prefix, words, encodingConst = 1) {
    const len = prefix.length;
    let chk = 1;
    for (let i = 0; i < len; i++) {
        const c = prefix.charCodeAt(i);
        if (c < 33 || c > 126)
            throw new Error(`Invalid prefix (${prefix})`);
        chk = bech32Polymod(chk) ^ (c >> 5);
    }
    chk = bech32Polymod(chk);
    for (let i = 0; i < len; i++)
        chk = bech32Polymod(chk) ^ (prefix.charCodeAt(i) & 0x1f);
    for (let v of words)
        chk = bech32Polymod(chk) ^ v;
    for (let i = 0; i < 6; i++)
        chk = bech32Polymod(chk);
    chk ^= encodingConst;
    return BECH_ALPHABET.encode(convertRadix2([chk % powers[30]], 30, 5, false));
}
/**
 * @__NO_SIDE_EFFECTS__
 */
function genBech32(encoding) {
    const ENCODING_CONST = encoding === 'bech32' ? 1 : 0x2bc830a3;
    const _words = radix2(5);
    const fromWords = _words.decode;
    const toWords = _words.encode;
    const fromWordsUnsafe = unsafeWrapper(fromWords);
    function encode(prefix, words, limit = 90) {
        astr('bech32.encode prefix', prefix);
        if (isBytes(words))
            words = Array.from(words);
        anumArr('bech32.encode', words);
        const plen = prefix.length;
        if (plen === 0)
            throw new TypeError(`Invalid prefix length ${plen}`);
        const actualLength = plen + 7 + words.length;
        if (limit !== false && actualLength > limit)
            throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
        const lowered = prefix.toLowerCase();
        const sum = bechChecksum(lowered, words, ENCODING_CONST);
        return `${lowered}1${BECH_ALPHABET.encode(words)}${sum}`;
    }
    function decode(str, limit = 90) {
        astr('bech32.decode input', str);
        const slen = str.length;
        if (slen < 8 || (limit !== false && slen > limit))
            throw new TypeError(`invalid string length: ${slen} (${str}). Expected (8..${limit})`);
        // don't allow mixed case
        const lowered = str.toLowerCase();
        if (str !== lowered && str !== str.toUpperCase())
            throw new Error(`String must be lowercase or uppercase`);
        const sepIndex = lowered.lastIndexOf('1');
        if (sepIndex === 0 || sepIndex === -1)
            throw new Error(`Letter "1" must be present between prefix and data only`);
        const prefix = lowered.slice(0, sepIndex);
        const data = lowered.slice(sepIndex + 1);
        if (data.length < 6)
            throw new Error('Data must be at least 6 characters long');
        const words = BECH_ALPHABET.decode(data).slice(0, -6);
        const sum = bechChecksum(prefix, words, ENCODING_CONST);
        if (!data.endsWith(sum))
            throw new Error(`Invalid checksum in ${str}: expected "${sum}"`);
        return { prefix, words };
    }
    const decodeUnsafe = unsafeWrapper(decode);
    function decodeToBytes(str) {
        const { prefix, words } = decode(str, false);
        return { prefix, words, bytes: fromWords(words) };
    }
    function encodeFromBytes(prefix, bytes) {
        return encode(prefix, toWords(bytes));
    }
    return {
        encode,
        decode,
        encodeFromBytes,
        decodeToBytes,
        decodeUnsafe,
        fromWords,
        fromWordsUnsafe,
        toWords,
    };
}
/**
 * bech32 from BIP 173. Operates on words.
 * For high-level, check out scure-btc-signer:
 * https://github.com/paulmillr/scure-btc-signer.
 */
exports.bech32 = genBech32('bech32');
/**
 * bech32m from BIP 350. Operates on words.
 * It was to mitigate `bech32` weaknesses.
 * For high-level, check out scure-btc-signer:
 * https://github.com/paulmillr/scure-btc-signer.
 */
exports.bech32m = genBech32('bech32m');
/**
 * UTF-8-to-byte decoder. Uses built-in TextDecoder / TextEncoder.
 * @example
 * ```js
 * const b = utf8.decode("hey"); // => new Uint8Array([ 104, 101, 121 ])
 * const str = utf8.encode(b); // "hey"
 * ```
 */
exports.utf8 = {
    encode: (data) => new TextDecoder().decode(data),
    decode: (str) => new TextEncoder().encode(str),
};
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
// prettier-ignore
const hasHexBuiltin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toHex === 'function' &&
    typeof Uint8Array.fromHex === 'function')();
// prettier-ignore
const hexBuiltin = {
    encode(data) { abytes(data); return data.toHex(); },
    decode(s) { astr('hex', s); return Uint8Array.fromHex(s); },
};
/**
 * hex string decoder. Uses built-in function, when available.
 * @example
 * ```js
 * const b = hex.decode("0102ff"); // => new Uint8Array([ 1, 2, 255 ])
 * const str = hex.encode(b); // "0102ff"
 * ```
 */
exports.hex = hasHexBuiltin
    ? hexBuiltin
    : chain(radix2(4), alphabet('0123456789abcdef'), join(''), normalize((s) => {
        if (typeof s !== 'string' || s.length % 2 !== 0)
            throw new TypeError(`hex.decode: expected string, got ${typeof s} with length ${s.length}`);
        return s.toLowerCase();
    }));
// prettier-ignore
const CODERS = {
    utf8: exports.utf8, hex: exports.hex, base16: exports.base16, base32: exports.base32, base64: exports.base64, base64url: exports.base64url, base58: exports.base58, base58xmr: exports.base58xmr
};
const coderTypeError = 'Invalid encoding type. Available types: utf8, hex, base16, base32, base64, base64url, base58, base58xmr';
/** @deprecated */
const bytesToString = (type, bytes) => {
    if (typeof type !== 'string' || !CODERS.hasOwnProperty(type))
        throw new TypeError(coderTypeError);
    if (!isBytes(bytes))
        throw new TypeError('bytesToString() expects Uint8Array');
    return CODERS[type].encode(bytes);
};
exports.bytesToString = bytesToString;
/** @deprecated */
exports.str = exports.bytesToString; // as in python, but for bytes only
/** @deprecated */
const stringToBytes = (type, str) => {
    if (!CODERS.hasOwnProperty(type))
        throw new TypeError(coderTypeError);
    if (typeof str !== 'string')
        throw new TypeError('stringToBytes() expects string');
    return CODERS[type].decode(str);
};
exports.stringToBytes = stringToBytes;
/** @deprecated */
exports.bytes = exports.stringToBytes;
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 7598:
/***/ ((module) => {

module.exports = require("node:crypto");

/***/ }),

/***/ 1239:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var bcs_type_exports = {};
__export(bcs_type_exports, {
  BcsType: () => BcsType,
  SerializedBcs: () => SerializedBcs,
  bigUIntBcsType: () => bigUIntBcsType,
  dynamicSizeBcsType: () => dynamicSizeBcsType,
  fixedSizeBcsType: () => fixedSizeBcsType,
  isSerializedBcs: () => isSerializedBcs,
  lazyBcsType: () => lazyBcsType,
  stringLikeBcsType: () => stringLikeBcsType,
  uIntBcsType: () => uIntBcsType
});
module.exports = __toCommonJS(bcs_type_exports);
var import_utils = __nccwpck_require__(5041);
var import_reader = __nccwpck_require__(5967);
var import_uleb = __nccwpck_require__(4314);
var import_writer = __nccwpck_require__(1023);
var _write, _serialize, _schema, _bytes;
const _BcsType = class _BcsType {
  constructor(options) {
    __privateAdd(this, _write);
    __privateAdd(this, _serialize);
    this.name = options.name;
    this.read = options.read;
    this.serializedSize = options.serializedSize ?? (() => null);
    __privateSet(this, _write, options.write);
    __privateSet(this, _serialize, options.serialize ?? ((value, options2) => {
      const writer = new import_writer.BcsWriter({
        initialSize: this.serializedSize(value) ?? void 0,
        ...options2
      });
      __privateGet(this, _write).call(this, value, writer);
      return writer.toBytes();
    }));
    this.validate = options.validate ?? (() => {
    });
  }
  write(value, writer) {
    this.validate(value);
    __privateGet(this, _write).call(this, value, writer);
  }
  serialize(value, options) {
    this.validate(value);
    return new SerializedBcs(this, __privateGet(this, _serialize).call(this, value, options));
  }
  parse(bytes) {
    const reader = new import_reader.BcsReader(bytes);
    return this.read(reader);
  }
  fromHex(hex) {
    return this.parse((0, import_utils.fromHex)(hex));
  }
  fromBase58(b64) {
    return this.parse((0, import_utils.fromBase58)(b64));
  }
  fromBase64(b64) {
    return this.parse((0, import_utils.fromBase64)(b64));
  }
  transform({
    name,
    input,
    output,
    validate
  }) {
    return new _BcsType({
      name: name ?? this.name,
      read: (reader) => output ? output(this.read(reader)) : this.read(reader),
      write: (value, writer) => __privateGet(this, _write).call(this, input ? input(value) : value, writer),
      serializedSize: (value) => this.serializedSize(input ? input(value) : value),
      serialize: (value, options) => __privateGet(this, _serialize).call(this, input ? input(value) : value, options),
      validate: (value) => {
        validate?.(value);
        this.validate(input ? input(value) : value);
      }
    });
  }
};
_write = new WeakMap();
_serialize = new WeakMap();
let BcsType = _BcsType;
const SERIALIZED_BCS_BRAND = Symbol.for("@mysten/serialized-bcs");
function isSerializedBcs(obj) {
  return !!obj && typeof obj === "object" && obj[SERIALIZED_BCS_BRAND] === true;
}
class SerializedBcs {
  constructor(type, schema) {
    __privateAdd(this, _schema);
    __privateAdd(this, _bytes);
    __privateSet(this, _schema, type);
    __privateSet(this, _bytes, schema);
  }
  // Used to brand SerializedBcs so that they can be identified, even between multiple copies
  // of the @mysten/bcs package are installed
  get [SERIALIZED_BCS_BRAND]() {
    return true;
  }
  toBytes() {
    return __privateGet(this, _bytes);
  }
  toHex() {
    return (0, import_utils.toHex)(__privateGet(this, _bytes));
  }
  toBase64() {
    return (0, import_utils.toBase64)(__privateGet(this, _bytes));
  }
  toBase58() {
    return (0, import_utils.toBase58)(__privateGet(this, _bytes));
  }
  parse() {
    return __privateGet(this, _schema).parse(__privateGet(this, _bytes));
  }
}
_schema = new WeakMap();
_bytes = new WeakMap();
function fixedSizeBcsType({
  size,
  ...options
}) {
  return new BcsType({
    ...options,
    serializedSize: () => size
  });
}
function uIntBcsType({
  readMethod,
  writeMethod,
  ...options
}) {
  return fixedSizeBcsType({
    ...options,
    read: (reader) => reader[readMethod](),
    write: (value, writer) => writer[writeMethod](value),
    validate: (value) => {
      if (value < 0 || value > options.maxValue) {
        throw new TypeError(
          `Invalid ${options.name} value: ${value}. Expected value in range 0-${options.maxValue}`
        );
      }
      options.validate?.(value);
    }
  });
}
function bigUIntBcsType({
  readMethod,
  writeMethod,
  ...options
}) {
  return fixedSizeBcsType({
    ...options,
    read: (reader) => reader[readMethod](),
    write: (value, writer) => writer[writeMethod](BigInt(value)),
    validate: (val) => {
      const value = BigInt(val);
      if (value < 0 || value > options.maxValue) {
        throw new TypeError(
          `Invalid ${options.name} value: ${value}. Expected value in range 0-${options.maxValue}`
        );
      }
      options.validate?.(value);
    }
  });
}
function dynamicSizeBcsType({
  serialize,
  ...options
}) {
  const type = new BcsType({
    ...options,
    serialize,
    write: (value, writer) => {
      for (const byte of type.serialize(value).toBytes()) {
        writer.write8(byte);
      }
    }
  });
  return type;
}
function stringLikeBcsType({
  toBytes,
  fromBytes,
  ...options
}) {
  return new BcsType({
    ...options,
    read: (reader) => {
      const length = reader.readULEB();
      const bytes = reader.readBytes(length);
      return fromBytes(bytes);
    },
    write: (hex, writer) => {
      const bytes = toBytes(hex);
      writer.writeULEB(bytes.length);
      for (let i = 0; i < bytes.length; i++) {
        writer.write8(bytes[i]);
      }
    },
    serialize: (value) => {
      const bytes = toBytes(value);
      const size = (0, import_uleb.ulebEncode)(bytes.length);
      const result = new Uint8Array(size.length + bytes.length);
      result.set(size, 0);
      result.set(bytes, size.length);
      return result;
    },
    validate: (value) => {
      if (typeof value !== "string") {
        throw new TypeError(`Invalid ${options.name} value: ${value}. Expected string`);
      }
      options.validate?.(value);
    }
  });
}
function lazyBcsType(cb) {
  let lazyType = null;
  function getType() {
    if (!lazyType) {
      lazyType = cb();
    }
    return lazyType;
  }
  return new BcsType({
    name: "lazy",
    read: (data) => getType().read(data),
    serializedSize: (value) => getType().serializedSize(value),
    write: (value, writer) => getType().write(value, writer),
    serialize: (value, options) => getType().serialize(value, options).toBytes()
  });
}
//# sourceMappingURL=bcs-type.js.map


/***/ }),

/***/ 3358:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var bcs_exports = {};
__export(bcs_exports, {
  bcs: () => bcs
});
module.exports = __toCommonJS(bcs_exports);
var import_bcs_type = __nccwpck_require__(1239);
var import_uleb = __nccwpck_require__(4314);
const bcs = {
  /**
   * Creates a BcsType that can be used to read and write an 8-bit unsigned integer.
   * @example
   * bcs.u8().serialize(255).toBytes() // Uint8Array [ 255 ]
   */
  u8(options) {
    return (0, import_bcs_type.uIntBcsType)({
      name: "u8",
      readMethod: "read8",
      writeMethod: "write8",
      size: 1,
      maxValue: 2 ** 8 - 1,
      ...options
    });
  },
  /**
   * Creates a BcsType that can be used to read and write a 16-bit unsigned integer.
   * @example
   * bcs.u16().serialize(65535).toBytes() // Uint8Array [ 255, 255 ]
   */
  u16(options) {
    return (0, import_bcs_type.uIntBcsType)({
      name: "u16",
      readMethod: "read16",
      writeMethod: "write16",
      size: 2,
      maxValue: 2 ** 16 - 1,
      ...options
    });
  },
  /**
   * Creates a BcsType that can be used to read and write a 32-bit unsigned integer.
   * @example
   * bcs.u32().serialize(4294967295).toBytes() // Uint8Array [ 255, 255, 255, 255 ]
   */
  u32(options) {
    return (0, import_bcs_type.uIntBcsType)({
      name: "u32",
      readMethod: "read32",
      writeMethod: "write32",
      size: 4,
      maxValue: 2 ** 32 - 1,
      ...options
    });
  },
  /**
   * Creates a BcsType that can be used to read and write a 64-bit unsigned integer.
   * @example
   * bcs.u64().serialize(1).toBytes() // Uint8Array [ 1, 0, 0, 0, 0, 0, 0, 0 ]
   */
  u64(options) {
    return (0, import_bcs_type.bigUIntBcsType)({
      name: "u64",
      readMethod: "read64",
      writeMethod: "write64",
      size: 8,
      maxValue: 2n ** 64n - 1n,
      ...options
    });
  },
  /**
   * Creates a BcsType that can be used to read and write a 128-bit unsigned integer.
   * @example
   * bcs.u128().serialize(1).toBytes() // Uint8Array [ 1, ..., 0 ]
   */
  u128(options) {
    return (0, import_bcs_type.bigUIntBcsType)({
      name: "u128",
      readMethod: "read128",
      writeMethod: "write128",
      size: 16,
      maxValue: 2n ** 128n - 1n,
      ...options
    });
  },
  /**
   * Creates a BcsType that can be used to read and write a 256-bit unsigned integer.
   * @example
   * bcs.u256().serialize(1).toBytes() // Uint8Array [ 1, ..., 0 ]
   */
  u256(options) {
    return (0, import_bcs_type.bigUIntBcsType)({
      name: "u256",
      readMethod: "read256",
      writeMethod: "write256",
      size: 32,
      maxValue: 2n ** 256n - 1n,
      ...options
    });
  },
  /**
   * Creates a BcsType that can be used to read and write boolean values.
   * @example
   * bcs.bool().serialize(true).toBytes() // Uint8Array [ 1 ]
   */
  bool(options) {
    return (0, import_bcs_type.fixedSizeBcsType)({
      name: "bool",
      size: 1,
      read: (reader) => reader.read8() === 1,
      write: (value, writer) => writer.write8(value ? 1 : 0),
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (typeof value !== "boolean") {
          throw new TypeError(`Expected boolean, found ${typeof value}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType that can be used to read and write unsigned LEB encoded integers
   * @example
   *
   */
  uleb128(options) {
    return (0, import_bcs_type.dynamicSizeBcsType)({
      name: "uleb128",
      read: (reader) => reader.readULEB(),
      serialize: (value) => {
        return Uint8Array.from((0, import_uleb.ulebEncode)(value));
      },
      ...options
    });
  },
  /**
   * Creates a BcsType representing a fixed length byte array
   * @param size The number of bytes this types represents
   * @example
   * bcs.bytes(3).serialize(new Uint8Array([1, 2, 3])).toBytes() // Uint8Array [1, 2, 3]
   */
  bytes(size, options) {
    return (0, import_bcs_type.fixedSizeBcsType)({
      name: `bytes[${size}]`,
      size,
      read: (reader) => reader.readBytes(size),
      write: (value, writer) => {
        const array = new Uint8Array(value);
        for (let i = 0; i < size; i++) {
          writer.write8(array[i] ?? 0);
        }
      },
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (!value || typeof value !== "object" || !("length" in value)) {
          throw new TypeError(`Expected array, found ${typeof value}`);
        }
        if (value.length !== size) {
          throw new TypeError(`Expected array of length ${size}, found ${value.length}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType representing a variable length byte array
   *
   * @example
   * bcs.byteVector().serialize([1, 2, 3]).toBytes() // Uint8Array [3, 1, 2, 3]
   */
  byteVector(options) {
    return new import_bcs_type.BcsType({
      name: `bytesVector`,
      read: (reader) => {
        const length = reader.readULEB();
        return reader.readBytes(length);
      },
      write: (value, writer) => {
        const array = new Uint8Array(value);
        writer.writeULEB(array.length);
        for (let i = 0; i < array.length; i++) {
          writer.write8(array[i] ?? 0);
        }
      },
      ...options,
      serializedSize: (value) => {
        const length = "length" in value ? value.length : null;
        return length == null ? null : (0, import_uleb.ulebEncode)(length).length + length;
      },
      validate: (value) => {
        options?.validate?.(value);
        if (!value || typeof value !== "object" || !("length" in value)) {
          throw new TypeError(`Expected array, found ${typeof value}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType that can ser/de string values.  Strings will be UTF-8 encoded
   * @example
   * bcs.string().serialize('a').toBytes() // Uint8Array [ 1, 97 ]
   */
  string(options) {
    return (0, import_bcs_type.stringLikeBcsType)({
      name: "string",
      toBytes: (value) => new TextEncoder().encode(value),
      fromBytes: (bytes) => new TextDecoder().decode(bytes),
      ...options
    });
  },
  /**
   * Creates a BcsType that represents a fixed length array of a given type
   * @param size The number of elements in the array
   * @param type The BcsType of each element in the array
   * @example
   * bcs.fixedArray(3, bcs.u8()).serialize([1, 2, 3]).toBytes() // Uint8Array [ 1, 2, 3 ]
   */
  fixedArray(size, type, options) {
    return new import_bcs_type.BcsType({
      name: `${type.name}[${size}]`,
      read: (reader) => {
        const result = new Array(size);
        for (let i = 0; i < size; i++) {
          result[i] = type.read(reader);
        }
        return result;
      },
      write: (value, writer) => {
        for (const item of value) {
          type.write(item, writer);
        }
      },
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (!value || typeof value !== "object" || !("length" in value)) {
          throw new TypeError(`Expected array, found ${typeof value}`);
        }
        if (value.length !== size) {
          throw new TypeError(`Expected array of length ${size}, found ${value.length}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType representing an optional value
   * @param type The BcsType of the optional value
   * @example
   * bcs.option(bcs.u8()).serialize(null).toBytes() // Uint8Array [ 0 ]
   * bcs.option(bcs.u8()).serialize(1).toBytes() // Uint8Array [ 1, 1 ]
   */
  option(type) {
    return bcs.enum(`Option<${type.name}>`, {
      None: null,
      Some: type
    }).transform({
      input: (value) => {
        if (value == null) {
          return { None: true };
        }
        return { Some: value };
      },
      output: (value) => {
        if (value.$kind === "Some") {
          return value.Some;
        }
        return null;
      }
    });
  },
  /**
   * Creates a BcsType representing a variable length vector of a given type
   * @param type The BcsType of each element in the vector
   *
   * @example
   * bcs.vector(bcs.u8()).toBytes([1, 2, 3]) // Uint8Array [ 3, 1, 2, 3 ]
   */
  vector(type, options) {
    return new import_bcs_type.BcsType({
      name: `vector<${type.name}>`,
      read: (reader) => {
        const length = reader.readULEB();
        const result = new Array(length);
        for (let i = 0; i < length; i++) {
          result[i] = type.read(reader);
        }
        return result;
      },
      write: (value, writer) => {
        writer.writeULEB(value.length);
        for (const item of value) {
          type.write(item, writer);
        }
      },
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (!value || typeof value !== "object" || !("length" in value)) {
          throw new TypeError(`Expected array, found ${typeof value}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType representing a tuple of a given set of types
   * @param types The BcsTypes for each element in the tuple
   *
   * @example
   * const tuple = bcs.tuple([bcs.u8(), bcs.string(), bcs.bool()])
   * tuple.serialize([1, 'a', true]).toBytes() // Uint8Array [ 1, 1, 97, 1 ]
   */
  tuple(types, options) {
    return new import_bcs_type.BcsType({
      name: `(${types.map((t) => t.name).join(", ")})`,
      serializedSize: (values) => {
        let total = 0;
        for (let i = 0; i < types.length; i++) {
          const size = types[i].serializedSize(values[i]);
          if (size == null) {
            return null;
          }
          total += size;
        }
        return total;
      },
      read: (reader) => {
        const result = [];
        for (const type of types) {
          result.push(type.read(reader));
        }
        return result;
      },
      write: (value, writer) => {
        for (let i = 0; i < types.length; i++) {
          types[i].write(value[i], writer);
        }
      },
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (!Array.isArray(value)) {
          throw new TypeError(`Expected array, found ${typeof value}`);
        }
        if (value.length !== types.length) {
          throw new TypeError(`Expected array of length ${types.length}, found ${value.length}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType representing a struct of a given set of fields
   * @param name The name of the struct
   * @param fields The fields of the struct. The order of the fields affects how data is serialized and deserialized
   *
   * @example
   * const struct = bcs.struct('MyStruct', {
   *  a: bcs.u8(),
   *  b: bcs.string(),
   * })
   * struct.serialize({ a: 1, b: 'a' }).toBytes() // Uint8Array [ 1, 1, 97 ]
   */
  struct(name, fields, options) {
    const canonicalOrder = Object.entries(fields);
    return new import_bcs_type.BcsType({
      name,
      serializedSize: (values) => {
        let total = 0;
        for (const [field, type] of canonicalOrder) {
          const size = type.serializedSize(values[field]);
          if (size == null) {
            return null;
          }
          total += size;
        }
        return total;
      },
      read: (reader) => {
        const result = {};
        for (const [field, type] of canonicalOrder) {
          result[field] = type.read(reader);
        }
        return result;
      },
      write: (value, writer) => {
        for (const [field, type] of canonicalOrder) {
          type.write(value[field], writer);
        }
      },
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (typeof value !== "object" || value == null) {
          throw new TypeError(`Expected object, found ${typeof value}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType representing an enum of a given set of options
   * @param name The name of the enum
   * @param values The values of the enum. The order of the values affects how data is serialized and deserialized.
   * null can be used to represent a variant with no data.
   *
   * @example
   * const enum = bcs.enum('MyEnum', {
   *   A: bcs.u8(),
   *   B: bcs.string(),
   *   C: null,
   * })
   * enum.serialize({ A: 1 }).toBytes() // Uint8Array [ 0, 1 ]
   * enum.serialize({ B: 'a' }).toBytes() // Uint8Array [ 1, 1, 97 ]
   * enum.serialize({ C: true }).toBytes() // Uint8Array [ 2 ]
   */
  enum(name, values, options) {
    const canonicalOrder = Object.entries(values);
    return new import_bcs_type.BcsType({
      name,
      read: (reader) => {
        const index = reader.readULEB();
        const enumEntry = canonicalOrder[index];
        if (!enumEntry) {
          throw new TypeError(`Unknown value ${index} for enum ${name}`);
        }
        const [kind, type] = enumEntry;
        return {
          [kind]: type?.read(reader) ?? true,
          $kind: kind
        };
      },
      write: (value, writer) => {
        const [name2, val] = Object.entries(value).filter(
          ([name3]) => Object.hasOwn(values, name3)
        )[0];
        for (let i = 0; i < canonicalOrder.length; i++) {
          const [optionName, optionType] = canonicalOrder[i];
          if (optionName === name2) {
            writer.writeULEB(i);
            optionType?.write(val, writer);
            return;
          }
        }
      },
      ...options,
      validate: (value) => {
        options?.validate?.(value);
        if (typeof value !== "object" || value == null) {
          throw new TypeError(`Expected object, found ${typeof value}`);
        }
        const keys = Object.keys(value).filter(
          (k) => value[k] !== void 0 && Object.hasOwn(values, k)
        );
        if (keys.length !== 1) {
          throw new TypeError(
            `Expected object with one key, but found ${keys.length} for type ${name}}`
          );
        }
        const [variant] = keys;
        if (!Object.hasOwn(values, variant)) {
          throw new TypeError(`Invalid enum variant ${variant}`);
        }
      }
    });
  },
  /**
   * Creates a BcsType representing a map of a given key and value type
   * @param keyType The BcsType of the key
   * @param valueType The BcsType of the value
   * @example
   * const map = bcs.map(bcs.u8(), bcs.string())
   * map.serialize(new Map([[2, 'a']])).toBytes() // Uint8Array [ 1, 2, 1, 97 ]
   */
  map(keyType, valueType) {
    return bcs.vector(bcs.tuple([keyType, valueType])).transform({
      name: `Map<${keyType.name}, ${valueType.name}>`,
      input: (value) => {
        return [...value.entries()];
      },
      output: (value) => {
        const result = /* @__PURE__ */ new Map();
        for (const [key, val] of value) {
          result.set(key, val);
        }
        return result;
      }
    });
  },
  /**
   * Creates a BcsType that wraps another BcsType which is lazily evaluated. This is useful for creating recursive types.
   * @param cb A callback that returns the BcsType
   */
  lazy(cb) {
    return (0, import_bcs_type.lazyBcsType)(cb);
  }
};
//# sourceMappingURL=bcs.js.map


/***/ }),

/***/ 8830:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var index_exports = {};
__export(index_exports, {
  BcsReader: () => import_reader.BcsReader,
  BcsType: () => import_bcs_type.BcsType,
  BcsWriter: () => import_writer.BcsWriter,
  SerializedBcs: () => import_bcs_type.SerializedBcs,
  bcs: () => import_bcs.bcs,
  decodeStr: () => import_utils2.decodeStr,
  encodeStr: () => import_utils2.encodeStr,
  fromB58: () => fromB58,
  fromB64: () => fromB64,
  fromBase58: () => import_utils.fromBase58,
  fromBase64: () => import_utils.fromBase64,
  fromHEX: () => fromHEX,
  fromHex: () => import_utils.fromHex,
  isSerializedBcs: () => import_bcs_type.isSerializedBcs,
  splitGenericParameters: () => import_utils2.splitGenericParameters,
  toB58: () => toB58,
  toB64: () => toB64,
  toBase58: () => import_utils.toBase58,
  toBase64: () => import_utils.toBase64,
  toHEX: () => toHEX,
  toHex: () => import_utils.toHex
});
module.exports = __toCommonJS(index_exports);
var import_utils = __nccwpck_require__(5041);
var import_bcs_type = __nccwpck_require__(1239);
var import_bcs = __nccwpck_require__(3358);
var import_reader = __nccwpck_require__(5967);
var import_utils2 = __nccwpck_require__(8751);
var import_writer = __nccwpck_require__(1023);
const toB58 = import_utils.toBase58;
const fromB58 = import_utils.fromBase58;
const toB64 = import_utils.toBase64;
const fromB64 = import_utils.fromBase64;
const toHEX = import_utils.toHex;
const fromHEX = import_utils.fromHex;
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 5967:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var reader_exports = {};
__export(reader_exports, {
  BcsReader: () => BcsReader
});
module.exports = __toCommonJS(reader_exports);
var import_uleb = __nccwpck_require__(4314);
class BcsReader {
  /**
   * @param {Uint8Array} data Data to use as a buffer.
   */
  constructor(data) {
    this.bytePosition = 0;
    this.dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
  }
  /**
   * Shift current cursor position by `bytes`.
   *
   * @param {Number} bytes Number of bytes to
   * @returns {this} Self for possible chaining.
   */
  shift(bytes) {
    this.bytePosition += bytes;
    return this;
  }
  /**
   * Read U8 value from the buffer and shift cursor by 1.
   * @returns
   */
  read8() {
    const value = this.dataView.getUint8(this.bytePosition);
    this.shift(1);
    return value;
  }
  /**
   * Read U16 value from the buffer and shift cursor by 2.
   * @returns
   */
  read16() {
    const value = this.dataView.getUint16(this.bytePosition, true);
    this.shift(2);
    return value;
  }
  /**
   * Read U32 value from the buffer and shift cursor by 4.
   * @returns
   */
  read32() {
    const value = this.dataView.getUint32(this.bytePosition, true);
    this.shift(4);
    return value;
  }
  /**
   * Read U64 value from the buffer and shift cursor by 8.
   * @returns
   */
  read64() {
    const value1 = this.read32();
    const value2 = this.read32();
    const result = value2.toString(16) + value1.toString(16).padStart(8, "0");
    return BigInt("0x" + result).toString(10);
  }
  /**
   * Read U128 value from the buffer and shift cursor by 16.
   */
  read128() {
    const value1 = BigInt(this.read64());
    const value2 = BigInt(this.read64());
    const result = value2.toString(16) + value1.toString(16).padStart(16, "0");
    return BigInt("0x" + result).toString(10);
  }
  /**
   * Read U128 value from the buffer and shift cursor by 32.
   * @returns
   */
  read256() {
    const value1 = BigInt(this.read128());
    const value2 = BigInt(this.read128());
    const result = value2.toString(16) + value1.toString(16).padStart(32, "0");
    return BigInt("0x" + result).toString(10);
  }
  /**
   * Read `num` number of bytes from the buffer and shift cursor by `num`.
   * @param num Number of bytes to read.
   */
  readBytes(num) {
    const start = this.bytePosition + this.dataView.byteOffset;
    const value = new Uint8Array(this.dataView.buffer, start, num);
    this.shift(num);
    return value;
  }
  /**
   * Read ULEB value - an integer of varying size. Used for enum indexes and
   * vector lengths.
   * @returns {Number} The ULEB value.
   */
  readULEB() {
    const start = this.bytePosition + this.dataView.byteOffset;
    const buffer = new Uint8Array(this.dataView.buffer, start);
    const { value, length } = (0, import_uleb.ulebDecode)(buffer);
    this.shift(length);
    return value;
  }
  /**
   * Read a BCS vector: read a length and then apply function `cb` X times
   * where X is the length of the vector, defined as ULEB in BCS bytes.
   * @param cb Callback to process elements of vector.
   * @returns {Array<Any>} Array of the resulting values, returned by callback.
   */
  readVec(cb) {
    const length = this.readULEB();
    const result = [];
    for (let i = 0; i < length; i++) {
      result.push(cb(this, i, length));
    }
    return result;
  }
}
//# sourceMappingURL=reader.js.map


/***/ }),

/***/ 4314:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var uleb_exports = {};
__export(uleb_exports, {
  ulebDecode: () => ulebDecode,
  ulebEncode: () => ulebEncode
});
module.exports = __toCommonJS(uleb_exports);
function ulebEncode(num) {
  const arr = [];
  let len = 0;
  if (num === 0) {
    return [0];
  }
  while (num > 0) {
    arr[len] = num & 127;
    if (num >>= 7) {
      arr[len] |= 128;
    }
    len += 1;
  }
  return arr;
}
function ulebDecode(arr) {
  let total = 0;
  let shift = 0;
  let len = 0;
  while (true) {
    const byte = arr[len];
    len += 1;
    total |= (byte & 127) << shift;
    if ((byte & 128) === 0) {
      break;
    }
    shift += 7;
  }
  return {
    value: total,
    length: len
  };
}
//# sourceMappingURL=uleb.js.map


/***/ }),

/***/ 8751:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var utils_exports = {};
__export(utils_exports, {
  decodeStr: () => decodeStr,
  encodeStr: () => encodeStr,
  splitGenericParameters: () => splitGenericParameters
});
module.exports = __toCommonJS(utils_exports);
var import_utils = __nccwpck_require__(5041);
function encodeStr(data, encoding) {
  switch (encoding) {
    case "base58":
      return (0, import_utils.toBase58)(data);
    case "base64":
      return (0, import_utils.toBase64)(data);
    case "hex":
      return (0, import_utils.toHex)(data);
    default:
      throw new Error("Unsupported encoding, supported values are: base64, hex");
  }
}
function decodeStr(data, encoding) {
  switch (encoding) {
    case "base58":
      return (0, import_utils.fromBase58)(data);
    case "base64":
      return (0, import_utils.fromBase64)(data);
    case "hex":
      return (0, import_utils.fromHex)(data);
    default:
      throw new Error("Unsupported encoding, supported values are: base64, hex");
  }
}
function splitGenericParameters(str, genericSeparators = ["<", ">"]) {
  const [left, right] = genericSeparators;
  const tok = [];
  let word = "";
  let nestedAngleBrackets = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    if (char === left) {
      nestedAngleBrackets++;
    }
    if (char === right) {
      nestedAngleBrackets--;
    }
    if (nestedAngleBrackets === 0 && char === ",") {
      tok.push(word.trim());
      word = "";
      continue;
    }
    word += char;
  }
  tok.push(word.trim());
  return tok;
}
//# sourceMappingURL=utils.js.map


/***/ }),

/***/ 1023:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var writer_exports = {};
__export(writer_exports, {
  BcsWriter: () => BcsWriter
});
module.exports = __toCommonJS(writer_exports);
var import_uleb = __nccwpck_require__(4314);
var import_utils = __nccwpck_require__(8751);
class BcsWriter {
  constructor({
    initialSize = 1024,
    maxSize = Infinity,
    allocateSize = 1024
  } = {}) {
    this.bytePosition = 0;
    this.size = initialSize;
    this.maxSize = maxSize;
    this.allocateSize = allocateSize;
    this.dataView = new DataView(new ArrayBuffer(initialSize));
  }
  ensureSizeOrGrow(bytes) {
    const requiredSize = this.bytePosition + bytes;
    if (requiredSize > this.size) {
      const nextSize = Math.min(this.maxSize, this.size + this.allocateSize);
      if (requiredSize > nextSize) {
        throw new Error(
          `Attempting to serialize to BCS, but buffer does not have enough size. Allocated size: ${this.size}, Max size: ${this.maxSize}, Required size: ${requiredSize}`
        );
      }
      this.size = nextSize;
      const nextBuffer = new ArrayBuffer(this.size);
      new Uint8Array(nextBuffer).set(new Uint8Array(this.dataView.buffer));
      this.dataView = new DataView(nextBuffer);
    }
  }
  /**
   * Shift current cursor position by `bytes`.
   *
   * @param {Number} bytes Number of bytes to
   * @returns {this} Self for possible chaining.
   */
  shift(bytes) {
    this.bytePosition += bytes;
    return this;
  }
  /**
   * Write a U8 value into a buffer and shift cursor position by 1.
   * @param {Number} value Value to write.
   * @returns {this}
   */
  write8(value) {
    this.ensureSizeOrGrow(1);
    this.dataView.setUint8(this.bytePosition, Number(value));
    return this.shift(1);
  }
  /**
   * Write a U16 value into a buffer and shift cursor position by 2.
   * @param {Number} value Value to write.
   * @returns {this}
   */
  write16(value) {
    this.ensureSizeOrGrow(2);
    this.dataView.setUint16(this.bytePosition, Number(value), true);
    return this.shift(2);
  }
  /**
   * Write a U32 value into a buffer and shift cursor position by 4.
   * @param {Number} value Value to write.
   * @returns {this}
   */
  write32(value) {
    this.ensureSizeOrGrow(4);
    this.dataView.setUint32(this.bytePosition, Number(value), true);
    return this.shift(4);
  }
  /**
   * Write a U64 value into a buffer and shift cursor position by 8.
   * @param {bigint} value Value to write.
   * @returns {this}
   */
  write64(value) {
    toLittleEndian(BigInt(value), 8).forEach((el) => this.write8(el));
    return this;
  }
  /**
   * Write a U128 value into a buffer and shift cursor position by 16.
   *
   * @param {bigint} value Value to write.
   * @returns {this}
   */
  write128(value) {
    toLittleEndian(BigInt(value), 16).forEach((el) => this.write8(el));
    return this;
  }
  /**
   * Write a U256 value into a buffer and shift cursor position by 16.
   *
   * @param {bigint} value Value to write.
   * @returns {this}
   */
  write256(value) {
    toLittleEndian(BigInt(value), 32).forEach((el) => this.write8(el));
    return this;
  }
  /**
   * Write a ULEB value into a buffer and shift cursor position by number of bytes
   * written.
   * @param {Number} value Value to write.
   * @returns {this}
   */
  writeULEB(value) {
    (0, import_uleb.ulebEncode)(value).forEach((el) => this.write8(el));
    return this;
  }
  /**
   * Write a vector into a buffer by first writing the vector length and then calling
   * a callback on each passed value.
   *
   * @param {Array<Any>} vector Array of elements to write.
   * @param {WriteVecCb} cb Callback to call on each element of the vector.
   * @returns {this}
   */
  writeVec(vector, cb) {
    this.writeULEB(vector.length);
    Array.from(vector).forEach((el, i) => cb(this, el, i, vector.length));
    return this;
  }
  /**
   * Adds support for iterations over the object.
   * @returns {Uint8Array}
   */
  *[Symbol.iterator]() {
    for (let i = 0; i < this.bytePosition; i++) {
      yield this.dataView.getUint8(i);
    }
    return this.toBytes();
  }
  /**
   * Get underlying buffer taking only value bytes (in case initial buffer size was bigger).
   * @returns {Uint8Array} Resulting bcs.
   */
  toBytes() {
    return new Uint8Array(this.dataView.buffer.slice(0, this.bytePosition));
  }
  /**
   * Represent data as 'hex' or 'base64'
   * @param encoding Encoding to use: 'base64' or 'hex'
   */
  toString(encoding) {
    return (0, import_utils.encodeStr)(this.toBytes(), encoding);
  }
}
function toLittleEndian(bigint, size) {
  const result = new Uint8Array(size);
  let i = 0;
  while (bigint > 0) {
    result[i] = Number(bigint % BigInt(256));
    bigint = bigint / BigInt(256);
    i += 1;
  }
  return result;
}
//# sourceMappingURL=writer.js.map


/***/ }),

/***/ 3388:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var bcs_exports = {};
__export(bcs_exports, {
  Address: () => Address,
  AppId: () => AppId,
  Argument: () => Argument,
  CallArg: () => CallArg,
  Command: () => Command,
  CompressedSignature: () => CompressedSignature,
  GasData: () => GasData,
  Intent: () => Intent,
  IntentMessage: () => IntentMessage,
  IntentScope: () => IntentScope,
  IntentVersion: () => IntentVersion,
  MultiSig: () => MultiSig,
  MultiSigPkMap: () => MultiSigPkMap,
  MultiSigPublicKey: () => MultiSigPublicKey,
  ObjectArg: () => ObjectArg,
  ObjectDigest: () => ObjectDigest,
  Owner: () => Owner,
  PasskeyAuthenticator: () => PasskeyAuthenticator,
  ProgrammableMoveCall: () => ProgrammableMoveCall,
  ProgrammableTransaction: () => ProgrammableTransaction,
  PublicKey: () => PublicKey,
  SenderSignedData: () => SenderSignedData,
  SenderSignedTransaction: () => SenderSignedTransaction,
  SharedObjectRef: () => SharedObjectRef,
  StructTag: () => StructTag,
  SuiObjectRef: () => SuiObjectRef,
  TransactionData: () => TransactionData,
  TransactionDataV1: () => TransactionDataV1,
  TransactionExpiration: () => TransactionExpiration,
  TransactionKind: () => TransactionKind,
  TypeTag: () => TypeTag,
  base64String: () => base64String
});
module.exports = __toCommonJS(bcs_exports);
var import_bcs = __nccwpck_require__(8830);
var import_sui_types = __nccwpck_require__(4818);
var import_type_tag_serializer = __nccwpck_require__(1020);
function unsafe_u64(options) {
  return import_bcs.bcs.u64({
    name: "unsafe_u64",
    ...options
  }).transform({
    input: (val) => val,
    output: (val) => Number(val)
  });
}
function optionEnum(type) {
  return import_bcs.bcs.enum("Option", {
    None: null,
    Some: type
  });
}
const Address = import_bcs.bcs.bytes(import_sui_types.SUI_ADDRESS_LENGTH).transform({
  validate: (val) => {
    const address = typeof val === "string" ? val : (0, import_bcs.toHex)(val);
    if (!address || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(address))) {
      throw new Error(`Invalid Sui address ${address}`);
    }
  },
  input: (val) => typeof val === "string" ? (0, import_bcs.fromHex)((0, import_sui_types.normalizeSuiAddress)(val)) : val,
  output: (val) => (0, import_sui_types.normalizeSuiAddress)((0, import_bcs.toHex)(val))
});
const ObjectDigest = import_bcs.bcs.vector(import_bcs.bcs.u8()).transform({
  name: "ObjectDigest",
  input: (value) => (0, import_bcs.fromBase58)(value),
  output: (value) => (0, import_bcs.toBase58)(new Uint8Array(value)),
  validate: (value) => {
    if ((0, import_bcs.fromBase58)(value).length !== 32) {
      throw new Error("ObjectDigest must be 32 bytes");
    }
  }
});
const SuiObjectRef = import_bcs.bcs.struct("SuiObjectRef", {
  objectId: Address,
  version: import_bcs.bcs.u64(),
  digest: ObjectDigest
});
const SharedObjectRef = import_bcs.bcs.struct("SharedObjectRef", {
  objectId: Address,
  initialSharedVersion: import_bcs.bcs.u64(),
  mutable: import_bcs.bcs.bool()
});
const ObjectArg = import_bcs.bcs.enum("ObjectArg", {
  ImmOrOwnedObject: SuiObjectRef,
  SharedObject: SharedObjectRef,
  Receiving: SuiObjectRef
});
const Owner = import_bcs.bcs.enum("Owner", {
  AddressOwner: Address,
  ObjectOwner: Address,
  Shared: import_bcs.bcs.struct("Shared", {
    initialSharedVersion: import_bcs.bcs.u64()
  }),
  Immutable: null,
  ConsensusV2: import_bcs.bcs.struct("ConsensusV2", {
    authenticator: import_bcs.bcs.enum("Authenticator", {
      SingleOwner: Address
    }),
    startVersion: import_bcs.bcs.u64()
  })
});
const CallArg = import_bcs.bcs.enum("CallArg", {
  Pure: import_bcs.bcs.struct("Pure", {
    bytes: import_bcs.bcs.vector(import_bcs.bcs.u8()).transform({
      input: (val) => typeof val === "string" ? (0, import_bcs.fromBase64)(val) : val,
      output: (val) => (0, import_bcs.toBase64)(new Uint8Array(val))
    })
  }),
  Object: ObjectArg
});
const InnerTypeTag = import_bcs.bcs.enum("TypeTag", {
  bool: null,
  u8: null,
  u64: null,
  u128: null,
  address: null,
  signer: null,
  vector: import_bcs.bcs.lazy(() => InnerTypeTag),
  struct: import_bcs.bcs.lazy(() => StructTag),
  u16: null,
  u32: null,
  u256: null
});
const TypeTag = InnerTypeTag.transform({
  input: (typeTag) => typeof typeTag === "string" ? import_type_tag_serializer.TypeTagSerializer.parseFromStr(typeTag, true) : typeTag,
  output: (typeTag) => import_type_tag_serializer.TypeTagSerializer.tagToString(typeTag)
});
const Argument = import_bcs.bcs.enum("Argument", {
  GasCoin: null,
  Input: import_bcs.bcs.u16(),
  Result: import_bcs.bcs.u16(),
  NestedResult: import_bcs.bcs.tuple([import_bcs.bcs.u16(), import_bcs.bcs.u16()])
});
const ProgrammableMoveCall = import_bcs.bcs.struct("ProgrammableMoveCall", {
  package: Address,
  module: import_bcs.bcs.string(),
  function: import_bcs.bcs.string(),
  typeArguments: import_bcs.bcs.vector(TypeTag),
  arguments: import_bcs.bcs.vector(Argument)
});
const Command = import_bcs.bcs.enum("Command", {
  /**
   * A Move Call - any public Move function can be called via
   * this transaction. The results can be used that instant to pass
   * into the next transaction.
   */
  MoveCall: ProgrammableMoveCall,
  /**
   * Transfer vector of objects to a receiver.
   */
  TransferObjects: import_bcs.bcs.struct("TransferObjects", {
    objects: import_bcs.bcs.vector(Argument),
    address: Argument
  }),
  // /**
  //  * Split `amount` from a `coin`.
  //  */
  SplitCoins: import_bcs.bcs.struct("SplitCoins", {
    coin: Argument,
    amounts: import_bcs.bcs.vector(Argument)
  }),
  // /**
  //  * Merge Vector of Coins (`sources`) into a `destination`.
  //  */
  MergeCoins: import_bcs.bcs.struct("MergeCoins", {
    destination: Argument,
    sources: import_bcs.bcs.vector(Argument)
  }),
  // /**
  //  * Publish a Move module.
  //  */
  Publish: import_bcs.bcs.struct("Publish", {
    modules: import_bcs.bcs.vector(
      import_bcs.bcs.vector(import_bcs.bcs.u8()).transform({
        input: (val) => typeof val === "string" ? (0, import_bcs.fromBase64)(val) : val,
        output: (val) => (0, import_bcs.toBase64)(new Uint8Array(val))
      })
    ),
    dependencies: import_bcs.bcs.vector(Address)
  }),
  // /**
  //  * Build a vector of objects using the input arguments.
  //  * It is impossible to export construct a `vector<T: key>` otherwise,
  //  * so this call serves a utility function.
  //  */
  MakeMoveVec: import_bcs.bcs.struct("MakeMoveVec", {
    type: optionEnum(TypeTag).transform({
      input: (val) => val === null ? {
        None: true
      } : {
        Some: val
      },
      output: (val) => val.Some ?? null
    }),
    elements: import_bcs.bcs.vector(Argument)
  }),
  Upgrade: import_bcs.bcs.struct("Upgrade", {
    modules: import_bcs.bcs.vector(
      import_bcs.bcs.vector(import_bcs.bcs.u8()).transform({
        input: (val) => typeof val === "string" ? (0, import_bcs.fromBase64)(val) : val,
        output: (val) => (0, import_bcs.toBase64)(new Uint8Array(val))
      })
    ),
    dependencies: import_bcs.bcs.vector(Address),
    package: Address,
    ticket: Argument
  })
});
const ProgrammableTransaction = import_bcs.bcs.struct("ProgrammableTransaction", {
  inputs: import_bcs.bcs.vector(CallArg),
  commands: import_bcs.bcs.vector(Command)
});
const TransactionKind = import_bcs.bcs.enum("TransactionKind", {
  ProgrammableTransaction,
  ChangeEpoch: null,
  Genesis: null,
  ConsensusCommitPrologue: null
});
const TransactionExpiration = import_bcs.bcs.enum("TransactionExpiration", {
  None: null,
  Epoch: unsafe_u64()
});
const StructTag = import_bcs.bcs.struct("StructTag", {
  address: Address,
  module: import_bcs.bcs.string(),
  name: import_bcs.bcs.string(),
  typeParams: import_bcs.bcs.vector(InnerTypeTag)
});
const GasData = import_bcs.bcs.struct("GasData", {
  payment: import_bcs.bcs.vector(SuiObjectRef),
  owner: Address,
  price: import_bcs.bcs.u64(),
  budget: import_bcs.bcs.u64()
});
const TransactionDataV1 = import_bcs.bcs.struct("TransactionDataV1", {
  kind: TransactionKind,
  sender: Address,
  gasData: GasData,
  expiration: TransactionExpiration
});
const TransactionData = import_bcs.bcs.enum("TransactionData", {
  V1: TransactionDataV1
});
const IntentScope = import_bcs.bcs.enum("IntentScope", {
  TransactionData: null,
  TransactionEffects: null,
  CheckpointSummary: null,
  PersonalMessage: null
});
const IntentVersion = import_bcs.bcs.enum("IntentVersion", {
  V0: null
});
const AppId = import_bcs.bcs.enum("AppId", {
  Sui: null
});
const Intent = import_bcs.bcs.struct("Intent", {
  scope: IntentScope,
  version: IntentVersion,
  appId: AppId
});
function IntentMessage(T) {
  return import_bcs.bcs.struct(`IntentMessage<${T.name}>`, {
    intent: Intent,
    value: T
  });
}
const CompressedSignature = import_bcs.bcs.enum("CompressedSignature", {
  ED25519: import_bcs.bcs.fixedArray(64, import_bcs.bcs.u8()),
  Secp256k1: import_bcs.bcs.fixedArray(64, import_bcs.bcs.u8()),
  Secp256r1: import_bcs.bcs.fixedArray(64, import_bcs.bcs.u8()),
  ZkLogin: import_bcs.bcs.vector(import_bcs.bcs.u8())
});
const PublicKey = import_bcs.bcs.enum("PublicKey", {
  ED25519: import_bcs.bcs.fixedArray(32, import_bcs.bcs.u8()),
  Secp256k1: import_bcs.bcs.fixedArray(33, import_bcs.bcs.u8()),
  Secp256r1: import_bcs.bcs.fixedArray(33, import_bcs.bcs.u8()),
  ZkLogin: import_bcs.bcs.vector(import_bcs.bcs.u8())
});
const MultiSigPkMap = import_bcs.bcs.struct("MultiSigPkMap", {
  pubKey: PublicKey,
  weight: import_bcs.bcs.u8()
});
const MultiSigPublicKey = import_bcs.bcs.struct("MultiSigPublicKey", {
  pk_map: import_bcs.bcs.vector(MultiSigPkMap),
  threshold: import_bcs.bcs.u16()
});
const MultiSig = import_bcs.bcs.struct("MultiSig", {
  sigs: import_bcs.bcs.vector(CompressedSignature),
  bitmap: import_bcs.bcs.u16(),
  multisig_pk: MultiSigPublicKey
});
const base64String = import_bcs.bcs.vector(import_bcs.bcs.u8()).transform({
  input: (val) => typeof val === "string" ? (0, import_bcs.fromBase64)(val) : val,
  output: (val) => (0, import_bcs.toBase64)(new Uint8Array(val))
});
const SenderSignedTransaction = import_bcs.bcs.struct("SenderSignedTransaction", {
  intentMessage: IntentMessage(TransactionData),
  txSignatures: import_bcs.bcs.vector(base64String)
});
const SenderSignedData = import_bcs.bcs.vector(SenderSignedTransaction, {
  name: "SenderSignedData"
});
const PasskeyAuthenticator = import_bcs.bcs.struct("PasskeyAuthenticator", {
  authenticatorData: import_bcs.bcs.vector(import_bcs.bcs.u8()),
  clientDataJson: import_bcs.bcs.string(),
  userSignature: import_bcs.bcs.vector(import_bcs.bcs.u8())
});
//# sourceMappingURL=bcs.js.map


/***/ }),

/***/ 9994:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var effects_exports = {};
__export(effects_exports, {
  TransactionEffects: () => TransactionEffects
});
module.exports = __toCommonJS(effects_exports);
var import_bcs = __nccwpck_require__(8830);
var import_bcs2 = __nccwpck_require__(3388);
const PackageUpgradeError = import_bcs.bcs.enum("PackageUpgradeError", {
  UnableToFetchPackage: import_bcs.bcs.struct("UnableToFetchPackage", { packageId: import_bcs2.Address }),
  NotAPackage: import_bcs.bcs.struct("NotAPackage", { objectId: import_bcs2.Address }),
  IncompatibleUpgrade: null,
  DigestDoesNotMatch: import_bcs.bcs.struct("DigestDoesNotMatch", { digest: import_bcs.bcs.vector(import_bcs.bcs.u8()) }),
  UnknownUpgradePolicy: import_bcs.bcs.struct("UnknownUpgradePolicy", { policy: import_bcs.bcs.u8() }),
  PackageIDDoesNotMatch: import_bcs.bcs.struct("PackageIDDoesNotMatch", {
    packageId: import_bcs2.Address,
    ticketId: import_bcs2.Address
  })
});
const ModuleId = import_bcs.bcs.struct("ModuleId", {
  address: import_bcs2.Address,
  name: import_bcs.bcs.string()
});
const MoveLocation = import_bcs.bcs.struct("MoveLocation", {
  module: ModuleId,
  function: import_bcs.bcs.u16(),
  instruction: import_bcs.bcs.u16(),
  functionName: import_bcs.bcs.option(import_bcs.bcs.string())
});
const CommandArgumentError = import_bcs.bcs.enum("CommandArgumentError", {
  TypeMismatch: null,
  InvalidBCSBytes: null,
  InvalidUsageOfPureArg: null,
  InvalidArgumentToPrivateEntryFunction: null,
  IndexOutOfBounds: import_bcs.bcs.struct("IndexOutOfBounds", { idx: import_bcs.bcs.u16() }),
  SecondaryIndexOutOfBounds: import_bcs.bcs.struct("SecondaryIndexOutOfBounds", {
    resultIdx: import_bcs.bcs.u16(),
    secondaryIdx: import_bcs.bcs.u16()
  }),
  InvalidResultArity: import_bcs.bcs.struct("InvalidResultArity", { resultIdx: import_bcs.bcs.u16() }),
  InvalidGasCoinUsage: null,
  InvalidValueUsage: null,
  InvalidObjectByValue: null,
  InvalidObjectByMutRef: null,
  SharedObjectOperationNotAllowed: null
});
const TypeArgumentError = import_bcs.bcs.enum("TypeArgumentError", {
  TypeNotFound: null,
  ConstraintNotSatisfied: null
});
const ExecutionFailureStatus = import_bcs.bcs.enum("ExecutionFailureStatus", {
  InsufficientGas: null,
  InvalidGasObject: null,
  InvariantViolation: null,
  FeatureNotYetSupported: null,
  MoveObjectTooBig: import_bcs.bcs.struct("MoveObjectTooBig", {
    objectSize: import_bcs.bcs.u64(),
    maxObjectSize: import_bcs.bcs.u64()
  }),
  MovePackageTooBig: import_bcs.bcs.struct("MovePackageTooBig", {
    objectSize: import_bcs.bcs.u64(),
    maxObjectSize: import_bcs.bcs.u64()
  }),
  CircularObjectOwnership: import_bcs.bcs.struct("CircularObjectOwnership", { object: import_bcs2.Address }),
  InsufficientCoinBalance: null,
  CoinBalanceOverflow: null,
  PublishErrorNonZeroAddress: null,
  SuiMoveVerificationError: null,
  MovePrimitiveRuntimeError: import_bcs.bcs.option(MoveLocation),
  MoveAbort: import_bcs.bcs.tuple([MoveLocation, import_bcs.bcs.u64()]),
  VMVerificationOrDeserializationError: null,
  VMInvariantViolation: null,
  FunctionNotFound: null,
  ArityMismatch: null,
  TypeArityMismatch: null,
  NonEntryFunctionInvoked: null,
  CommandArgumentError: import_bcs.bcs.struct("CommandArgumentError", {
    argIdx: import_bcs.bcs.u16(),
    kind: CommandArgumentError
  }),
  TypeArgumentError: import_bcs.bcs.struct("TypeArgumentError", {
    argumentIdx: import_bcs.bcs.u16(),
    kind: TypeArgumentError
  }),
  UnusedValueWithoutDrop: import_bcs.bcs.struct("UnusedValueWithoutDrop", {
    resultIdx: import_bcs.bcs.u16(),
    secondaryIdx: import_bcs.bcs.u16()
  }),
  InvalidPublicFunctionReturnType: import_bcs.bcs.struct("InvalidPublicFunctionReturnType", {
    idx: import_bcs.bcs.u16()
  }),
  InvalidTransferObject: null,
  EffectsTooLarge: import_bcs.bcs.struct("EffectsTooLarge", { currentSize: import_bcs.bcs.u64(), maxSize: import_bcs.bcs.u64() }),
  PublishUpgradeMissingDependency: null,
  PublishUpgradeDependencyDowngrade: null,
  PackageUpgradeError: import_bcs.bcs.struct("PackageUpgradeError", { upgradeError: PackageUpgradeError }),
  WrittenObjectsTooLarge: import_bcs.bcs.struct("WrittenObjectsTooLarge", {
    currentSize: import_bcs.bcs.u64(),
    maxSize: import_bcs.bcs.u64()
  }),
  CertificateDenied: null,
  SuiMoveVerificationTimedout: null,
  SharedObjectOperationNotAllowed: null,
  InputObjectDeleted: null,
  ExecutionCancelledDueToSharedObjectCongestion: import_bcs.bcs.struct(
    "ExecutionCancelledDueToSharedObjectCongestion",
    {
      congestedObjects: import_bcs.bcs.vector(import_bcs2.Address)
    }
  ),
  AddressDeniedForCoin: import_bcs.bcs.struct("AddressDeniedForCoin", {
    address: import_bcs2.Address,
    coinType: import_bcs.bcs.string()
  }),
  CoinTypeGlobalPause: import_bcs.bcs.struct("CoinTypeGlobalPause", { coinType: import_bcs.bcs.string() }),
  ExecutionCancelledDueToRandomnessUnavailable: null
});
const ExecutionStatus = import_bcs.bcs.enum("ExecutionStatus", {
  Success: null,
  Failed: import_bcs.bcs.struct("ExecutionFailed", {
    error: ExecutionFailureStatus,
    command: import_bcs.bcs.option(import_bcs.bcs.u64())
  })
});
const GasCostSummary = import_bcs.bcs.struct("GasCostSummary", {
  computationCost: import_bcs.bcs.u64(),
  storageCost: import_bcs.bcs.u64(),
  storageRebate: import_bcs.bcs.u64(),
  nonRefundableStorageFee: import_bcs.bcs.u64()
});
const TransactionEffectsV1 = import_bcs.bcs.struct("TransactionEffectsV1", {
  status: ExecutionStatus,
  executedEpoch: import_bcs.bcs.u64(),
  gasUsed: GasCostSummary,
  modifiedAtVersions: import_bcs.bcs.vector(import_bcs.bcs.tuple([import_bcs2.Address, import_bcs.bcs.u64()])),
  sharedObjects: import_bcs.bcs.vector(import_bcs2.SuiObjectRef),
  transactionDigest: import_bcs2.ObjectDigest,
  created: import_bcs.bcs.vector(import_bcs.bcs.tuple([import_bcs2.SuiObjectRef, import_bcs2.Owner])),
  mutated: import_bcs.bcs.vector(import_bcs.bcs.tuple([import_bcs2.SuiObjectRef, import_bcs2.Owner])),
  unwrapped: import_bcs.bcs.vector(import_bcs.bcs.tuple([import_bcs2.SuiObjectRef, import_bcs2.Owner])),
  deleted: import_bcs.bcs.vector(import_bcs2.SuiObjectRef),
  unwrappedThenDeleted: import_bcs.bcs.vector(import_bcs2.SuiObjectRef),
  wrapped: import_bcs.bcs.vector(import_bcs2.SuiObjectRef),
  gasObject: import_bcs.bcs.tuple([import_bcs2.SuiObjectRef, import_bcs2.Owner]),
  eventsDigest: import_bcs.bcs.option(import_bcs2.ObjectDigest),
  dependencies: import_bcs.bcs.vector(import_bcs2.ObjectDigest)
});
const VersionDigest = import_bcs.bcs.tuple([import_bcs.bcs.u64(), import_bcs2.ObjectDigest]);
const ObjectIn = import_bcs.bcs.enum("ObjectIn", {
  NotExist: null,
  Exist: import_bcs.bcs.tuple([VersionDigest, import_bcs2.Owner])
});
const ObjectOut = import_bcs.bcs.enum("ObjectOut", {
  NotExist: null,
  ObjectWrite: import_bcs.bcs.tuple([import_bcs2.ObjectDigest, import_bcs2.Owner]),
  PackageWrite: VersionDigest
});
const IDOperation = import_bcs.bcs.enum("IDOperation", {
  None: null,
  Created: null,
  Deleted: null
});
const EffectsObjectChange = import_bcs.bcs.struct("EffectsObjectChange", {
  inputState: ObjectIn,
  outputState: ObjectOut,
  idOperation: IDOperation
});
const UnchangedSharedKind = import_bcs.bcs.enum("UnchangedSharedKind", {
  ReadOnlyRoot: VersionDigest,
  MutateDeleted: import_bcs.bcs.u64(),
  ReadDeleted: import_bcs.bcs.u64(),
  Cancelled: import_bcs.bcs.u64(),
  PerEpochConfig: null
});
const TransactionEffectsV2 = import_bcs.bcs.struct("TransactionEffectsV2", {
  status: ExecutionStatus,
  executedEpoch: import_bcs.bcs.u64(),
  gasUsed: GasCostSummary,
  transactionDigest: import_bcs2.ObjectDigest,
  gasObjectIndex: import_bcs.bcs.option(import_bcs.bcs.u32()),
  eventsDigest: import_bcs.bcs.option(import_bcs2.ObjectDigest),
  dependencies: import_bcs.bcs.vector(import_bcs2.ObjectDigest),
  lamportVersion: import_bcs.bcs.u64(),
  changedObjects: import_bcs.bcs.vector(import_bcs.bcs.tuple([import_bcs2.Address, EffectsObjectChange])),
  unchangedSharedObjects: import_bcs.bcs.vector(import_bcs.bcs.tuple([import_bcs2.Address, UnchangedSharedKind])),
  auxDataDigest: import_bcs.bcs.option(import_bcs2.ObjectDigest)
});
const TransactionEffects = import_bcs.bcs.enum("TransactionEffects", {
  V1: TransactionEffectsV1,
  V2: TransactionEffectsV2
});
//# sourceMappingURL=effects.js.map


/***/ }),

/***/ 6244:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var bcs_exports = {};
__export(bcs_exports, {
  BcsType: () => import_bcs3.BcsType,
  TypeTagSerializer: () => import_type_tag_serializer.TypeTagSerializer,
  bcs: () => suiBcs,
  pureBcsSchemaFromTypeName: () => import_pure.pureBcsSchemaFromTypeName
});
module.exports = __toCommonJS(bcs_exports);
var import_bcs = __nccwpck_require__(8830);
var import_bcs2 = __nccwpck_require__(3388);
var import_effects = __nccwpck_require__(9994);
var import_type_tag_serializer = __nccwpck_require__(1020);
var import_bcs3 = __nccwpck_require__(8830);
var import_pure = __nccwpck_require__(5388);
const suiBcs = {
  ...import_bcs.bcs,
  U8: import_bcs.bcs.u8(),
  U16: import_bcs.bcs.u16(),
  U32: import_bcs.bcs.u32(),
  U64: import_bcs.bcs.u64(),
  U128: import_bcs.bcs.u128(),
  U256: import_bcs.bcs.u256(),
  ULEB128: import_bcs.bcs.uleb128(),
  Bool: import_bcs.bcs.bool(),
  String: import_bcs.bcs.string(),
  Address: import_bcs2.Address,
  AppId: import_bcs2.AppId,
  Argument: import_bcs2.Argument,
  CallArg: import_bcs2.CallArg,
  Command: import_bcs2.Command,
  CompressedSignature: import_bcs2.CompressedSignature,
  GasData: import_bcs2.GasData,
  Intent: import_bcs2.Intent,
  IntentMessage: import_bcs2.IntentMessage,
  IntentScope: import_bcs2.IntentScope,
  IntentVersion: import_bcs2.IntentVersion,
  MultiSig: import_bcs2.MultiSig,
  MultiSigPkMap: import_bcs2.MultiSigPkMap,
  MultiSigPublicKey: import_bcs2.MultiSigPublicKey,
  ObjectArg: import_bcs2.ObjectArg,
  ObjectDigest: import_bcs2.ObjectDigest,
  Owner: import_bcs2.Owner,
  PasskeyAuthenticator: import_bcs2.PasskeyAuthenticator,
  ProgrammableMoveCall: import_bcs2.ProgrammableMoveCall,
  ProgrammableTransaction: import_bcs2.ProgrammableTransaction,
  PublicKey: import_bcs2.PublicKey,
  SenderSignedData: import_bcs2.SenderSignedData,
  SenderSignedTransaction: import_bcs2.SenderSignedTransaction,
  SharedObjectRef: import_bcs2.SharedObjectRef,
  StructTag: import_bcs2.StructTag,
  SuiObjectRef: import_bcs2.SuiObjectRef,
  TransactionData: import_bcs2.TransactionData,
  TransactionDataV1: import_bcs2.TransactionDataV1,
  TransactionEffects: import_effects.TransactionEffects,
  TransactionExpiration: import_bcs2.TransactionExpiration,
  TransactionKind: import_bcs2.TransactionKind,
  TypeTag: import_bcs2.TypeTag
};
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 5388:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var pure_exports = {};
__export(pure_exports, {
  pureBcsSchemaFromTypeName: () => pureBcsSchemaFromTypeName
});
module.exports = __toCommonJS(pure_exports);
var import_bcs = __nccwpck_require__(8830);
var import_bcs2 = __nccwpck_require__(3388);
function pureBcsSchemaFromTypeName(name) {
  switch (name) {
    case "u8":
      return import_bcs.bcs.u8();
    case "u16":
      return import_bcs.bcs.u16();
    case "u32":
      return import_bcs.bcs.u32();
    case "u64":
      return import_bcs.bcs.u64();
    case "u128":
      return import_bcs.bcs.u128();
    case "u256":
      return import_bcs.bcs.u256();
    case "bool":
      return import_bcs.bcs.bool();
    case "string":
      return import_bcs.bcs.string();
    case "id":
    case "address":
      return import_bcs2.Address;
  }
  const generic = name.match(/^(vector|option)<(.+)>$/);
  if (generic) {
    const [kind, inner] = generic.slice(1);
    if (kind === "vector") {
      return import_bcs.bcs.vector(pureBcsSchemaFromTypeName(inner));
    } else {
      return import_bcs.bcs.option(pureBcsSchemaFromTypeName(inner));
    }
  }
  throw new Error(`Invalid Pure type name: ${name}`);
}
//# sourceMappingURL=pure.js.map


/***/ }),

/***/ 1020:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var type_tag_serializer_exports = {};
__export(type_tag_serializer_exports, {
  TypeTagSerializer: () => TypeTagSerializer
});
module.exports = __toCommonJS(type_tag_serializer_exports);
var import_bcs = __nccwpck_require__(8830);
var import_sui_types = __nccwpck_require__(4818);
const VECTOR_REGEX = /^vector<(.+)>$/;
const STRUCT_REGEX = /^([^:]+)::([^:]+)::([^<]+)(<(.+)>)?/;
class TypeTagSerializer {
  static parseFromStr(str, normalizeAddress = false) {
    if (str === "address") {
      return { address: null };
    } else if (str === "bool") {
      return { bool: null };
    } else if (str === "u8") {
      return { u8: null };
    } else if (str === "u16") {
      return { u16: null };
    } else if (str === "u32") {
      return { u32: null };
    } else if (str === "u64") {
      return { u64: null };
    } else if (str === "u128") {
      return { u128: null };
    } else if (str === "u256") {
      return { u256: null };
    } else if (str === "signer") {
      return { signer: null };
    }
    const vectorMatch = str.match(VECTOR_REGEX);
    if (vectorMatch) {
      return {
        vector: TypeTagSerializer.parseFromStr(vectorMatch[1], normalizeAddress)
      };
    }
    const structMatch = str.match(STRUCT_REGEX);
    if (structMatch) {
      const address = normalizeAddress ? (0, import_sui_types.normalizeSuiAddress)(structMatch[1]) : structMatch[1];
      return {
        struct: {
          address,
          module: structMatch[2],
          name: structMatch[3],
          typeParams: structMatch[5] === void 0 ? [] : TypeTagSerializer.parseStructTypeArgs(structMatch[5], normalizeAddress)
        }
      };
    }
    throw new Error(`Encountered unexpected token when parsing type args for ${str}`);
  }
  static parseStructTypeArgs(str, normalizeAddress = false) {
    return (0, import_bcs.splitGenericParameters)(str).map(
      (tok) => TypeTagSerializer.parseFromStr(tok, normalizeAddress)
    );
  }
  static tagToString(tag) {
    if ("bool" in tag) {
      return "bool";
    }
    if ("u8" in tag) {
      return "u8";
    }
    if ("u16" in tag) {
      return "u16";
    }
    if ("u32" in tag) {
      return "u32";
    }
    if ("u64" in tag) {
      return "u64";
    }
    if ("u128" in tag) {
      return "u128";
    }
    if ("u256" in tag) {
      return "u256";
    }
    if ("address" in tag) {
      return "address";
    }
    if ("signer" in tag) {
      return "signer";
    }
    if ("vector" in tag) {
      return `vector<${TypeTagSerializer.tagToString(tag.vector)}>`;
    }
    if ("struct" in tag) {
      const struct = tag.struct;
      const typeParams = struct.typeParams.map(TypeTagSerializer.tagToString).join(", ");
      return `${struct.address}::${struct.module}::${struct.name}${typeParams ? `<${typeParams}>` : ""}`;
    }
    throw new Error("Invalid TypeTag");
  }
}
//# sourceMappingURL=type-tag-serializer.js.map


/***/ }),

/***/ 4052:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var client_exports = {};
__export(client_exports, {
  SuiClient: () => SuiClient,
  isSuiClient: () => isSuiClient
});
module.exports = __toCommonJS(client_exports);
var import_bcs = __nccwpck_require__(8830);
var import_client = __nccwpck_require__(1795);
var import_jsonRPC = __nccwpck_require__(7420);
var import_transactions = __nccwpck_require__(9417);
var import_sui_types = __nccwpck_require__(4818);
var import_suins = __nccwpck_require__(8593);
var import_http_transport = __nccwpck_require__(2027);
const SUI_CLIENT_BRAND = Symbol.for("@mysten/SuiClient");
function isSuiClient(client) {
  return typeof client === "object" && client !== null && client[SUI_CLIENT_BRAND] === true;
}
class SuiClient extends import_client.Experimental_BaseClient {
  /**
   * Establish a connection to a Sui RPC endpoint
   *
   * @param options configuration options for the API Client
   */
  constructor(options) {
    super({ network: options.network ?? "unknown" });
    this.core = new import_jsonRPC.JSONRpcTransport(this);
    this.jsonRpc = this;
    this.transport = options.transport ?? new import_http_transport.SuiHTTPTransport({ url: options.url });
  }
  get [SUI_CLIENT_BRAND]() {
    return true;
  }
  async getRpcApiVersion({ signal } = {}) {
    const resp = await this.transport.request({
      method: "rpc.discover",
      params: [],
      signal
    });
    return resp.info.version;
  }
  /**
   * Get all Coin<`coin_type`> objects owned by an address.
   */
  async getCoins(input) {
    if (!input.owner || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(input.owner))) {
      throw new Error("Invalid Sui address");
    }
    return await this.transport.request({
      method: "suix_getCoins",
      params: [input.owner, input.coinType, input.cursor, input.limit],
      signal: input.signal
    });
  }
  /**
   * Get all Coin objects owned by an address.
   */
  async getAllCoins(input) {
    if (!input.owner || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(input.owner))) {
      throw new Error("Invalid Sui address");
    }
    return await this.transport.request({
      method: "suix_getAllCoins",
      params: [input.owner, input.cursor, input.limit],
      signal: input.signal
    });
  }
  /**
   * Get the total coin balance for one coin type, owned by the address owner.
   */
  async getBalance(input) {
    if (!input.owner || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(input.owner))) {
      throw new Error("Invalid Sui address");
    }
    return await this.transport.request({
      method: "suix_getBalance",
      params: [input.owner, input.coinType],
      signal: input.signal
    });
  }
  /**
   * Get the total coin balance for all coin types, owned by the address owner.
   */
  async getAllBalances(input) {
    if (!input.owner || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(input.owner))) {
      throw new Error("Invalid Sui address");
    }
    return await this.transport.request({
      method: "suix_getAllBalances",
      params: [input.owner],
      signal: input.signal
    });
  }
  /**
   * Fetch CoinMetadata for a given coin type
   */
  async getCoinMetadata(input) {
    return await this.transport.request({
      method: "suix_getCoinMetadata",
      params: [input.coinType],
      signal: input.signal
    });
  }
  /**
   *  Fetch total supply for a coin
   */
  async getTotalSupply(input) {
    return await this.transport.request({
      method: "suix_getTotalSupply",
      params: [input.coinType],
      signal: input.signal
    });
  }
  /**
   * Invoke any RPC method
   * @param method the method to be invoked
   * @param args the arguments to be passed to the RPC request
   */
  async call(method, params, { signal } = {}) {
    return await this.transport.request({ method, params, signal });
  }
  /**
   * Get Move function argument types like read, write and full access
   */
  async getMoveFunctionArgTypes(input) {
    return await this.transport.request({
      method: "sui_getMoveFunctionArgTypes",
      params: [input.package, input.module, input.function],
      signal: input.signal
    });
  }
  /**
   * Get a map from module name to
   * structured representations of Move modules
   */
  async getNormalizedMoveModulesByPackage(input) {
    return await this.transport.request({
      method: "sui_getNormalizedMoveModulesByPackage",
      params: [input.package],
      signal: input.signal
    });
  }
  /**
   * Get a structured representation of Move module
   */
  async getNormalizedMoveModule(input) {
    return await this.transport.request({
      method: "sui_getNormalizedMoveModule",
      params: [input.package, input.module],
      signal: input.signal
    });
  }
  /**
   * Get a structured representation of Move function
   */
  async getNormalizedMoveFunction(input) {
    return await this.transport.request({
      method: "sui_getNormalizedMoveFunction",
      params: [input.package, input.module, input.function],
      signal: input.signal
    });
  }
  /**
   * Get a structured representation of Move struct
   */
  async getNormalizedMoveStruct(input) {
    return await this.transport.request({
      method: "sui_getNormalizedMoveStruct",
      params: [input.package, input.module, input.struct],
      signal: input.signal
    });
  }
  /**
   * Get all objects owned by an address
   */
  async getOwnedObjects(input) {
    if (!input.owner || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(input.owner))) {
      throw new Error("Invalid Sui address");
    }
    return await this.transport.request({
      method: "suix_getOwnedObjects",
      params: [
        input.owner,
        {
          filter: input.filter,
          options: input.options
        },
        input.cursor,
        input.limit
      ],
      signal: input.signal
    });
  }
  /**
   * Get details about an object
   */
  async getObject(input) {
    if (!input.id || !(0, import_sui_types.isValidSuiObjectId)((0, import_sui_types.normalizeSuiObjectId)(input.id))) {
      throw new Error("Invalid Sui Object id");
    }
    return await this.transport.request({
      method: "sui_getObject",
      params: [input.id, input.options],
      signal: input.signal
    });
  }
  async tryGetPastObject(input) {
    return await this.transport.request({
      method: "sui_tryGetPastObject",
      params: [input.id, input.version, input.options],
      signal: input.signal
    });
  }
  /**
   * Batch get details about a list of objects. If any of the object ids are duplicates the call will fail
   */
  async multiGetObjects(input) {
    input.ids.forEach((id) => {
      if (!id || !(0, import_sui_types.isValidSuiObjectId)((0, import_sui_types.normalizeSuiObjectId)(id))) {
        throw new Error(`Invalid Sui Object id ${id}`);
      }
    });
    const hasDuplicates = input.ids.length !== new Set(input.ids).size;
    if (hasDuplicates) {
      throw new Error(`Duplicate object ids in batch call ${input.ids}`);
    }
    return await this.transport.request({
      method: "sui_multiGetObjects",
      params: [input.ids, input.options],
      signal: input.signal
    });
  }
  /**
   * Get transaction blocks for a given query criteria
   */
  async queryTransactionBlocks(input) {
    return await this.transport.request({
      method: "suix_queryTransactionBlocks",
      params: [
        {
          filter: input.filter,
          options: input.options
        },
        input.cursor,
        input.limit,
        (input.order || "descending") === "descending"
      ],
      signal: input.signal
    });
  }
  async getTransactionBlock(input) {
    if (!(0, import_sui_types.isValidTransactionDigest)(input.digest)) {
      throw new Error("Invalid Transaction digest");
    }
    return await this.transport.request({
      method: "sui_getTransactionBlock",
      params: [input.digest, input.options],
      signal: input.signal
    });
  }
  async multiGetTransactionBlocks(input) {
    input.digests.forEach((d) => {
      if (!(0, import_sui_types.isValidTransactionDigest)(d)) {
        throw new Error(`Invalid Transaction digest ${d}`);
      }
    });
    const hasDuplicates = input.digests.length !== new Set(input.digests).size;
    if (hasDuplicates) {
      throw new Error(`Duplicate digests in batch call ${input.digests}`);
    }
    return await this.transport.request({
      method: "sui_multiGetTransactionBlocks",
      params: [input.digests, input.options],
      signal: input.signal
    });
  }
  async executeTransactionBlock({
    transactionBlock,
    signature,
    options,
    requestType,
    signal
  }) {
    const result = await this.transport.request({
      method: "sui_executeTransactionBlock",
      params: [
        typeof transactionBlock === "string" ? transactionBlock : (0, import_bcs.toBase64)(transactionBlock),
        Array.isArray(signature) ? signature : [signature],
        options
      ],
      signal
    });
    if (requestType === "WaitForLocalExecution") {
      try {
        await this.waitForTransaction({
          digest: result.digest
        });
      } catch (_) {
      }
    }
    return result;
  }
  async signAndExecuteTransaction({
    transaction,
    signer,
    ...input
  }) {
    let transactionBytes;
    if (transaction instanceof Uint8Array) {
      transactionBytes = transaction;
    } else {
      transaction.setSenderIfNotSet(signer.toSuiAddress());
      transactionBytes = await transaction.build({ client: this });
    }
    const { signature, bytes } = await signer.signTransaction(transactionBytes);
    return this.executeTransactionBlock({
      transactionBlock: bytes,
      signature,
      ...input
    });
  }
  /**
   * Get total number of transactions
   */
  async getTotalTransactionBlocks({ signal } = {}) {
    const resp = await this.transport.request({
      method: "sui_getTotalTransactionBlocks",
      params: [],
      signal
    });
    return BigInt(resp);
  }
  /**
   * Getting the reference gas price for the network
   */
  async getReferenceGasPrice({ signal } = {}) {
    const resp = await this.transport.request({
      method: "suix_getReferenceGasPrice",
      params: [],
      signal
    });
    return BigInt(resp);
  }
  /**
   * Return the delegated stakes for an address
   */
  async getStakes(input) {
    if (!input.owner || !(0, import_sui_types.isValidSuiAddress)((0, import_sui_types.normalizeSuiAddress)(input.owner))) {
      throw new Error("Invalid Sui address");
    }
    return await this.transport.request({
      method: "suix_getStakes",
      params: [input.owner],
      signal: input.signal
    });
  }
  /**
   * Return the delegated stakes queried by id.
   */
  async getStakesByIds(input) {
    input.stakedSuiIds.forEach((id) => {
      if (!id || !(0, import_sui_types.isValidSuiObjectId)((0, import_sui_types.normalizeSuiObjectId)(id))) {
        throw new Error(`Invalid Sui Stake id ${id}`);
      }
    });
    return await this.transport.request({
      method: "suix_getStakesByIds",
      params: [input.stakedSuiIds],
      signal: input.signal
    });
  }
  /**
   * Return the latest system state content.
   */
  async getLatestSuiSystemState({
    signal
  } = {}) {
    return await this.transport.request({
      method: "suix_getLatestSuiSystemState",
      params: [],
      signal
    });
  }
  /**
   * Get events for a given query criteria
   */
  async queryEvents(input) {
    return await this.transport.request({
      method: "suix_queryEvents",
      params: [
        input.query,
        input.cursor,
        input.limit,
        (input.order || "descending") === "descending"
      ],
      signal: input.signal
    });
  }
  /**
   * Subscribe to get notifications whenever an event matching the filter occurs
   *
   * @deprecated
   */
  async subscribeEvent(input) {
    return this.transport.subscribe({
      method: "suix_subscribeEvent",
      unsubscribe: "suix_unsubscribeEvent",
      params: [input.filter],
      onMessage: input.onMessage,
      signal: input.signal
    });
  }
  /**
   * @deprecated
   */
  async subscribeTransaction(input) {
    return this.transport.subscribe({
      method: "suix_subscribeTransaction",
      unsubscribe: "suix_unsubscribeTransaction",
      params: [input.filter],
      onMessage: input.onMessage,
      signal: input.signal
    });
  }
  /**
   * Runs the transaction block in dev-inspect mode. Which allows for nearly any
   * transaction (or Move call) with any arguments. Detailed results are
   * provided, including both the transaction effects and any return values.
   */
  async devInspectTransactionBlock(input) {
    let devInspectTxBytes;
    if ((0, import_transactions.isTransaction)(input.transactionBlock)) {
      input.transactionBlock.setSenderIfNotSet(input.sender);
      devInspectTxBytes = (0, import_bcs.toBase64)(
        await input.transactionBlock.build({
          client: this,
          onlyTransactionKind: true
        })
      );
    } else if (typeof input.transactionBlock === "string") {
      devInspectTxBytes = input.transactionBlock;
    } else if (input.transactionBlock instanceof Uint8Array) {
      devInspectTxBytes = (0, import_bcs.toBase64)(input.transactionBlock);
    } else {
      throw new Error("Unknown transaction block format.");
    }
    input.signal?.throwIfAborted();
    return await this.transport.request({
      method: "sui_devInspectTransactionBlock",
      params: [input.sender, devInspectTxBytes, input.gasPrice?.toString(), input.epoch],
      signal: input.signal
    });
  }
  /**
   * Dry run a transaction block and return the result.
   */
  async dryRunTransactionBlock(input) {
    return await this.transport.request({
      method: "sui_dryRunTransactionBlock",
      params: [
        typeof input.transactionBlock === "string" ? input.transactionBlock : (0, import_bcs.toBase64)(input.transactionBlock)
      ]
    });
  }
  /**
   * Return the list of dynamic field objects owned by an object
   */
  async getDynamicFields(input) {
    if (!input.parentId || !(0, import_sui_types.isValidSuiObjectId)((0, import_sui_types.normalizeSuiObjectId)(input.parentId))) {
      throw new Error("Invalid Sui Object id");
    }
    return await this.transport.request({
      method: "suix_getDynamicFields",
      params: [input.parentId, input.cursor, input.limit],
      signal: input.signal
    });
  }
  /**
   * Return the dynamic field object information for a specified object
   */
  async getDynamicFieldObject(input) {
    return await this.transport.request({
      method: "suix_getDynamicFieldObject",
      params: [input.parentId, input.name],
      signal: input.signal
    });
  }
  /**
   * Get the sequence number of the latest checkpoint that has been executed
   */
  async getLatestCheckpointSequenceNumber({
    signal
  } = {}) {
    const resp = await this.transport.request({
      method: "sui_getLatestCheckpointSequenceNumber",
      params: [],
      signal
    });
    return String(resp);
  }
  /**
   * Returns information about a given checkpoint
   */
  async getCheckpoint(input) {
    return await this.transport.request({
      method: "sui_getCheckpoint",
      params: [input.id],
      signal: input.signal
    });
  }
  /**
   * Returns historical checkpoints paginated
   */
  async getCheckpoints(input) {
    return await this.transport.request({
      method: "sui_getCheckpoints",
      params: [input.cursor, input?.limit, input.descendingOrder],
      signal: input.signal
    });
  }
  /**
   * Return the committee information for the asked epoch
   */
  async getCommitteeInfo(input) {
    return await this.transport.request({
      method: "suix_getCommitteeInfo",
      params: [input?.epoch],
      signal: input?.signal
    });
  }
  async getNetworkMetrics({ signal } = {}) {
    return await this.transport.request({
      method: "suix_getNetworkMetrics",
      params: [],
      signal
    });
  }
  async getAddressMetrics({ signal } = {}) {
    return await this.transport.request({
      method: "suix_getLatestAddressMetrics",
      params: [],
      signal
    });
  }
  async getEpochMetrics(input) {
    return await this.transport.request({
      method: "suix_getEpochMetrics",
      params: [input?.cursor, input?.limit, input?.descendingOrder],
      signal: input?.signal
    });
  }
  async getAllEpochAddressMetrics(input) {
    return await this.transport.request({
      method: "suix_getAllEpochAddressMetrics",
      params: [input?.descendingOrder],
      signal: input?.signal
    });
  }
  /**
   * Return the committee information for the asked epoch
   */
  async getEpochs(input) {
    return await this.transport.request({
      method: "suix_getEpochs",
      params: [input?.cursor, input?.limit, input?.descendingOrder],
      signal: input?.signal
    });
  }
  /**
   * Returns list of top move calls by usage
   */
  async getMoveCallMetrics({ signal } = {}) {
    return await this.transport.request({
      method: "suix_getMoveCallMetrics",
      params: [],
      signal
    });
  }
  /**
   * Return the committee information for the asked epoch
   */
  async getCurrentEpoch({ signal } = {}) {
    return await this.transport.request({
      method: "suix_getCurrentEpoch",
      params: [],
      signal
    });
  }
  /**
   * Return the Validators APYs
   */
  async getValidatorsApy({ signal } = {}) {
    return await this.transport.request({
      method: "suix_getValidatorsApy",
      params: [],
      signal
    });
  }
  // TODO: Migrate this to `sui_getChainIdentifier` once it is widely available.
  async getChainIdentifier({ signal } = {}) {
    const checkpoint = await this.getCheckpoint({ id: "0", signal });
    const bytes = (0, import_bcs.fromBase58)(checkpoint.digest);
    return (0, import_bcs.toHex)(bytes.slice(0, 4));
  }
  async resolveNameServiceAddress(input) {
    return await this.transport.request({
      method: "suix_resolveNameServiceAddress",
      params: [input.name],
      signal: input.signal
    });
  }
  async resolveNameServiceNames({
    format = "dot",
    ...input
  }) {
    const { nextCursor, hasNextPage, data } = await this.transport.request({
      method: "suix_resolveNameServiceNames",
      params: [input.address, input.cursor, input.limit],
      signal: input.signal
    });
    return {
      hasNextPage,
      nextCursor,
      data: data.map((name) => (0, import_suins.normalizeSuiNSName)(name, format))
    };
  }
  async getProtocolConfig(input) {
    return await this.transport.request({
      method: "sui_getProtocolConfig",
      params: [input?.version],
      signal: input?.signal
    });
  }
  async verifyZkLoginSignature(input) {
    return await this.transport.request({
      method: "sui_verifyZkLoginSignature",
      params: [input.bytes, input.signature, input.intentScope, input.author],
      signal: input.signal
    });
  }
  /**
   * Wait for a transaction block result to be available over the API.
   * This can be used in conjunction with `executeTransactionBlock` to wait for the transaction to
   * be available via the API.
   * This currently polls the `getTransactionBlock` API to check for the transaction.
   */
  async waitForTransaction({
    signal,
    timeout = 60 * 1e3,
    pollInterval = 2 * 1e3,
    ...input
  }) {
    const timeoutSignal = AbortSignal.timeout(timeout);
    const timeoutPromise = new Promise((_, reject) => {
      timeoutSignal.addEventListener("abort", () => reject(timeoutSignal.reason));
    });
    timeoutPromise.catch(() => {
    });
    while (!timeoutSignal.aborted) {
      signal?.throwIfAborted();
      try {
        return await this.getTransactionBlock(input);
      } catch (e) {
        await Promise.race([
          new Promise((resolve) => setTimeout(resolve, pollInterval)),
          timeoutPromise
        ]);
      }
    }
    timeoutSignal.throwIfAborted();
    throw new Error("Unexpected error while waiting for transaction block.");
  }
  experimental_asClientExtension() {
    return {
      name: "jsonRPC",
      register: () => {
        return this;
      }
    };
  }
}
//# sourceMappingURL=client.js.map


/***/ }),

/***/ 2052:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var errors_exports = {};
__export(errors_exports, {
  JsonRpcError: () => JsonRpcError,
  SuiHTTPStatusError: () => SuiHTTPStatusError,
  SuiHTTPTransportError: () => SuiHTTPTransportError
});
module.exports = __toCommonJS(errors_exports);
const CODE_TO_ERROR_TYPE = {
  "-32700": "ParseError",
  "-32701": "OversizedRequest",
  "-32702": "OversizedResponse",
  "-32600": "InvalidRequest",
  "-32601": "MethodNotFound",
  "-32602": "InvalidParams",
  "-32603": "InternalError",
  "-32604": "ServerBusy",
  "-32000": "CallExecutionFailed",
  "-32001": "UnknownError",
  "-32003": "SubscriptionClosed",
  "-32004": "SubscriptionClosedWithError",
  "-32005": "BatchesNotSupported",
  "-32006": "TooManySubscriptions",
  "-32050": "TransientError",
  "-32002": "TransactionExecutionClientError"
};
class SuiHTTPTransportError extends Error {
}
class JsonRpcError extends SuiHTTPTransportError {
  constructor(message, code) {
    super(message);
    this.code = code;
    this.type = CODE_TO_ERROR_TYPE[code] ?? "ServerError";
  }
}
class SuiHTTPStatusError extends SuiHTTPTransportError {
  constructor(message, status, statusText) {
    super(message);
    this.status = status;
    this.statusText = statusText;
  }
}
//# sourceMappingURL=errors.js.map


/***/ }),

/***/ 2027:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
var http_transport_exports = {};
__export(http_transport_exports, {
  SuiHTTPTransport: () => SuiHTTPTransport
});
module.exports = __toCommonJS(http_transport_exports);
var import_version = __nccwpck_require__(4531);
var import_errors = __nccwpck_require__(2052);
var import_rpc_websocket_client = __nccwpck_require__(5164);
var _requestId, _options, _websocketClient, _SuiHTTPTransport_instances, getWebsocketClient_fn;
class SuiHTTPTransport {
  constructor(options) {
    __privateAdd(this, _SuiHTTPTransport_instances);
    __privateAdd(this, _requestId, 0);
    __privateAdd(this, _options);
    __privateAdd(this, _websocketClient);
    __privateSet(this, _options, options);
  }
  fetch(input, init) {
    const fetchFn = __privateGet(this, _options).fetch ?? fetch;
    if (!fetchFn) {
      throw new Error(
        "The current environment does not support fetch, you can provide a fetch implementation in the options for SuiHTTPTransport."
      );
    }
    return fetchFn(input, init);
  }
  async request(input) {
    __privateSet(this, _requestId, __privateGet(this, _requestId) + 1);
    const res = await this.fetch(__privateGet(this, _options).rpc?.url ?? __privateGet(this, _options).url, {
      method: "POST",
      signal: input.signal,
      headers: {
        "Content-Type": "application/json",
        "Client-Sdk-Type": "typescript",
        "Client-Sdk-Version": import_version.PACKAGE_VERSION,
        "Client-Target-Api-Version": import_version.TARGETED_RPC_VERSION,
        "Client-Request-Method": input.method,
        ...__privateGet(this, _options).rpc?.headers
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: __privateGet(this, _requestId),
        method: input.method,
        params: input.params
      })
    });
    if (!res.ok) {
      throw new import_errors.SuiHTTPStatusError(
        `Unexpected status code: ${res.status}`,
        res.status,
        res.statusText
      );
    }
    const data = await res.json();
    if ("error" in data && data.error != null) {
      throw new import_errors.JsonRpcError(data.error.message, data.error.code);
    }
    return data.result;
  }
  async subscribe(input) {
    const unsubscribe = await __privateMethod(this, _SuiHTTPTransport_instances, getWebsocketClient_fn).call(this).subscribe(input);
    if (input.signal) {
      input.signal.throwIfAborted();
      input.signal.addEventListener("abort", () => {
        unsubscribe();
      });
    }
    return async () => !!await unsubscribe();
  }
}
_requestId = new WeakMap();
_options = new WeakMap();
_websocketClient = new WeakMap();
_SuiHTTPTransport_instances = new WeakSet();
getWebsocketClient_fn = function() {
  if (!__privateGet(this, _websocketClient)) {
    const WebSocketConstructor = __privateGet(this, _options).WebSocketConstructor ?? WebSocket;
    if (!WebSocketConstructor) {
      throw new Error(
        "The current environment does not support WebSocket, you can provide a WebSocketConstructor in the options for SuiHTTPTransport."
      );
    }
    __privateSet(this, _websocketClient, new import_rpc_websocket_client.WebsocketClient(
      __privateGet(this, _options).websocket?.url ?? __privateGet(this, _options).url,
      {
        WebSocketConstructor,
        ...__privateGet(this, _options).websocket
      }
    ));
  }
  return __privateGet(this, _websocketClient);
};
//# sourceMappingURL=http-transport.js.map


/***/ }),

/***/ 827:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var client_exports = {};
__export(client_exports, {
  JsonRpcError: () => import_errors.JsonRpcError,
  SuiClient: () => import_client.SuiClient,
  SuiHTTPStatusError: () => import_errors.SuiHTTPStatusError,
  SuiHTTPTransport: () => import_http_transport.SuiHTTPTransport,
  SuiHTTPTransportError: () => import_errors.SuiHTTPTransportError,
  getFullnodeUrl: () => import_network.getFullnodeUrl,
  isSuiClient: () => import_client.isSuiClient
});
module.exports = __toCommonJS(client_exports);
var import_http_transport = __nccwpck_require__(2027);
var import_network = __nccwpck_require__(9001);
__reExport(client_exports, __nccwpck_require__(6473), module.exports);
var import_client = __nccwpck_require__(4052);
var import_errors = __nccwpck_require__(2052);
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 9001:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var network_exports = {};
__export(network_exports, {
  getFullnodeUrl: () => getFullnodeUrl
});
module.exports = __toCommonJS(network_exports);
function getFullnodeUrl(network) {
  switch (network) {
    case "mainnet":
      return "https://fullnode.mainnet.sui.io:443";
    case "testnet":
      return "https://fullnode.testnet.sui.io:443";
    case "devnet":
      return "https://fullnode.devnet.sui.io:443";
    case "localnet":
      return "http://127.0.0.1:9000";
    default:
      throw new Error(`Unknown network: ${network}`);
  }
}
//# sourceMappingURL=network.js.map


/***/ }),

/***/ 5164:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
var __privateWrapper = (obj, member, setter, getter) => ({
  set _(value) {
    __privateSet(obj, member, value, setter);
  },
  get _() {
    return __privateGet(obj, member, getter);
  }
});
var rpc_websocket_client_exports = {};
__export(rpc_websocket_client_exports, {
  DEFAULT_CLIENT_OPTIONS: () => DEFAULT_CLIENT_OPTIONS,
  WebsocketClient: () => WebsocketClient
});
module.exports = __toCommonJS(rpc_websocket_client_exports);
var import_errors = __nccwpck_require__(2052);
var _requestId, _disconnects, _webSocket, _connectionPromise, _subscriptions, _pendingRequests, _WebsocketClient_instances, setupWebSocket_fn, reconnect_fn;
function getWebsocketUrl(httpUrl) {
  const url = new URL(httpUrl);
  url.protocol = url.protocol.replace("http", "ws");
  return url.toString();
}
const DEFAULT_CLIENT_OPTIONS = {
  // We fudge the typing because we also check for undefined in the constructor:
  WebSocketConstructor: typeof WebSocket !== "undefined" ? WebSocket : void 0,
  callTimeout: 3e4,
  reconnectTimeout: 3e3,
  maxReconnects: 5
};
class WebsocketClient {
  constructor(endpoint, options = {}) {
    __privateAdd(this, _WebsocketClient_instances);
    __privateAdd(this, _requestId, 0);
    __privateAdd(this, _disconnects, 0);
    __privateAdd(this, _webSocket, null);
    __privateAdd(this, _connectionPromise, null);
    __privateAdd(this, _subscriptions, /* @__PURE__ */ new Set());
    __privateAdd(this, _pendingRequests, /* @__PURE__ */ new Map());
    this.endpoint = endpoint;
    this.options = { ...DEFAULT_CLIENT_OPTIONS, ...options };
    if (!this.options.WebSocketConstructor) {
      throw new Error("Missing WebSocket constructor");
    }
    if (this.endpoint.startsWith("http")) {
      this.endpoint = getWebsocketUrl(this.endpoint);
    }
  }
  async makeRequest(method, params, signal) {
    const webSocket = await __privateMethod(this, _WebsocketClient_instances, setupWebSocket_fn).call(this);
    return new Promise((resolve, reject) => {
      __privateSet(this, _requestId, __privateGet(this, _requestId) + 1);
      __privateGet(this, _pendingRequests).set(__privateGet(this, _requestId), {
        resolve,
        reject,
        timeout: setTimeout(() => {
          __privateGet(this, _pendingRequests).delete(__privateGet(this, _requestId));
          reject(new Error(`Request timeout: ${method}`));
        }, this.options.callTimeout)
      });
      signal?.addEventListener("abort", () => {
        __privateGet(this, _pendingRequests).delete(__privateGet(this, _requestId));
        reject(signal.reason);
      });
      webSocket.send(JSON.stringify({ jsonrpc: "2.0", id: __privateGet(this, _requestId), method, params }));
    }).then(({ error, result }) => {
      if (error) {
        throw new import_errors.JsonRpcError(error.message, error.code);
      }
      return result;
    });
  }
  async subscribe(input) {
    const subscription = new RpcSubscription(input);
    __privateGet(this, _subscriptions).add(subscription);
    await subscription.subscribe(this);
    return () => subscription.unsubscribe(this);
  }
}
_requestId = new WeakMap();
_disconnects = new WeakMap();
_webSocket = new WeakMap();
_connectionPromise = new WeakMap();
_subscriptions = new WeakMap();
_pendingRequests = new WeakMap();
_WebsocketClient_instances = new WeakSet();
setupWebSocket_fn = function() {
  if (__privateGet(this, _connectionPromise)) {
    return __privateGet(this, _connectionPromise);
  }
  __privateSet(this, _connectionPromise, new Promise((resolve) => {
    __privateGet(this, _webSocket)?.close();
    __privateSet(this, _webSocket, new this.options.WebSocketConstructor(this.endpoint));
    __privateGet(this, _webSocket).addEventListener("open", () => {
      __privateSet(this, _disconnects, 0);
      resolve(__privateGet(this, _webSocket));
    });
    __privateGet(this, _webSocket).addEventListener("close", () => {
      __privateWrapper(this, _disconnects)._++;
      if (__privateGet(this, _disconnects) <= this.options.maxReconnects) {
        setTimeout(() => {
          __privateMethod(this, _WebsocketClient_instances, reconnect_fn).call(this);
        }, this.options.reconnectTimeout);
      }
    });
    __privateGet(this, _webSocket).addEventListener("message", ({ data }) => {
      let json;
      try {
        json = JSON.parse(data);
      } catch (error) {
        console.error(new Error(`Failed to parse RPC message: ${data}`, { cause: error }));
        return;
      }
      if ("id" in json && json.id != null && __privateGet(this, _pendingRequests).has(json.id)) {
        const { resolve: resolve2, timeout } = __privateGet(this, _pendingRequests).get(json.id);
        clearTimeout(timeout);
        resolve2(json);
      } else if ("params" in json) {
        const { params } = json;
        __privateGet(this, _subscriptions).forEach((subscription) => {
          if (subscription.subscriptionId === params.subscription) {
            if (params.subscription === subscription.subscriptionId) {
              subscription.onMessage(params.result);
            }
          }
        });
      }
    });
  }));
  return __privateGet(this, _connectionPromise);
};
reconnect_fn = async function() {
  __privateGet(this, _webSocket)?.close();
  __privateSet(this, _connectionPromise, null);
  return Promise.allSettled(
    [...__privateGet(this, _subscriptions)].map((subscription) => subscription.subscribe(this))
  );
};
class RpcSubscription {
  constructor(input) {
    this.subscriptionId = null;
    this.subscribed = false;
    this.input = input;
  }
  onMessage(message) {
    if (this.subscribed) {
      this.input.onMessage(message);
    }
  }
  async unsubscribe(client) {
    const { subscriptionId } = this;
    this.subscribed = false;
    if (subscriptionId == null) return false;
    this.subscriptionId = null;
    return client.makeRequest(this.input.unsubscribe, [subscriptionId]);
  }
  async subscribe(client) {
    this.subscriptionId = null;
    this.subscribed = true;
    const newSubscriptionId = await client.makeRequest(
      this.input.method,
      this.input.params,
      this.input.signal
    );
    if (this.subscribed) {
      this.subscriptionId = newSubscriptionId;
    }
  }
}
//# sourceMappingURL=rpc-websocket-client.js.map


/***/ }),

/***/ 8788:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var chain_exports = {};
module.exports = __toCommonJS(chain_exports);
//# sourceMappingURL=chain.js.map


/***/ }),

/***/ 772:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var changes_exports = {};
module.exports = __toCommonJS(changes_exports);
//# sourceMappingURL=changes.js.map


/***/ }),

/***/ 1319:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var coins_exports = {};
module.exports = __toCommonJS(coins_exports);
//# sourceMappingURL=coins.js.map


/***/ }),

/***/ 8624:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var common_exports = {};
module.exports = __toCommonJS(common_exports);
//# sourceMappingURL=common.js.map


/***/ }),

/***/ 928:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var generated_exports = {};
module.exports = __toCommonJS(generated_exports);
//# sourceMappingURL=generated.js.map


/***/ }),

/***/ 6473:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __reExport = (target, mod, secondTarget) => (__copyProps(target, mod, "default"), secondTarget && __copyProps(secondTarget, mod, "default"));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var types_exports = {};
module.exports = __toCommonJS(types_exports);
__reExport(types_exports, __nccwpck_require__(8788), module.exports);
__reExport(types_exports, __nccwpck_require__(1319), module.exports);
__reExport(types_exports, __nccwpck_require__(8624), module.exports);
__reExport(types_exports, __nccwpck_require__(772), module.exports);
__reExport(types_exports, __nccwpck_require__(928), module.exports);
__reExport(types_exports, __nccwpck_require__(4815), module.exports);
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 4815:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var params_exports = {};
module.exports = __toCommonJS(params_exports);
//# sourceMappingURL=params.js.map


/***/ }),

/***/ 9420:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var cache_exports = {};
__export(cache_exports, {
  ClientCache: () => ClientCache
});
module.exports = __toCommonJS(cache_exports);
var _prefix, _cache;
const _ClientCache = class _ClientCache {
  constructor({ prefix, cache } = {}) {
    __privateAdd(this, _prefix);
    __privateAdd(this, _cache);
    __privateSet(this, _prefix, prefix ?? []);
    __privateSet(this, _cache, cache ?? /* @__PURE__ */ new Map());
  }
  read(key, load) {
    const cacheKey = [__privateGet(this, _prefix), ...key].join(":");
    if (__privateGet(this, _cache).has(cacheKey)) {
      return __privateGet(this, _cache).get(cacheKey);
    }
    const result = load();
    __privateGet(this, _cache).set(cacheKey, result);
    if (typeof result === "object" && result !== null && "then" in result) {
      return Promise.resolve(result).then((v) => {
        __privateGet(this, _cache).set(cacheKey, v);
        return v;
      }).catch((err) => {
        __privateGet(this, _cache).delete(cacheKey);
        throw err;
      });
    }
    return result;
  }
  clear(prefix) {
    const prefixKey = [...__privateGet(this, _prefix), ...prefix ?? []].join(":");
    if (!prefixKey) {
      __privateGet(this, _cache).clear();
      return;
    }
    for (const key of __privateGet(this, _cache).keys()) {
      if (key.startsWith(prefixKey)) {
        __privateGet(this, _cache).delete(key);
      }
    }
  }
  scope(prefix) {
    return new _ClientCache({
      prefix: [...__privateGet(this, _prefix), ...Array.isArray(prefix) ? prefix : [prefix]],
      cache: __privateGet(this, _cache)
    });
  }
};
_prefix = new WeakMap();
_cache = new WeakMap();
let ClientCache = _ClientCache;
//# sourceMappingURL=cache.js.map


/***/ }),

/***/ 1795:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var client_exports = {};
__export(client_exports, {
  Experimental_BaseClient: () => Experimental_BaseClient
});
module.exports = __toCommonJS(client_exports);
var import_cache = __nccwpck_require__(9420);
class Experimental_BaseClient {
  constructor({ network }) {
    this.cache = new import_cache.ClientCache();
    this.network = network;
  }
  $extend(...registrations) {
    return Object.create(
      this,
      Object.fromEntries(
        registrations.map((registration) => {
          if ("experimental_asClientExtension" in registration) {
            const { name, register } = registration.experimental_asClientExtension();
            return [name, { value: register(this) }];
          }
          return [registration.name, { value: registration.register(this) }];
        })
      )
    );
  }
}
//# sourceMappingURL=client.js.map


/***/ }),

/***/ 7151:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var core_exports = {};
__export(core_exports, {
  Experimental_CoreClient: () => Experimental_CoreClient
});
module.exports = __toCommonJS(core_exports);
var import_type_tag_serializer = __nccwpck_require__(1020);
var import_dynamic_fields = __nccwpck_require__(3100);
var import_sui_types = __nccwpck_require__(4818);
var import_client = __nccwpck_require__(1795);
class Experimental_CoreClient extends import_client.Experimental_BaseClient {
  constructor() {
    super(...arguments);
    this.core = this;
  }
  async getObject(options) {
    const { objectId } = options;
    const {
      objects: [result]
    } = await this.getObjects({ objectIds: [objectId], signal: options.signal });
    if (result instanceof Error) {
      throw result;
    }
    return { object: result };
  }
  async getDynamicField(options) {
    const fieldId = (0, import_dynamic_fields.deriveDynamicFieldID)(
      options.parentId,
      import_type_tag_serializer.TypeTagSerializer.parseFromStr(options.name.type),
      options.name.bcs
    );
    const {
      objects: [fieldObject]
    } = await this.getObjects({
      objectIds: [fieldId],
      signal: options.signal
    });
    if (fieldObject instanceof Error) {
      throw fieldObject;
    }
    const fieldType = (0, import_sui_types.parseStructTag)(fieldObject.type);
    return {
      dynamicField: {
        id: fieldObject.id,
        digest: fieldObject.digest,
        version: fieldObject.version,
        type: fieldObject.type,
        name: {
          type: typeof fieldType.typeParams[0] === "string" ? fieldType.typeParams[0] : (0, import_sui_types.normalizeStructTag)(fieldType.typeParams[0]),
          bcs: options.name.bcs
        },
        value: {
          type: typeof fieldType.typeParams[1] === "string" ? fieldType.typeParams[1] : (0, import_sui_types.normalizeStructTag)(fieldType.typeParams[1]),
          bcs: fieldObject.content.slice(import_sui_types.SUI_ADDRESS_LENGTH + options.name.bcs.length)
        }
      }
    };
  }
  async waitForTransaction({
    signal,
    timeout = 60 * 1e3,
    ...input
  }) {
    const abortSignal = signal ? AbortSignal.any([AbortSignal.timeout(timeout), signal]) : AbortSignal.timeout(timeout);
    const abortPromise = new Promise((_, reject) => {
      abortSignal.addEventListener("abort", () => reject(abortSignal.reason));
    });
    abortPromise.catch(() => {
    });
    while (true) {
      abortSignal.throwIfAborted();
      try {
        return await this.getTransaction({
          ...input,
          signal: abortSignal
        });
      } catch (e) {
        await Promise.race([new Promise((resolve) => setTimeout(resolve, 2e3)), abortPromise]);
      }
    }
  }
}
//# sourceMappingURL=core.js.map


/***/ }),

/***/ 4399:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var errors_exports = {};
__export(errors_exports, {
  ObjectError: () => ObjectError,
  SuiClientError: () => SuiClientError
});
module.exports = __toCommonJS(errors_exports);
class SuiClientError extends Error {
}
class ObjectError extends SuiClientError {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
  static fromResponse(response, objectId) {
    switch (response.code) {
      case "notExists":
        return new ObjectError(response.code, `Object ${response.object_id} does not exist`);
      case "dynamicFieldNotFound":
        return new ObjectError(
          response.code,
          `Dynamic field not found for object ${response.parent_object_id}`
        );
      case "deleted":
        return new ObjectError(response.code, `Object ${response.object_id} has been deleted`);
      case "displayError":
        return new ObjectError(response.code, `Display error: ${response.error}`);
      case "unknown":
      default:
        return new ObjectError(
          response.code,
          `Unknown error while loading object${objectId ? ` ${objectId}` : ""}`
        );
    }
  }
}
//# sourceMappingURL=errors.js.map


/***/ }),

/***/ 7420:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var jsonRPC_exports = {};
__export(jsonRPC_exports, {
  JSONRpcTransport: () => JSONRpcTransport
});
module.exports = __toCommonJS(jsonRPC_exports);
var import_bcs = __nccwpck_require__(8830);
var import_bcs2 = __nccwpck_require__(6244);
var import_utils = __nccwpck_require__(1767);
var import_Transaction = __nccwpck_require__(2545);
var import_sui_types = __nccwpck_require__(4818);
var import_core = __nccwpck_require__(7151);
var import_errors = __nccwpck_require__(4399);
var import_utils2 = __nccwpck_require__(6540);
var _jsonRpcClient;
class JSONRpcTransport extends import_core.Experimental_CoreClient {
  constructor(jsonRpcClient) {
    super({ network: jsonRpcClient.network });
    __privateAdd(this, _jsonRpcClient);
    __privateSet(this, _jsonRpcClient, jsonRpcClient);
  }
  async getObjects(options) {
    const batches = (0, import_utils.batch)(options.objectIds, 50);
    const results = [];
    for (const batch2 of batches) {
      const objects = await __privateGet(this, _jsonRpcClient).multiGetObjects({
        ids: batch2,
        options: {
          showOwner: true,
          showType: true,
          showBcs: true
        },
        signal: options.signal
      });
      for (const [idx, object] of objects.entries()) {
        if (object.error) {
          results.push(import_errors.ObjectError.fromResponse(object.error, batch2[idx]));
        } else {
          results.push(parseObject(object.data));
        }
      }
    }
    return {
      objects: results
    };
  }
  async getOwnedObjects(options) {
    const objects = await __privateGet(this, _jsonRpcClient).getOwnedObjects({
      owner: options.address,
      limit: options.limit,
      cursor: options.cursor,
      options: {
        showOwner: true,
        showType: true,
        showBcs: true
      },
      signal: options.signal
    });
    return {
      objects: objects.data.map((result) => {
        if (result.error) {
          throw import_errors.ObjectError.fromResponse(result.error);
        }
        return parseObject(result.data);
      }),
      hasNextPage: objects.hasNextPage,
      cursor: objects.nextCursor ?? null
    };
  }
  async getCoins(options) {
    const coins = await __privateGet(this, _jsonRpcClient).getCoins({
      owner: options.address,
      coinType: options.coinType,
      limit: options.limit,
      cursor: options.cursor,
      signal: options.signal
    });
    return {
      objects: coins.data.map((coin) => {
        return {
          id: coin.coinObjectId,
          version: coin.version,
          digest: coin.digest,
          balance: coin.balance,
          type: `0x2::coin::Coin<${coin.coinType}>`,
          content: Coin.serialize({
            id: coin.coinObjectId,
            balance: {
              value: coin.balance
            }
          }).toBytes(),
          owner: {
            $kind: "ObjectOwner",
            ObjectOwner: options.address
          }
        };
      }),
      hasNextPage: coins.hasNextPage,
      cursor: coins.nextCursor ?? null
    };
  }
  async getBalance(options) {
    const balance = await __privateGet(this, _jsonRpcClient).getBalance({
      owner: options.address,
      coinType: options.coinType,
      signal: options.signal
    });
    return {
      balance: {
        coinType: balance.coinType,
        balance: balance.totalBalance
      }
    };
  }
  async getAllBalances(options) {
    const balances = await __privateGet(this, _jsonRpcClient).getAllBalances({
      owner: options.address,
      signal: options.signal
    });
    return {
      balances: balances.map((balance) => ({
        coinType: balance.coinType,
        balance: balance.totalBalance
      })),
      hasNextPage: false,
      cursor: null
    };
  }
  async getTransaction(options) {
    const transaction = await __privateGet(this, _jsonRpcClient).getTransactionBlock({
      digest: options.digest,
      options: {
        showRawInput: true,
        showObjectChanges: true,
        showRawEffects: true,
        showEvents: true
      },
      signal: options.signal
    });
    return {
      transaction: parseTransaction(transaction)
    };
  }
  async executeTransaction(options) {
    const transaction = await __privateGet(this, _jsonRpcClient).executeTransactionBlock({
      transactionBlock: options.transaction,
      signature: options.signatures,
      options: {
        showRawEffects: true,
        showEvents: true,
        showObjectChanges: true,
        showRawInput: true
      },
      signal: options.signal
    });
    return {
      transaction: parseTransaction(transaction)
    };
  }
  async dryRunTransaction(options) {
    const tx = import_Transaction.Transaction.from(options.transaction);
    const result = await __privateGet(this, _jsonRpcClient).dryRunTransactionBlock({
      transactionBlock: options.transaction,
      signal: options.signal
    });
    return {
      transaction: {
        digest: await tx.getDigest(),
        effects: parseTransactionEffectsJson({
          effects: result.effects,
          objectChanges: result.objectChanges
        }),
        signatures: [],
        bcs: options.transaction
      }
    };
  }
  async getReferenceGasPrice(options) {
    const referenceGasPrice = await __privateGet(this, _jsonRpcClient).getReferenceGasPrice({
      signal: options?.signal
    });
    return {
      referenceGasPrice: String(referenceGasPrice)
    };
  }
  async getDynamicFields(options) {
    const dynamicFields = await __privateGet(this, _jsonRpcClient).getDynamicFields({
      parentId: options.parentId,
      limit: options.limit,
      cursor: options.cursor
    });
    return {
      dynamicFields: dynamicFields.data.map((dynamicField) => {
        return {
          id: dynamicField.objectId,
          type: dynamicField.objectType,
          name: {
            type: dynamicField.name.type,
            bcs: (0, import_bcs.fromBase64)(dynamicField.bcsName)
          }
        };
      }),
      hasNextPage: dynamicFields.hasNextPage,
      cursor: dynamicFields.nextCursor
    };
  }
  async verifyZkLoginSignature(options) {
    const result = await __privateGet(this, _jsonRpcClient).verifyZkLoginSignature({
      bytes: options.bytes,
      signature: options.signature,
      intentScope: options.intentScope,
      author: options.author
    });
    return {
      success: result.success,
      errors: result.errors
    };
  }
}
_jsonRpcClient = new WeakMap();
function parseObject(object) {
  return {
    id: object.objectId,
    version: object.version,
    digest: object.digest,
    type: object.type,
    content: object.bcs?.dataType === "moveObject" ? (0, import_bcs.fromBase64)(object.bcs.bcsBytes) : new Uint8Array(),
    owner: parseOwner(object.owner)
  };
}
function parseOwner(owner) {
  if (owner === "Immutable") {
    return {
      $kind: "Immutable",
      Immutable: true
    };
  }
  if ("ConsensusV2" in owner) {
    return {
      $kind: "ConsensusV2",
      ConsensusV2: {
        authenticator: {
          $kind: "SingleOwner",
          SingleOwner: owner.ConsensusV2.authenticator.SingleOwner
        },
        startVersion: owner.ConsensusV2.start_version
      }
    };
  }
  if ("AddressOwner" in owner) {
    return {
      $kind: "AddressOwner",
      AddressOwner: owner.AddressOwner
    };
  }
  if ("ObjectOwner" in owner) {
    return {
      $kind: "ObjectOwner",
      ObjectOwner: owner.ObjectOwner
    };
  }
  if ("Shared" in owner) {
    return {
      $kind: "Shared",
      Shared: {
        initialSharedVersion: owner.Shared.initial_shared_version
      }
    };
  }
  throw new Error(`Unknown owner type: ${JSON.stringify(owner)}`);
}
function parseTransaction(transaction) {
  const parsedTx = import_bcs2.bcs.SenderSignedData.parse((0, import_bcs.fromBase64)(transaction.rawTransaction))[0];
  const objectTypes = {};
  transaction.objectChanges?.forEach((change) => {
    if (change.type !== "published") {
      objectTypes[change.objectId] = change.objectType;
    }
  });
  return {
    digest: transaction.digest,
    effects: (0, import_utils2.parseTransactionEffects)({
      effects: new Uint8Array(transaction.rawEffects),
      objectTypes
    }),
    bcs: import_bcs2.bcs.TransactionData.serialize(parsedTx.intentMessage.value).toBytes(),
    signatures: parsedTx.txSignatures
  };
}
function parseTransactionEffectsJson({
  bytes,
  effects,
  epoch,
  objectChanges
}) {
  const changedObjects = [];
  const unchangedSharedObjects = [];
  objectChanges?.forEach((change) => {
    switch (change.type) {
      case "published":
        changedObjects.push({
          id: change.packageId,
          inputState: "DoesNotExist",
          inputVersion: null,
          inputDigest: null,
          inputOwner: null,
          outputState: "PackageWrite",
          outputVersion: change.version,
          outputDigest: change.digest,
          outputOwner: null,
          idOperation: "Created",
          objectType: null
        });
        break;
      case "transferred":
        changedObjects.push({
          id: change.objectId,
          inputState: "Exists",
          inputVersion: change.version,
          inputDigest: change.digest,
          inputOwner: {
            $kind: "AddressOwner",
            AddressOwner: change.sender
          },
          outputState: "ObjectWrite",
          outputVersion: change.version,
          outputDigest: change.digest,
          outputOwner: parseOwner(change.recipient),
          idOperation: "None",
          objectType: change.objectType
        });
        break;
      case "mutated":
        changedObjects.push({
          id: change.objectId,
          inputState: "Exists",
          inputVersion: change.previousVersion,
          inputDigest: null,
          inputOwner: parseOwner(change.owner),
          outputState: "ObjectWrite",
          outputVersion: change.version,
          outputDigest: change.digest,
          outputOwner: parseOwner(change.owner),
          idOperation: "None",
          objectType: change.objectType
        });
        break;
      case "deleted":
        changedObjects.push({
          id: change.objectId,
          inputState: "Exists",
          inputVersion: change.version,
          inputDigest: effects.deleted?.find((d) => d.objectId === change.objectId)?.digest ?? null,
          inputOwner: null,
          outputState: "DoesNotExist",
          outputVersion: null,
          outputDigest: null,
          outputOwner: null,
          idOperation: "Deleted",
          objectType: change.objectType
        });
        break;
      case "wrapped":
        changedObjects.push({
          id: change.objectId,
          inputState: "Exists",
          inputVersion: change.version,
          inputDigest: null,
          inputOwner: {
            $kind: "AddressOwner",
            AddressOwner: change.sender
          },
          outputState: "ObjectWrite",
          outputVersion: change.version,
          outputDigest: effects.wrapped?.find((w) => w.objectId === change.objectId)?.digest ?? null,
          outputOwner: {
            $kind: "ObjectOwner",
            ObjectOwner: change.sender
          },
          idOperation: "None",
          objectType: change.objectType
        });
        break;
      case "created":
        changedObjects.push({
          id: change.objectId,
          inputState: "DoesNotExist",
          inputVersion: null,
          inputDigest: null,
          inputOwner: null,
          outputState: "ObjectWrite",
          outputVersion: change.version,
          outputDigest: change.digest,
          outputOwner: parseOwner(change.owner),
          idOperation: "Created",
          objectType: change.objectType
        });
        break;
    }
  });
  return {
    bcs: bytes ?? null,
    digest: effects.transactionDigest,
    version: 2,
    status: effects.status.status === "success" ? { success: true, error: null } : { success: false, error: effects.status.error },
    epoch: epoch ?? null,
    gasUsed: effects.gasUsed,
    transactionDigest: effects.transactionDigest,
    gasObject: {
      id: effects.gasObject?.reference.objectId,
      inputState: "Exists",
      inputVersion: null,
      inputDigest: null,
      inputOwner: null,
      outputState: "ObjectWrite",
      outputVersion: effects.gasObject.reference.version,
      outputDigest: effects.gasObject.reference.digest,
      outputOwner: parseOwner(effects.gasObject.owner),
      idOperation: "None",
      objectType: (0, import_sui_types.normalizeStructTag)("0x2::coin::Coin<0x2::sui::SUI>")
    },
    eventsDigest: effects.eventsDigest ?? null,
    dependencies: effects.dependencies ?? [],
    lamportVersion: effects.gasObject.reference.version,
    changedObjects,
    unchangedSharedObjects,
    auxiliaryDataDigest: null
  };
}
const Balance = import_bcs2.bcs.struct("Balance", {
  value: import_bcs2.bcs.u64()
});
const Coin = import_bcs2.bcs.struct("Coin", {
  id: import_bcs2.bcs.Address,
  balance: Balance
});
//# sourceMappingURL=jsonRPC.js.map


/***/ }),

/***/ 6540:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var utils_exports = {};
__export(utils_exports, {
  parseTransactionEffects: () => parseTransactionEffects
});
module.exports = __toCommonJS(utils_exports);
var import_bcs = __nccwpck_require__(6244);
function parseTransactionEffects({
  effects,
  epoch,
  objectTypes
}) {
  const parsed = import_bcs.bcs.TransactionEffects.parse(effects);
  switch (parsed.$kind) {
    case "V1":
      return parseTransactionEffectsV1({ bytes: effects, effects: parsed.V1, epoch, objectTypes });
    case "V2":
      return parseTransactionEffectsV2({ bytes: effects, effects: parsed.V2, epoch, objectTypes });
    default:
      throw new Error(
        `Unknown transaction effects version: ${parsed.$kind}`
      );
  }
}
function parseTransactionEffectsV1(_) {
  throw new Error("V1 effects are not supported yet");
}
function parseTransactionEffectsV2({
  bytes,
  effects,
  epoch,
  objectTypes
}) {
  const changedObjects = effects.changedObjects.map(
    ([id, change]) => {
      return {
        id,
        inputState: change.inputState.$kind === "Exist" ? "Exists" : "DoesNotExist",
        inputVersion: change.inputState.Exist?.[0][0] ?? null,
        inputDigest: change.inputState.Exist?.[0][1] ?? null,
        inputOwner: change.inputState.Exist?.[1] ?? null,
        outputState: change.outputState.$kind === "NotExist" ? "DoesNotExist" : change.outputState.$kind,
        outputVersion: change.outputState.$kind === "PackageWrite" ? change.outputState.PackageWrite?.[0] : change.outputState.ObjectWrite ? effects.lamportVersion : null,
        outputDigest: change.outputState.$kind === "PackageWrite" ? change.outputState.PackageWrite?.[1] : change.outputState.ObjectWrite?.[0] ?? null,
        outputOwner: change.outputState.ObjectWrite ? change.outputState.ObjectWrite[1] : null,
        idOperation: change.idOperation.$kind,
        objectType: objectTypes[id] ?? null
      };
    }
  );
  return {
    bcs: bytes,
    digest: effects.transactionDigest,
    version: 2,
    status: effects.status.$kind === "Success" ? {
      success: true,
      error: null
    } : {
      success: false,
      // TODO: add command
      error: effects.status.Failed.error.$kind
    },
    epoch: epoch ?? null,
    gasUsed: effects.gasUsed,
    transactionDigest: effects.transactionDigest,
    gasObject: effects.gasObjectIndex === null ? null : changedObjects[effects.gasObjectIndex] ?? null,
    eventsDigest: effects.eventsDigest,
    dependencies: effects.dependencies,
    lamportVersion: effects.lamportVersion,
    changedObjects,
    unchangedSharedObjects: effects.unchangedSharedObjects.map(
      ([objectId, object]) => {
        return {
          kind: object.$kind,
          objectId,
          version: object.$kind === "ReadOnlyRoot" ? object.ReadOnlyRoot[0] : object[object.$kind],
          digest: object.$kind === "ReadOnlyRoot" ? object.ReadOnlyRoot[1] : null,
          objectType: objectTypes[objectId] ?? null
        };
      }
    ),
    auxiliaryDataDigest: effects.auxDataDigest
  };
}
//# sourceMappingURL=utils.js.map


/***/ }),

/***/ 4845:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var Arguments_exports = {};
__export(Arguments_exports, {
  Arguments: () => Arguments
});
module.exports = __toCommonJS(Arguments_exports);
var import_object = __nccwpck_require__(3714);
var import_pure = __nccwpck_require__(59);
const Arguments = {
  pure: (0, import_pure.createPure)((value) => (tx) => tx.pure(value)),
  object: (0, import_object.createObjectMethods)((value) => (tx) => tx.object(value)),
  sharedObjectRef: (...args) => (tx) => tx.sharedObjectRef(...args),
  objectRef: (...args) => (tx) => tx.objectRef(...args),
  receivingRef: (...args) => (tx) => tx.receivingRef(...args)
};
//# sourceMappingURL=Arguments.js.map


/***/ }),

/***/ 8783:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var Commands_exports = {};
__export(Commands_exports, {
  Commands: () => Commands,
  UpgradePolicy: () => UpgradePolicy
});
module.exports = __toCommonJS(Commands_exports);
var import_bcs = __nccwpck_require__(8830);
var import_valibot = __nccwpck_require__(8275);
var import_sui_types = __nccwpck_require__(4818);
var import_internal = __nccwpck_require__(6921);
var UpgradePolicy = /* @__PURE__ */ ((UpgradePolicy2) => {
  UpgradePolicy2[UpgradePolicy2["COMPATIBLE"] = 0] = "COMPATIBLE";
  UpgradePolicy2[UpgradePolicy2["ADDITIVE"] = 128] = "ADDITIVE";
  UpgradePolicy2[UpgradePolicy2["DEP_ONLY"] = 192] = "DEP_ONLY";
  return UpgradePolicy2;
})(UpgradePolicy || {});
const Commands = {
  MoveCall(input) {
    const [pkg, mod = "", fn = ""] = "target" in input ? input.target.split("::") : [input.package, input.module, input.function];
    return {
      $kind: "MoveCall",
      MoveCall: {
        package: pkg,
        module: mod,
        function: fn,
        typeArguments: input.typeArguments ?? [],
        arguments: input.arguments ?? []
      }
    };
  },
  TransferObjects(objects, address) {
    return {
      $kind: "TransferObjects",
      TransferObjects: {
        objects: objects.map((o) => (0, import_valibot.parse)(import_internal.Argument, o)),
        address: (0, import_valibot.parse)(import_internal.Argument, address)
      }
    };
  },
  SplitCoins(coin, amounts) {
    return {
      $kind: "SplitCoins",
      SplitCoins: {
        coin: (0, import_valibot.parse)(import_internal.Argument, coin),
        amounts: amounts.map((o) => (0, import_valibot.parse)(import_internal.Argument, o))
      }
    };
  },
  MergeCoins(destination, sources) {
    return {
      $kind: "MergeCoins",
      MergeCoins: {
        destination: (0, import_valibot.parse)(import_internal.Argument, destination),
        sources: sources.map((o) => (0, import_valibot.parse)(import_internal.Argument, o))
      }
    };
  },
  Publish({
    modules,
    dependencies
  }) {
    return {
      $kind: "Publish",
      Publish: {
        modules: modules.map(
          (module2) => typeof module2 === "string" ? module2 : (0, import_bcs.toBase64)(new Uint8Array(module2))
        ),
        dependencies: dependencies.map((dep) => (0, import_sui_types.normalizeSuiObjectId)(dep))
      }
    };
  },
  Upgrade({
    modules,
    dependencies,
    package: packageId,
    ticket
  }) {
    return {
      $kind: "Upgrade",
      Upgrade: {
        modules: modules.map(
          (module2) => typeof module2 === "string" ? module2 : (0, import_bcs.toBase64)(new Uint8Array(module2))
        ),
        dependencies: dependencies.map((dep) => (0, import_sui_types.normalizeSuiObjectId)(dep)),
        package: packageId,
        ticket: (0, import_valibot.parse)(import_internal.Argument, ticket)
      }
    };
  },
  MakeMoveVec({
    type,
    elements
  }) {
    return {
      $kind: "MakeMoveVec",
      MakeMoveVec: {
        type: type ?? null,
        elements: elements.map((o) => (0, import_valibot.parse)(import_internal.Argument, o))
      }
    };
  },
  Intent({
    name,
    inputs = {},
    data = {}
  }) {
    return {
      $kind: "$Intent",
      $Intent: {
        name,
        inputs: Object.fromEntries(
          Object.entries(inputs).map(([key, value]) => [
            key,
            Array.isArray(value) ? value.map((o) => (0, import_valibot.parse)(import_internal.Argument, o)) : (0, import_valibot.parse)(import_internal.Argument, value)
          ])
        ),
        data
      }
    };
  }
};
//# sourceMappingURL=Commands.js.map


/***/ }),

/***/ 7484:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var Inputs_exports = {};
__export(Inputs_exports, {
  Inputs: () => Inputs
});
module.exports = __toCommonJS(Inputs_exports);
var import_bcs = __nccwpck_require__(8830);
var import_sui_types = __nccwpck_require__(4818);
function Pure(data) {
  return {
    $kind: "Pure",
    Pure: {
      bytes: data instanceof Uint8Array ? (0, import_bcs.toBase64)(data) : data.toBase64()
    }
  };
}
const Inputs = {
  Pure,
  ObjectRef({ objectId, digest, version }) {
    return {
      $kind: "Object",
      Object: {
        $kind: "ImmOrOwnedObject",
        ImmOrOwnedObject: {
          digest,
          version,
          objectId: (0, import_sui_types.normalizeSuiAddress)(objectId)
        }
      }
    };
  },
  SharedObjectRef({
    objectId,
    mutable,
    initialSharedVersion
  }) {
    return {
      $kind: "Object",
      Object: {
        $kind: "SharedObject",
        SharedObject: {
          mutable,
          initialSharedVersion,
          objectId: (0, import_sui_types.normalizeSuiAddress)(objectId)
        }
      }
    };
  },
  ReceivingRef({ objectId, digest, version }) {
    return {
      $kind: "Object",
      Object: {
        $kind: "Receiving",
        Receiving: {
          digest,
          version,
          objectId: (0, import_sui_types.normalizeSuiAddress)(objectId)
        }
      }
    };
  }
};
//# sourceMappingURL=Inputs.js.map


/***/ }),

/***/ 7570:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var ObjectCache_exports = {};
__export(ObjectCache_exports, {
  AsyncCache: () => AsyncCache,
  InMemoryCache: () => InMemoryCache,
  ObjectCache: () => ObjectCache
});
module.exports = __toCommonJS(ObjectCache_exports);
var import_sui_types = __nccwpck_require__(4818);
var _caches, _cache, _onEffects;
class AsyncCache {
  async getObject(id) {
    const [owned, shared] = await Promise.all([
      this.get("OwnedObject", id),
      this.get("SharedOrImmutableObject", id)
    ]);
    return owned ?? shared ?? null;
  }
  async getObjects(ids) {
    return Promise.all([...ids.map((id) => this.getObject(id))]);
  }
  async addObject(object) {
    if (object.owner) {
      await this.set("OwnedObject", object.objectId, object);
    } else {
      await this.set("SharedOrImmutableObject", object.objectId, object);
    }
    return object;
  }
  async addObjects(objects) {
    await Promise.all(objects.map(async (object) => this.addObject(object)));
  }
  async deleteObject(id) {
    await Promise.all([this.delete("OwnedObject", id), this.delete("SharedOrImmutableObject", id)]);
  }
  async deleteObjects(ids) {
    await Promise.all(ids.map((id) => this.deleteObject(id)));
  }
  async getMoveFunctionDefinition(ref) {
    const functionName = `${(0, import_sui_types.normalizeSuiAddress)(ref.package)}::${ref.module}::${ref.function}`;
    return this.get("MoveFunction", functionName);
  }
  async addMoveFunctionDefinition(functionEntry) {
    const pkg = (0, import_sui_types.normalizeSuiAddress)(functionEntry.package);
    const functionName = `${pkg}::${functionEntry.module}::${functionEntry.function}`;
    const entry = {
      ...functionEntry,
      package: pkg
    };
    await this.set("MoveFunction", functionName, entry);
    return entry;
  }
  async deleteMoveFunctionDefinition(ref) {
    const functionName = `${(0, import_sui_types.normalizeSuiAddress)(ref.package)}::${ref.module}::${ref.function}`;
    await this.delete("MoveFunction", functionName);
  }
  async getCustom(key) {
    return this.get("Custom", key);
  }
  async setCustom(key, value) {
    return this.set("Custom", key, value);
  }
  async deleteCustom(key) {
    return this.delete("Custom", key);
  }
}
class InMemoryCache extends AsyncCache {
  constructor() {
    super(...arguments);
    __privateAdd(this, _caches, {
      OwnedObject: /* @__PURE__ */ new Map(),
      SharedOrImmutableObject: /* @__PURE__ */ new Map(),
      MoveFunction: /* @__PURE__ */ new Map(),
      Custom: /* @__PURE__ */ new Map()
    });
  }
  async get(type, key) {
    return __privateGet(this, _caches)[type].get(key) ?? null;
  }
  async set(type, key, value) {
    __privateGet(this, _caches)[type].set(key, value);
  }
  async delete(type, key) {
    __privateGet(this, _caches)[type].delete(key);
  }
  async clear(type) {
    if (type) {
      __privateGet(this, _caches)[type].clear();
    } else {
      for (const cache of Object.values(__privateGet(this, _caches))) {
        cache.clear();
      }
    }
  }
}
_caches = new WeakMap();
class ObjectCache {
  constructor({ cache = new InMemoryCache(), onEffects }) {
    __privateAdd(this, _cache);
    __privateAdd(this, _onEffects);
    __privateSet(this, _cache, cache);
    __privateSet(this, _onEffects, onEffects);
  }
  asPlugin() {
    return async (transactionData, _options, next) => {
      const unresolvedObjects = transactionData.inputs.filter((input) => input.UnresolvedObject).map((input) => input.UnresolvedObject.objectId);
      const cached = (await __privateGet(this, _cache).getObjects(unresolvedObjects)).filter(
        (obj) => obj !== null
      );
      const byId = new Map(cached.map((obj) => [obj.objectId, obj]));
      for (const input of transactionData.inputs) {
        if (!input.UnresolvedObject) {
          continue;
        }
        const cached2 = byId.get(input.UnresolvedObject.objectId);
        if (!cached2) {
          continue;
        }
        if (cached2.initialSharedVersion && !input.UnresolvedObject.initialSharedVersion) {
          input.UnresolvedObject.initialSharedVersion = cached2.initialSharedVersion;
        } else {
          if (cached2.version && !input.UnresolvedObject.version) {
            input.UnresolvedObject.version = cached2.version;
          }
          if (cached2.digest && !input.UnresolvedObject.digest) {
            input.UnresolvedObject.digest = cached2.digest;
          }
        }
      }
      await Promise.all(
        transactionData.commands.map(async (commands) => {
          if (commands.MoveCall) {
            const def = await this.getMoveFunctionDefinition({
              package: commands.MoveCall.package,
              module: commands.MoveCall.module,
              function: commands.MoveCall.function
            });
            if (def) {
              commands.MoveCall._argumentTypes = def.parameters;
            }
          }
        })
      );
      await next();
      await Promise.all(
        transactionData.commands.map(async (commands) => {
          if (commands.MoveCall?._argumentTypes) {
            await __privateGet(this, _cache).addMoveFunctionDefinition({
              package: commands.MoveCall.package,
              module: commands.MoveCall.module,
              function: commands.MoveCall.function,
              parameters: commands.MoveCall._argumentTypes
            });
          }
        })
      );
    };
  }
  async clear() {
    await __privateGet(this, _cache).clear();
  }
  async getMoveFunctionDefinition(ref) {
    return __privateGet(this, _cache).getMoveFunctionDefinition(ref);
  }
  async getObjects(ids) {
    return __privateGet(this, _cache).getObjects(ids);
  }
  async deleteObjects(ids) {
    return __privateGet(this, _cache).deleteObjects(ids);
  }
  async clearOwnedObjects() {
    await __privateGet(this, _cache).clear("OwnedObject");
  }
  async clearCustom() {
    await __privateGet(this, _cache).clear("Custom");
  }
  async getCustom(key) {
    return __privateGet(this, _cache).getCustom(key);
  }
  async setCustom(key, value) {
    return __privateGet(this, _cache).setCustom(key, value);
  }
  async deleteCustom(key) {
    return __privateGet(this, _cache).deleteCustom(key);
  }
  async applyEffects(effects) {
    var _a;
    if (!effects.V2) {
      throw new Error(`Unsupported transaction effects version ${effects.$kind}`);
    }
    const { lamportVersion, changedObjects } = effects.V2;
    const deletedIds = [];
    const addedObjects = [];
    changedObjects.forEach(([id, change]) => {
      if (change.outputState.NotExist) {
        deletedIds.push(id);
      } else if (change.outputState.ObjectWrite) {
        const [digest, owner] = change.outputState.ObjectWrite;
        addedObjects.push({
          objectId: id,
          digest,
          version: lamportVersion,
          owner: owner.AddressOwner ?? owner.ObjectOwner ?? null,
          initialSharedVersion: owner.Shared?.initialSharedVersion ?? null
        });
      }
    });
    await Promise.all([
      __privateGet(this, _cache).addObjects(addedObjects),
      __privateGet(this, _cache).deleteObjects(deletedIds),
      (_a = __privateGet(this, _onEffects)) == null ? void 0 : _a.call(this, effects)
    ]);
  }
}
_cache = new WeakMap();
_onEffects = new WeakMap();
//# sourceMappingURL=ObjectCache.js.map


/***/ }),

/***/ 2545:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
var Transaction_exports = {};
__export(Transaction_exports, {
  Transaction: () => Transaction,
  isTransaction: () => isTransaction
});
module.exports = __toCommonJS(Transaction_exports);
var import_bcs = __nccwpck_require__(8830);
var import_valibot = __nccwpck_require__(8275);
var import_sui_types = __nccwpck_require__(4818);
var import_Commands = __nccwpck_require__(8783);
var import_internal = __nccwpck_require__(6921);
var import_v1 = __nccwpck_require__(113);
var import_v2 = __nccwpck_require__(3768);
var import_Inputs = __nccwpck_require__(7484);
var import_json_rpc_resolver = __nccwpck_require__(1700);
var import_object = __nccwpck_require__(3714);
var import_pure = __nccwpck_require__(59);
var import_TransactionData = __nccwpck_require__(1553);
var import_utils = __nccwpck_require__(6500);
var _serializationPlugins, _buildPlugins, _intentResolvers, _inputSection, _commandSection, _availableResults, _pendingPromises, _added, _data, _Transaction_instances, fork_fn, addCommand_fn, addInput_fn, normalizeTransactionArgument_fn, resolveArgument_fn, prepareBuild_fn, runPlugins_fn, waitForPendingTasks_fn, sortCommandsAndInputs_fn;
function createTransactionResult(index, length = Infinity) {
  const baseResult = { $kind: "Result", Result: index };
  const nestedResults = [];
  const nestedResultFor = (resultIndex) => nestedResults[resultIndex] ?? (nestedResults[resultIndex] = {
    $kind: "NestedResult",
    NestedResult: [index, resultIndex]
  });
  return new Proxy(baseResult, {
    set() {
      throw new Error(
        "The transaction result is a proxy, and does not support setting properties directly"
      );
    },
    // TODO: Instead of making this return a concrete argument, we should ideally
    // make it reference-based (so that this gets resolved at build-time), which
    // allows re-ordering transactions.
    get(target, property) {
      if (property in target) {
        return Reflect.get(target, property);
      }
      if (property === Symbol.iterator) {
        return function* () {
          let i = 0;
          while (i < length) {
            yield nestedResultFor(i);
            i++;
          }
        };
      }
      if (typeof property === "symbol") return;
      const resultIndex = parseInt(property, 10);
      if (Number.isNaN(resultIndex) || resultIndex < 0) return;
      return nestedResultFor(resultIndex);
    }
  });
}
const TRANSACTION_BRAND = Symbol.for("@mysten/transaction");
function isTransaction(obj) {
  return !!obj && typeof obj === "object" && obj[TRANSACTION_BRAND] === true;
}
const modulePluginRegistry = {
  buildPlugins: /* @__PURE__ */ new Map(),
  serializationPlugins: /* @__PURE__ */ new Map()
};
const TRANSACTION_REGISTRY_KEY = Symbol.for("@mysten/transaction/registry");
function getGlobalPluginRegistry() {
  try {
    const target = globalThis;
    if (!target[TRANSACTION_REGISTRY_KEY]) {
      target[TRANSACTION_REGISTRY_KEY] = modulePluginRegistry;
    }
    return target[TRANSACTION_REGISTRY_KEY];
  } catch (e) {
    return modulePluginRegistry;
  }
}
const _Transaction = class _Transaction {
  constructor() {
    __privateAdd(this, _Transaction_instances);
    __privateAdd(this, _serializationPlugins);
    __privateAdd(this, _buildPlugins);
    __privateAdd(this, _intentResolvers, /* @__PURE__ */ new Map());
    __privateAdd(this, _inputSection, []);
    __privateAdd(this, _commandSection, []);
    __privateAdd(this, _availableResults, /* @__PURE__ */ new Set());
    __privateAdd(this, _pendingPromises, /* @__PURE__ */ new Set());
    __privateAdd(this, _added, /* @__PURE__ */ new Map());
    __privateAdd(this, _data);
    /**
     * Add a new object input to the transaction.
     */
    this.object = (0, import_object.createObjectMethods)(
      (value) => {
        if (typeof value === "function") {
          return this.object(this.add(value));
        }
        if (typeof value === "object" && (0, import_valibot.is)(import_internal.Argument, value)) {
          return value;
        }
        const id = (0, import_utils.getIdFromCallArg)(value);
        const inserted = __privateGet(this, _data).inputs.find((i) => id === (0, import_utils.getIdFromCallArg)(i));
        if (inserted?.Object?.SharedObject && typeof value === "object" && value.Object?.SharedObject) {
          inserted.Object.SharedObject.mutable = inserted.Object.SharedObject.mutable || value.Object.SharedObject.mutable;
        }
        return inserted ? { $kind: "Input", Input: __privateGet(this, _data).inputs.indexOf(inserted), type: "object" } : __privateMethod(this, _Transaction_instances, addInput_fn).call(this, "object", typeof value === "string" ? {
          $kind: "UnresolvedObject",
          UnresolvedObject: { objectId: (0, import_sui_types.normalizeSuiAddress)(value) }
        } : value);
      }
    );
    const globalPlugins = getGlobalPluginRegistry();
    __privateSet(this, _data, new import_TransactionData.TransactionDataBuilder());
    __privateSet(this, _buildPlugins, [...globalPlugins.buildPlugins.values()]);
    __privateSet(this, _serializationPlugins, [...globalPlugins.serializationPlugins.values()]);
  }
  /**
   * Converts from a serialize transaction kind (built with `build({ onlyTransactionKind: true })`) to a `Transaction` class.
   * Supports either a byte array, or base64-encoded bytes.
   */
  static fromKind(serialized) {
    const tx = new _Transaction();
    __privateSet(tx, _data, import_TransactionData.TransactionDataBuilder.fromKindBytes(
      typeof serialized === "string" ? (0, import_bcs.fromBase64)(serialized) : serialized
    ));
    __privateSet(tx, _inputSection, __privateGet(tx, _data).inputs);
    __privateSet(tx, _commandSection, __privateGet(tx, _data).commands);
    return tx;
  }
  /**
   * Converts from a serialized transaction format to a `Transaction` class.
   * There are two supported serialized formats:
   * - A string returned from `Transaction#serialize`. The serialized format must be compatible, or it will throw an error.
   * - A byte array (or base64-encoded bytes) containing BCS transaction data.
   */
  static from(transaction) {
    const newTransaction = new _Transaction();
    if (isTransaction(transaction)) {
      __privateSet(newTransaction, _data, new import_TransactionData.TransactionDataBuilder(transaction.getData()));
    } else if (typeof transaction !== "string" || !transaction.startsWith("{")) {
      __privateSet(newTransaction, _data, import_TransactionData.TransactionDataBuilder.fromBytes(
        typeof transaction === "string" ? (0, import_bcs.fromBase64)(transaction) : transaction
      ));
    } else {
      __privateSet(newTransaction, _data, import_TransactionData.TransactionDataBuilder.restore(JSON.parse(transaction)));
    }
    __privateSet(newTransaction, _inputSection, __privateGet(newTransaction, _data).inputs);
    __privateSet(newTransaction, _commandSection, __privateGet(newTransaction, _data).commands);
    return newTransaction;
  }
  static registerGlobalSerializationPlugin(stepOrStep, step) {
    getGlobalPluginRegistry().serializationPlugins.set(
      stepOrStep,
      step ?? stepOrStep
    );
  }
  static unregisterGlobalSerializationPlugin(name) {
    getGlobalPluginRegistry().serializationPlugins.delete(name);
  }
  static registerGlobalBuildPlugin(stepOrStep, step) {
    getGlobalPluginRegistry().buildPlugins.set(
      stepOrStep,
      step ?? stepOrStep
    );
  }
  static unregisterGlobalBuildPlugin(name) {
    getGlobalPluginRegistry().buildPlugins.delete(name);
  }
  addSerializationPlugin(step) {
    __privateGet(this, _serializationPlugins).push(step);
  }
  addBuildPlugin(step) {
    __privateGet(this, _buildPlugins).push(step);
  }
  addIntentResolver(intent, resolver) {
    if (__privateGet(this, _intentResolvers).has(intent) && __privateGet(this, _intentResolvers).get(intent) !== resolver) {
      throw new Error(`Intent resolver for ${intent} already exists`);
    }
    __privateGet(this, _intentResolvers).set(intent, resolver);
  }
  setSender(sender) {
    __privateGet(this, _data).sender = sender;
  }
  /**
   * Sets the sender only if it has not already been set.
   * This is useful for sponsored transaction flows where the sender may not be the same as the signer address.
   */
  setSenderIfNotSet(sender) {
    if (!__privateGet(this, _data).sender) {
      __privateGet(this, _data).sender = sender;
    }
  }
  setExpiration(expiration) {
    __privateGet(this, _data).expiration = expiration ? (0, import_valibot.parse)(import_internal.TransactionExpiration, expiration) : null;
  }
  setGasPrice(price) {
    __privateGet(this, _data).gasConfig.price = String(price);
  }
  setGasBudget(budget) {
    __privateGet(this, _data).gasConfig.budget = String(budget);
  }
  setGasBudgetIfNotSet(budget) {
    if (__privateGet(this, _data).gasData.budget == null) {
      __privateGet(this, _data).gasConfig.budget = String(budget);
    }
  }
  setGasOwner(owner) {
    __privateGet(this, _data).gasConfig.owner = owner;
  }
  setGasPayment(payments) {
    __privateGet(this, _data).gasConfig.payment = payments.map((payment) => (0, import_valibot.parse)(import_internal.ObjectRef, payment));
  }
  /** @deprecated Use `getData()` instead. */
  get blockData() {
    return (0, import_v1.serializeV1TransactionData)(__privateGet(this, _data).snapshot());
  }
  /** Get a snapshot of the transaction data, in JSON form: */
  getData() {
    return __privateGet(this, _data).snapshot();
  }
  // Used to brand transaction classes so that they can be identified, even between multiple copies
  // of the builder.
  get [TRANSACTION_BRAND]() {
    return true;
  }
  // Temporary workaround for the wallet interface accidentally serializing transactions via postMessage
  get pure() {
    Object.defineProperty(this, "pure", {
      enumerable: false,
      value: (0, import_pure.createPure)((value) => {
        if ((0, import_bcs.isSerializedBcs)(value)) {
          return __privateMethod(this, _Transaction_instances, addInput_fn).call(this, "pure", {
            $kind: "Pure",
            Pure: {
              bytes: value.toBase64()
            }
          });
        }
        return __privateMethod(this, _Transaction_instances, addInput_fn).call(this, "pure", (0, import_valibot.is)(import_internal.NormalizedCallArg, value) ? (0, import_valibot.parse)(import_internal.NormalizedCallArg, value) : value instanceof Uint8Array ? import_Inputs.Inputs.Pure(value) : { $kind: "UnresolvedPure", UnresolvedPure: { value } });
      })
    });
    return this.pure;
  }
  /** Returns an argument for the gas coin, to be used in a transaction. */
  get gas() {
    return { $kind: "GasCoin", GasCoin: true };
  }
  /**
   * Add a new object input to the transaction using the fully-resolved object reference.
   * If you only have an object ID, use `builder.object(id)` instead.
   */
  objectRef(...args) {
    return this.object(import_Inputs.Inputs.ObjectRef(...args));
  }
  /**
   * Add a new receiving input to the transaction using the fully-resolved object reference.
   * If you only have an object ID, use `builder.object(id)` instead.
   */
  receivingRef(...args) {
    return this.object(import_Inputs.Inputs.ReceivingRef(...args));
  }
  /**
   * Add a new shared object input to the transaction using the fully-resolved shared object reference.
   * If you only have an object ID, use `builder.object(id)` instead.
   */
  sharedObjectRef(...args) {
    return this.object(import_Inputs.Inputs.SharedObjectRef(...args));
  }
  add(command) {
    if (typeof command === "function") {
      if (__privateGet(this, _added).has(command)) {
        return __privateGet(this, _added).get(command);
      }
      const fork = __privateMethod(this, _Transaction_instances, fork_fn).call(this);
      const result = command(fork);
      if (!(result && typeof result === "object" && "then" in result)) {
        __privateSet(this, _availableResults, __privateGet(fork, _availableResults));
        __privateGet(this, _added).set(command, result);
        return result;
      }
      const placeholder = __privateMethod(this, _Transaction_instances, addCommand_fn).call(this, {
        $kind: "$Intent",
        $Intent: {
          name: "AsyncTransactionThunk",
          inputs: {},
          data: {
            result: null
          }
        }
      });
      __privateGet(this, _pendingPromises).add(
        Promise.resolve(result).then((result2) => {
          placeholder.$Intent.data.result = result2;
        })
      );
      const txResult = createTransactionResult(__privateGet(this, _data).commands.length - 1);
      __privateGet(this, _added).set(command, txResult);
      return txResult;
    } else {
      __privateMethod(this, _Transaction_instances, addCommand_fn).call(this, command);
    }
    return createTransactionResult(__privateGet(this, _data).commands.length - 1);
  }
  // Method shorthands:
  splitCoins(coin, amounts) {
    const command = import_Commands.Commands.SplitCoins(
      typeof coin === "string" ? this.object(coin) : __privateMethod(this, _Transaction_instances, resolveArgument_fn).call(this, coin),
      amounts.map(
        (amount) => typeof amount === "number" || typeof amount === "bigint" || typeof amount === "string" ? this.pure.u64(amount) : __privateMethod(this, _Transaction_instances, normalizeTransactionArgument_fn).call(this, amount)
      )
    );
    __privateMethod(this, _Transaction_instances, addCommand_fn).call(this, command);
    return createTransactionResult(__privateGet(this, _data).commands.length - 1, amounts.length);
  }
  mergeCoins(destination, sources) {
    return this.add(
      import_Commands.Commands.MergeCoins(
        this.object(destination),
        sources.map((src) => this.object(src))
      )
    );
  }
  publish({ modules, dependencies }) {
    return this.add(
      import_Commands.Commands.Publish({
        modules,
        dependencies
      })
    );
  }
  upgrade({
    modules,
    dependencies,
    package: packageId,
    ticket
  }) {
    return this.add(
      import_Commands.Commands.Upgrade({
        modules,
        dependencies,
        package: packageId,
        ticket: this.object(ticket)
      })
    );
  }
  moveCall({
    arguments: args,
    ...input
  }) {
    return this.add(
      import_Commands.Commands.MoveCall({
        ...input,
        arguments: args?.map((arg) => __privateMethod(this, _Transaction_instances, normalizeTransactionArgument_fn).call(this, arg))
      })
    );
  }
  transferObjects(objects, address) {
    return this.add(
      import_Commands.Commands.TransferObjects(
        objects.map((obj) => this.object(obj)),
        typeof address === "string" ? this.pure.address(address) : __privateMethod(this, _Transaction_instances, normalizeTransactionArgument_fn).call(this, address)
      )
    );
  }
  makeMoveVec({
    type,
    elements
  }) {
    return this.add(
      import_Commands.Commands.MakeMoveVec({
        type,
        elements: elements.map((obj) => this.object(obj))
      })
    );
  }
  /**
   * @deprecated Use toJSON instead.
   * For synchronous serialization, you can use `getData()`
   * */
  serialize() {
    return JSON.stringify((0, import_v1.serializeV1TransactionData)(__privateGet(this, _data).snapshot()));
  }
  async toJSON(options = {}) {
    await this.prepareForSerialization(options);
    return JSON.stringify(
      (0, import_valibot.parse)(import_v2.SerializedTransactionDataV2, __privateGet(this, _data).snapshot()),
      (_key, value) => typeof value === "bigint" ? value.toString() : value,
      2
    );
  }
  /** Build the transaction to BCS bytes, and sign it with the provided keypair. */
  async sign(options) {
    const { signer, ...buildOptions } = options;
    const bytes = await this.build(buildOptions);
    return signer.signTransaction(bytes);
  }
  /** Build the transaction to BCS bytes. */
  async build(options = {}) {
    await this.prepareForSerialization(options);
    await __privateMethod(this, _Transaction_instances, prepareBuild_fn).call(this, options);
    return __privateGet(this, _data).build({
      onlyTransactionKind: options.onlyTransactionKind
    });
  }
  /** Derive transaction digest */
  async getDigest(options = {}) {
    await __privateMethod(this, _Transaction_instances, prepareBuild_fn).call(this, options);
    return __privateGet(this, _data).getDigest();
  }
  async prepareForSerialization(options) {
    await __privateMethod(this, _Transaction_instances, waitForPendingTasks_fn).call(this);
    __privateMethod(this, _Transaction_instances, sortCommandsAndInputs_fn).call(this);
    const intents = /* @__PURE__ */ new Set();
    for (const command of __privateGet(this, _data).commands) {
      if (command.$Intent) {
        intents.add(command.$Intent.name);
      }
    }
    const steps = [...__privateGet(this, _serializationPlugins)];
    for (const intent of intents) {
      if (options.supportedIntents?.includes(intent)) {
        continue;
      }
      if (!__privateGet(this, _intentResolvers).has(intent)) {
        throw new Error(`Missing intent resolver for ${intent}`);
      }
      steps.push(__privateGet(this, _intentResolvers).get(intent));
    }
    await __privateMethod(this, _Transaction_instances, runPlugins_fn).call(this, steps, options);
  }
};
_serializationPlugins = new WeakMap();
_buildPlugins = new WeakMap();
_intentResolvers = new WeakMap();
_inputSection = new WeakMap();
_commandSection = new WeakMap();
_availableResults = new WeakMap();
_pendingPromises = new WeakMap();
_added = new WeakMap();
_data = new WeakMap();
_Transaction_instances = new WeakSet();
fork_fn = function() {
  const fork = new _Transaction();
  __privateSet(fork, _data, __privateGet(this, _data));
  __privateSet(fork, _serializationPlugins, __privateGet(this, _serializationPlugins));
  __privateSet(fork, _buildPlugins, __privateGet(this, _buildPlugins));
  __privateSet(fork, _intentResolvers, __privateGet(this, _intentResolvers));
  __privateSet(fork, _pendingPromises, __privateGet(this, _pendingPromises));
  __privateSet(fork, _availableResults, new Set(__privateGet(this, _availableResults)));
  __privateSet(fork, _added, __privateGet(this, _added));
  __privateGet(this, _inputSection).push(__privateGet(fork, _inputSection));
  __privateGet(this, _commandSection).push(__privateGet(fork, _commandSection));
  return fork;
};
addCommand_fn = function(command) {
  const resultIndex = __privateGet(this, _data).commands.length;
  __privateGet(this, _commandSection).push(command);
  __privateGet(this, _availableResults).add(resultIndex);
  __privateGet(this, _data).commands.push(command);
  __privateGet(this, _data).mapCommandArguments(resultIndex, (arg) => {
    if (arg.$kind === "Result" && !__privateGet(this, _availableResults).has(arg.Result)) {
      throw new Error(
        `Result { Result: ${arg.Result} } is not available to use the current transaction`
      );
    }
    if (arg.$kind === "NestedResult" && !__privateGet(this, _availableResults).has(arg.NestedResult[0])) {
      throw new Error(
        `Result { NestedResult: [${arg.NestedResult[0]}, ${arg.NestedResult[1]}] } is not available to use the current transaction`
      );
    }
    if (arg.$kind === "Input" && arg.Input >= __privateGet(this, _data).inputs.length) {
      throw new Error(
        `Input { Input: ${arg.Input} } references an input that does not exist in the current transaction`
      );
    }
    return arg;
  });
  return command;
};
addInput_fn = function(type, input) {
  __privateGet(this, _inputSection).push(input);
  return __privateGet(this, _data).addInput(type, input);
};
normalizeTransactionArgument_fn = function(arg) {
  if ((0, import_bcs.isSerializedBcs)(arg)) {
    return this.pure(arg);
  }
  return __privateMethod(this, _Transaction_instances, resolveArgument_fn).call(this, arg);
};
resolveArgument_fn = function(arg) {
  if (typeof arg === "function") {
    const resolved = this.add(arg);
    if (typeof resolved === "function") {
      return __privateMethod(this, _Transaction_instances, resolveArgument_fn).call(this, resolved);
    }
    return (0, import_valibot.parse)(import_internal.Argument, resolved);
  }
  return (0, import_valibot.parse)(import_internal.Argument, arg);
};
prepareBuild_fn = async function(options) {
  if (!options.onlyTransactionKind && !__privateGet(this, _data).sender) {
    throw new Error("Missing transaction sender");
  }
  await __privateMethod(this, _Transaction_instances, runPlugins_fn).call(this, [...__privateGet(this, _buildPlugins), import_json_rpc_resolver.resolveTransactionData], options);
};
runPlugins_fn = async function(plugins, options) {
  const createNext = (i) => {
    if (i >= plugins.length) {
      return () => {
      };
    }
    const plugin = plugins[i];
    return async () => {
      const next = createNext(i + 1);
      let calledNext = false;
      let nextResolved = false;
      await plugin(__privateGet(this, _data), options, async () => {
        if (calledNext) {
          throw new Error(`next() was call multiple times in TransactionPlugin ${i}`);
        }
        calledNext = true;
        await next();
        nextResolved = true;
      });
      if (!calledNext) {
        throw new Error(`next() was not called in TransactionPlugin ${i}`);
      }
      if (!nextResolved) {
        throw new Error(`next() was not awaited in TransactionPlugin ${i}`);
      }
    };
  };
  await createNext(0)();
  __privateSet(this, _inputSection, __privateGet(this, _data).inputs);
  __privateSet(this, _commandSection, __privateGet(this, _data).commands);
};
waitForPendingTasks_fn = async function() {
  while (__privateGet(this, _pendingPromises).size > 0) {
    const newPromise = Promise.all(__privateGet(this, _pendingPromises));
    __privateGet(this, _pendingPromises).clear();
    __privateGet(this, _pendingPromises).add(newPromise);
    await newPromise;
    __privateGet(this, _pendingPromises).delete(newPromise);
  }
};
sortCommandsAndInputs_fn = function() {
  const unorderedCommands = __privateGet(this, _data).commands;
  const unorderedInputs = __privateGet(this, _data).inputs;
  const orderedCommands = __privateGet(this, _commandSection).flat(Infinity);
  const orderedInputs = __privateGet(this, _inputSection).flat(Infinity);
  if (orderedCommands.length !== unorderedCommands.length) {
    throw new Error("Unexpected number of commands found in transaction data");
  }
  if (orderedInputs.length !== unorderedInputs.length) {
    throw new Error("Unexpected number of inputs found in transaction data");
  }
  const filteredCommands = orderedCommands.filter(
    (cmd) => cmd.$Intent?.name !== "AsyncTransactionThunk"
  );
  __privateGet(this, _data).commands = filteredCommands;
  __privateGet(this, _data).inputs = orderedInputs;
  __privateSet(this, _commandSection, filteredCommands);
  __privateSet(this, _inputSection, orderedInputs);
  function getOriginalIndex(index) {
    const command = unorderedCommands[index];
    if (command.$Intent?.name === "AsyncTransactionThunk") {
      const result = command.$Intent.data.result;
      if (result == null) {
        throw new Error("AsyncTransactionThunk has not been resolved");
      }
      return getOriginalIndex(result.Result);
    }
    const updated = filteredCommands.indexOf(command);
    if (updated === -1) {
      throw new Error("Unable to find original index for command");
    }
    return updated;
  }
  __privateGet(this, _data).mapArguments((arg) => {
    if (arg.$kind === "Input") {
      const updated = orderedInputs.indexOf(unorderedInputs[arg.Input]);
      if (updated === -1) {
        throw new Error("Input has not been resolved");
      }
      return { ...arg, Input: updated };
    } else if (arg.$kind === "Result") {
      const updated = getOriginalIndex(arg.Result);
      return { ...arg, Result: updated };
    } else if (arg.$kind === "NestedResult") {
      const updated = getOriginalIndex(arg.NestedResult[0]);
      return { ...arg, NestedResult: [updated, arg.NestedResult[1]] };
    }
    return arg;
  });
};
let Transaction = _Transaction;
//# sourceMappingURL=Transaction.js.map


/***/ }),

/***/ 1553:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var TransactionData_exports = {};
__export(TransactionData_exports, {
  TransactionDataBuilder: () => TransactionDataBuilder
});
module.exports = __toCommonJS(TransactionData_exports);
var import_bcs = __nccwpck_require__(8830);
var import_valibot = __nccwpck_require__(8275);
var import_bcs2 = __nccwpck_require__(6244);
var import_sui_types = __nccwpck_require__(4818);
var import_internal = __nccwpck_require__(6921);
var import_v1 = __nccwpck_require__(113);
var import_hash = __nccwpck_require__(7689);
function prepareSuiAddress(address) {
  return (0, import_sui_types.normalizeSuiAddress)(address).replace("0x", "");
}
class TransactionDataBuilder {
  constructor(clone) {
    this.version = 2;
    this.sender = clone?.sender ?? null;
    this.expiration = clone?.expiration ?? null;
    this.inputs = clone?.inputs ?? [];
    this.commands = clone?.commands ?? [];
    this.gasData = clone?.gasData ?? {
      budget: null,
      price: null,
      owner: null,
      payment: null
    };
  }
  static fromKindBytes(bytes) {
    const kind = import_bcs2.bcs.TransactionKind.parse(bytes);
    const programmableTx = kind.ProgrammableTransaction;
    if (!programmableTx) {
      throw new Error("Unable to deserialize from bytes.");
    }
    return TransactionDataBuilder.restore({
      version: 2,
      sender: null,
      expiration: null,
      gasData: {
        budget: null,
        owner: null,
        payment: null,
        price: null
      },
      inputs: programmableTx.inputs,
      commands: programmableTx.commands
    });
  }
  static fromBytes(bytes) {
    const rawData = import_bcs2.bcs.TransactionData.parse(bytes);
    const data = rawData?.V1;
    const programmableTx = data.kind.ProgrammableTransaction;
    if (!data || !programmableTx) {
      throw new Error("Unable to deserialize from bytes.");
    }
    return TransactionDataBuilder.restore({
      version: 2,
      sender: data.sender,
      expiration: data.expiration,
      gasData: data.gasData,
      inputs: programmableTx.inputs,
      commands: programmableTx.commands
    });
  }
  static restore(data) {
    if (data.version === 2) {
      return new TransactionDataBuilder((0, import_valibot.parse)(import_internal.TransactionData, data));
    } else {
      return new TransactionDataBuilder((0, import_valibot.parse)(import_internal.TransactionData, (0, import_v1.transactionDataFromV1)(data)));
    }
  }
  /**
   * Generate transaction digest.
   *
   * @param bytes BCS serialized transaction data
   * @returns transaction digest.
   */
  static getDigestFromBytes(bytes) {
    const hash = (0, import_hash.hashTypedData)("TransactionData", bytes);
    return (0, import_bcs.toBase58)(hash);
  }
  // @deprecated use gasData instead
  get gasConfig() {
    return this.gasData;
  }
  // @deprecated use gasData instead
  set gasConfig(value) {
    this.gasData = value;
  }
  build({
    maxSizeBytes = Infinity,
    overrides,
    onlyTransactionKind
  } = {}) {
    const inputs = this.inputs;
    const commands = this.commands;
    const kind = {
      ProgrammableTransaction: {
        inputs,
        commands
      }
    };
    if (onlyTransactionKind) {
      return import_bcs2.bcs.TransactionKind.serialize(kind, { maxSize: maxSizeBytes }).toBytes();
    }
    const expiration = overrides?.expiration ?? this.expiration;
    const sender = overrides?.sender ?? this.sender;
    const gasData = { ...this.gasData, ...overrides?.gasConfig, ...overrides?.gasData };
    if (!sender) {
      throw new Error("Missing transaction sender");
    }
    if (!gasData.budget) {
      throw new Error("Missing gas budget");
    }
    if (!gasData.payment) {
      throw new Error("Missing gas payment");
    }
    if (!gasData.price) {
      throw new Error("Missing gas price");
    }
    const transactionData = {
      sender: prepareSuiAddress(sender),
      expiration: expiration ? expiration : { None: true },
      gasData: {
        payment: gasData.payment,
        owner: prepareSuiAddress(this.gasData.owner ?? sender),
        price: BigInt(gasData.price),
        budget: BigInt(gasData.budget)
      },
      kind: {
        ProgrammableTransaction: {
          inputs,
          commands
        }
      }
    };
    return import_bcs2.bcs.TransactionData.serialize(
      { V1: transactionData },
      { maxSize: maxSizeBytes }
    ).toBytes();
  }
  addInput(type, arg) {
    const index = this.inputs.length;
    this.inputs.push(arg);
    return { Input: index, type, $kind: "Input" };
  }
  getInputUses(index, fn) {
    this.mapArguments((arg, command) => {
      if (arg.$kind === "Input" && arg.Input === index) {
        fn(arg, command);
      }
      return arg;
    });
  }
  mapCommandArguments(index, fn) {
    const command = this.commands[index];
    switch (command.$kind) {
      case "MoveCall":
        command.MoveCall.arguments = command.MoveCall.arguments.map(
          (arg) => fn(arg, command, index)
        );
        break;
      case "TransferObjects":
        command.TransferObjects.objects = command.TransferObjects.objects.map(
          (arg) => fn(arg, command, index)
        );
        command.TransferObjects.address = fn(command.TransferObjects.address, command, index);
        break;
      case "SplitCoins":
        command.SplitCoins.coin = fn(command.SplitCoins.coin, command, index);
        command.SplitCoins.amounts = command.SplitCoins.amounts.map(
          (arg) => fn(arg, command, index)
        );
        break;
      case "MergeCoins":
        command.MergeCoins.destination = fn(command.MergeCoins.destination, command, index);
        command.MergeCoins.sources = command.MergeCoins.sources.map(
          (arg) => fn(arg, command, index)
        );
        break;
      case "MakeMoveVec":
        command.MakeMoveVec.elements = command.MakeMoveVec.elements.map(
          (arg) => fn(arg, command, index)
        );
        break;
      case "Upgrade":
        command.Upgrade.ticket = fn(command.Upgrade.ticket, command, index);
        break;
      case "$Intent":
        const inputs = command.$Intent.inputs;
        command.$Intent.inputs = {};
        for (const [key, value] of Object.entries(inputs)) {
          command.$Intent.inputs[key] = Array.isArray(value) ? value.map((arg) => fn(arg, command, index)) : fn(value, command, index);
        }
        break;
      case "Publish":
        break;
      default:
        throw new Error(`Unexpected transaction kind: ${command.$kind}`);
    }
  }
  mapArguments(fn) {
    for (const commandIndex of this.commands.keys()) {
      this.mapCommandArguments(commandIndex, fn);
    }
  }
  replaceCommand(index, replacement, resultIndex = index) {
    if (!Array.isArray(replacement)) {
      this.commands[index] = replacement;
      return;
    }
    const sizeDiff = replacement.length - 1;
    this.commands.splice(index, 1, ...replacement);
    if (sizeDiff !== 0) {
      this.mapArguments((arg, _command, commandIndex) => {
        if (commandIndex < index + replacement.length) {
          return arg;
        }
        switch (arg.$kind) {
          case "Result":
            if (arg.Result === index) {
              arg.Result = resultIndex;
            }
            if (arg.Result > index) {
              arg.Result += sizeDiff;
            }
            break;
          case "NestedResult":
            if (arg.NestedResult[0] === index) {
              arg.NestedResult[0] = resultIndex;
            }
            if (arg.NestedResult[0] > index) {
              arg.NestedResult[0] += sizeDiff;
            }
            break;
        }
        return arg;
      });
    }
  }
  getDigest() {
    const bytes = this.build({ onlyTransactionKind: false });
    return TransactionDataBuilder.getDigestFromBytes(bytes);
  }
  snapshot() {
    return (0, import_valibot.parse)(import_internal.TransactionData, this);
  }
  shallowClone() {
    return new TransactionDataBuilder({
      version: this.version,
      sender: this.sender,
      expiration: this.expiration,
      gasData: {
        ...this.gasData
      },
      inputs: [...this.inputs],
      commands: [...this.commands]
    });
  }
}
//# sourceMappingURL=TransactionData.js.map


/***/ }),

/***/ 6921:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var internal_exports = {};
__export(internal_exports, {
  $Intent: () => $Intent,
  Argument: () => Argument,
  BCSBytes: () => BCSBytes,
  Command: () => Command,
  GasData: () => GasData,
  JsonU64: () => JsonU64,
  NormalizedCallArg: () => NormalizedCallArg,
  ObjectArg: () => ObjectArg,
  ObjectID: () => ObjectID,
  ObjectRef: () => ObjectRef,
  OpenMoveTypeSignature: () => OpenMoveTypeSignature,
  OpenMoveTypeSignatureBody: () => OpenMoveTypeSignatureBody,
  StructTag: () => StructTag,
  SuiAddress: () => SuiAddress,
  TransactionData: () => TransactionData,
  TransactionExpiration: () => TransactionExpiration,
  safeEnum: () => safeEnum
});
module.exports = __toCommonJS(internal_exports);
var import_valibot = __nccwpck_require__(8275);
var import_sui_types = __nccwpck_require__(4818);
function safeEnum(options) {
  const unionOptions = Object.entries(options).map(([key, value]) => (0, import_valibot.object)({ [key]: value }));
  return (0, import_valibot.pipe)(
    (0, import_valibot.union)(unionOptions),
    (0, import_valibot.transform)((value) => ({
      ...value,
      $kind: Object.keys(value)[0]
    }))
  );
}
const SuiAddress = (0, import_valibot.pipe)(
  (0, import_valibot.string)(),
  (0, import_valibot.transform)((value) => (0, import_sui_types.normalizeSuiAddress)(value)),
  (0, import_valibot.check)(import_sui_types.isValidSuiAddress)
);
const ObjectID = SuiAddress;
const BCSBytes = (0, import_valibot.string)();
const JsonU64 = (0, import_valibot.pipe)(
  (0, import_valibot.union)([(0, import_valibot.string)(), (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)())]),
  (0, import_valibot.check)((val) => {
    try {
      BigInt(val);
      return BigInt(val) >= 0 && BigInt(val) <= 18446744073709551615n;
    } catch {
      return false;
    }
  }, "Invalid u64")
);
const ObjectRef = (0, import_valibot.object)({
  objectId: SuiAddress,
  version: JsonU64,
  digest: (0, import_valibot.string)()
});
const Argument = (0, import_valibot.pipe)(
  (0, import_valibot.union)([
    (0, import_valibot.object)({ GasCoin: (0, import_valibot.literal)(true) }),
    (0, import_valibot.object)({ Input: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()), type: (0, import_valibot.optional)((0, import_valibot.literal)("pure")) }),
    (0, import_valibot.object)({ Input: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()), type: (0, import_valibot.optional)((0, import_valibot.literal)("object")) }),
    (0, import_valibot.object)({ Result: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()) }),
    (0, import_valibot.object)({ NestedResult: (0, import_valibot.tuple)([(0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()), (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)())]) })
  ]),
  (0, import_valibot.transform)((value) => ({
    ...value,
    $kind: Object.keys(value)[0]
  }))
  // Defined manually to add `type?: 'pure' | 'object'` to Input
);
const GasData = (0, import_valibot.object)({
  budget: (0, import_valibot.nullable)(JsonU64),
  price: (0, import_valibot.nullable)(JsonU64),
  owner: (0, import_valibot.nullable)(SuiAddress),
  payment: (0, import_valibot.nullable)((0, import_valibot.array)(ObjectRef))
});
const StructTag = (0, import_valibot.object)({
  address: (0, import_valibot.string)(),
  module: (0, import_valibot.string)(),
  name: (0, import_valibot.string)(),
  // type_params in rust, should be updated to use camelCase
  typeParams: (0, import_valibot.array)((0, import_valibot.string)())
});
const OpenMoveTypeSignatureBody = (0, import_valibot.union)([
  (0, import_valibot.literal)("address"),
  (0, import_valibot.literal)("bool"),
  (0, import_valibot.literal)("u8"),
  (0, import_valibot.literal)("u16"),
  (0, import_valibot.literal)("u32"),
  (0, import_valibot.literal)("u64"),
  (0, import_valibot.literal)("u128"),
  (0, import_valibot.literal)("u256"),
  (0, import_valibot.object)({ vector: (0, import_valibot.lazy)(() => OpenMoveTypeSignatureBody) }),
  (0, import_valibot.object)({
    datatype: (0, import_valibot.object)({
      package: (0, import_valibot.string)(),
      module: (0, import_valibot.string)(),
      type: (0, import_valibot.string)(),
      typeParameters: (0, import_valibot.array)((0, import_valibot.lazy)(() => OpenMoveTypeSignatureBody))
    })
  }),
  (0, import_valibot.object)({ typeParameter: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()) })
]);
const OpenMoveTypeSignature = (0, import_valibot.object)({
  ref: (0, import_valibot.nullable)((0, import_valibot.union)([(0, import_valibot.literal)("&"), (0, import_valibot.literal)("&mut")])),
  body: OpenMoveTypeSignatureBody
});
const ProgrammableMoveCall = (0, import_valibot.object)({
  package: ObjectID,
  module: (0, import_valibot.string)(),
  function: (0, import_valibot.string)(),
  // snake case in rust
  typeArguments: (0, import_valibot.array)((0, import_valibot.string)()),
  arguments: (0, import_valibot.array)(Argument),
  _argumentTypes: (0, import_valibot.optional)((0, import_valibot.nullable)((0, import_valibot.array)(OpenMoveTypeSignature)))
});
const $Intent = (0, import_valibot.object)({
  name: (0, import_valibot.string)(),
  inputs: (0, import_valibot.record)((0, import_valibot.string)(), (0, import_valibot.union)([Argument, (0, import_valibot.array)(Argument)])),
  data: (0, import_valibot.record)((0, import_valibot.string)(), (0, import_valibot.unknown)())
});
const Command = safeEnum({
  MoveCall: ProgrammableMoveCall,
  TransferObjects: (0, import_valibot.object)({
    objects: (0, import_valibot.array)(Argument),
    address: Argument
  }),
  SplitCoins: (0, import_valibot.object)({
    coin: Argument,
    amounts: (0, import_valibot.array)(Argument)
  }),
  MergeCoins: (0, import_valibot.object)({
    destination: Argument,
    sources: (0, import_valibot.array)(Argument)
  }),
  Publish: (0, import_valibot.object)({
    modules: (0, import_valibot.array)(BCSBytes),
    dependencies: (0, import_valibot.array)(ObjectID)
  }),
  MakeMoveVec: (0, import_valibot.object)({
    type: (0, import_valibot.nullable)((0, import_valibot.string)()),
    elements: (0, import_valibot.array)(Argument)
  }),
  Upgrade: (0, import_valibot.object)({
    modules: (0, import_valibot.array)(BCSBytes),
    dependencies: (0, import_valibot.array)(ObjectID),
    package: ObjectID,
    ticket: Argument
  }),
  $Intent
});
const ObjectArg = safeEnum({
  ImmOrOwnedObject: ObjectRef,
  SharedObject: (0, import_valibot.object)({
    objectId: ObjectID,
    // snake case in rust
    initialSharedVersion: JsonU64,
    mutable: (0, import_valibot.boolean)()
  }),
  Receiving: ObjectRef
});
const CallArg = safeEnum({
  Object: ObjectArg,
  Pure: (0, import_valibot.object)({
    bytes: BCSBytes
  }),
  UnresolvedPure: (0, import_valibot.object)({
    value: (0, import_valibot.unknown)()
  }),
  UnresolvedObject: (0, import_valibot.object)({
    objectId: ObjectID,
    version: (0, import_valibot.optional)((0, import_valibot.nullable)(JsonU64)),
    digest: (0, import_valibot.optional)((0, import_valibot.nullable)((0, import_valibot.string)())),
    initialSharedVersion: (0, import_valibot.optional)((0, import_valibot.nullable)(JsonU64))
  })
});
const NormalizedCallArg = safeEnum({
  Object: ObjectArg,
  Pure: (0, import_valibot.object)({
    bytes: BCSBytes
  })
});
const TransactionExpiration = safeEnum({
  None: (0, import_valibot.literal)(true),
  Epoch: JsonU64
});
const TransactionData = (0, import_valibot.object)({
  version: (0, import_valibot.literal)(2),
  sender: (0, import_valibot.nullish)(SuiAddress),
  expiration: (0, import_valibot.nullish)(TransactionExpiration),
  gasData: GasData,
  inputs: (0, import_valibot.array)(CallArg),
  commands: (0, import_valibot.array)(Command)
});
//# sourceMappingURL=internal.js.map


/***/ }),

/***/ 113:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var v1_exports = {};
__export(v1_exports, {
  NormalizedCallArg: () => NormalizedCallArg,
  ObjectRef: () => ObjectRef,
  SerializedTransactionDataV1: () => SerializedTransactionDataV1,
  StructTag: () => StructTag,
  TransactionArgument: () => TransactionArgument,
  TypeTag: () => TypeTag,
  serializeV1TransactionData: () => serializeV1TransactionData,
  transactionDataFromV1: () => transactionDataFromV1
});
module.exports = __toCommonJS(v1_exports);
var import_bcs = __nccwpck_require__(8830);
var import_valibot = __nccwpck_require__(8275);
var import_bcs2 = __nccwpck_require__(6244);
var import_internal = __nccwpck_require__(6921);
const ObjectRef = (0, import_valibot.object)({
  digest: (0, import_valibot.string)(),
  objectId: (0, import_valibot.string)(),
  version: (0, import_valibot.union)([(0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()), (0, import_valibot.string)(), (0, import_valibot.bigint)()])
});
const ObjectArg = (0, import_internal.safeEnum)({
  ImmOrOwned: ObjectRef,
  Shared: (0, import_valibot.object)({
    objectId: import_internal.ObjectID,
    initialSharedVersion: import_internal.JsonU64,
    mutable: (0, import_valibot.boolean)()
  }),
  Receiving: ObjectRef
});
const NormalizedCallArg = (0, import_internal.safeEnum)({
  Object: ObjectArg,
  Pure: (0, import_valibot.array)((0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()))
});
const TransactionInput = (0, import_valibot.union)([
  (0, import_valibot.object)({
    kind: (0, import_valibot.literal)("Input"),
    index: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()),
    value: (0, import_valibot.unknown)(),
    type: (0, import_valibot.optional)((0, import_valibot.literal)("object"))
  }),
  (0, import_valibot.object)({
    kind: (0, import_valibot.literal)("Input"),
    index: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()),
    value: (0, import_valibot.unknown)(),
    type: (0, import_valibot.literal)("pure")
  })
]);
const TransactionExpiration = (0, import_valibot.union)([
  (0, import_valibot.object)({ Epoch: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()) }),
  (0, import_valibot.object)({ None: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) })
]);
const StringEncodedBigint = (0, import_valibot.pipe)(
  (0, import_valibot.union)([(0, import_valibot.number)(), (0, import_valibot.string)(), (0, import_valibot.bigint)()]),
  (0, import_valibot.check)((val) => {
    if (!["string", "number", "bigint"].includes(typeof val)) return false;
    try {
      BigInt(val);
      return true;
    } catch {
      return false;
    }
  })
);
const TypeTag = (0, import_valibot.union)([
  (0, import_valibot.object)({ bool: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ u8: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ u64: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ u128: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ address: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ signer: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ vector: (0, import_valibot.lazy)(() => TypeTag) }),
  (0, import_valibot.object)({ struct: (0, import_valibot.lazy)(() => StructTag) }),
  (0, import_valibot.object)({ u16: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ u32: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) }),
  (0, import_valibot.object)({ u256: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) })
]);
const StructTag = (0, import_valibot.object)({
  address: (0, import_valibot.string)(),
  module: (0, import_valibot.string)(),
  name: (0, import_valibot.string)(),
  typeParams: (0, import_valibot.array)(TypeTag)
});
const GasConfig = (0, import_valibot.object)({
  budget: (0, import_valibot.optional)(StringEncodedBigint),
  price: (0, import_valibot.optional)(StringEncodedBigint),
  payment: (0, import_valibot.optional)((0, import_valibot.array)(ObjectRef)),
  owner: (0, import_valibot.optional)((0, import_valibot.string)())
});
const TransactionArgumentTypes = [
  TransactionInput,
  (0, import_valibot.object)({ kind: (0, import_valibot.literal)("GasCoin") }),
  (0, import_valibot.object)({ kind: (0, import_valibot.literal)("Result"), index: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()) }),
  (0, import_valibot.object)({
    kind: (0, import_valibot.literal)("NestedResult"),
    index: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()),
    resultIndex: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)())
  })
];
const TransactionArgument = (0, import_valibot.union)([...TransactionArgumentTypes]);
const MoveCallTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("MoveCall"),
  target: (0, import_valibot.pipe)(
    (0, import_valibot.string)(),
    (0, import_valibot.check)((target) => target.split("::").length === 3)
  ),
  typeArguments: (0, import_valibot.array)((0, import_valibot.string)()),
  arguments: (0, import_valibot.array)(TransactionArgument)
});
const TransferObjectsTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("TransferObjects"),
  objects: (0, import_valibot.array)(TransactionArgument),
  address: TransactionArgument
});
const SplitCoinsTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("SplitCoins"),
  coin: TransactionArgument,
  amounts: (0, import_valibot.array)(TransactionArgument)
});
const MergeCoinsTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("MergeCoins"),
  destination: TransactionArgument,
  sources: (0, import_valibot.array)(TransactionArgument)
});
const MakeMoveVecTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("MakeMoveVec"),
  type: (0, import_valibot.union)([(0, import_valibot.object)({ Some: TypeTag }), (0, import_valibot.object)({ None: (0, import_valibot.nullable)((0, import_valibot.literal)(true)) })]),
  objects: (0, import_valibot.array)(TransactionArgument)
});
const PublishTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("Publish"),
  modules: (0, import_valibot.array)((0, import_valibot.array)((0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()))),
  dependencies: (0, import_valibot.array)((0, import_valibot.string)())
});
const UpgradeTransaction = (0, import_valibot.object)({
  kind: (0, import_valibot.literal)("Upgrade"),
  modules: (0, import_valibot.array)((0, import_valibot.array)((0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()))),
  dependencies: (0, import_valibot.array)((0, import_valibot.string)()),
  packageId: (0, import_valibot.string)(),
  ticket: TransactionArgument
});
const TransactionTypes = [
  MoveCallTransaction,
  TransferObjectsTransaction,
  SplitCoinsTransaction,
  MergeCoinsTransaction,
  PublishTransaction,
  UpgradeTransaction,
  MakeMoveVecTransaction
];
const TransactionType = (0, import_valibot.union)([...TransactionTypes]);
const SerializedTransactionDataV1 = (0, import_valibot.object)({
  version: (0, import_valibot.literal)(1),
  sender: (0, import_valibot.optional)((0, import_valibot.string)()),
  expiration: (0, import_valibot.nullish)(TransactionExpiration),
  gasConfig: GasConfig,
  inputs: (0, import_valibot.array)(TransactionInput),
  transactions: (0, import_valibot.array)(TransactionType)
});
function serializeV1TransactionData(transactionData) {
  const inputs = transactionData.inputs.map(
    (input, index) => {
      if (input.Object) {
        return {
          kind: "Input",
          index,
          value: {
            Object: input.Object.ImmOrOwnedObject ? {
              ImmOrOwned: input.Object.ImmOrOwnedObject
            } : input.Object.Receiving ? {
              Receiving: {
                digest: input.Object.Receiving.digest,
                version: input.Object.Receiving.version,
                objectId: input.Object.Receiving.objectId
              }
            } : {
              Shared: {
                mutable: input.Object.SharedObject.mutable,
                initialSharedVersion: input.Object.SharedObject.initialSharedVersion,
                objectId: input.Object.SharedObject.objectId
              }
            }
          },
          type: "object"
        };
      }
      if (input.Pure) {
        return {
          kind: "Input",
          index,
          value: {
            Pure: Array.from((0, import_bcs.fromBase64)(input.Pure.bytes))
          },
          type: "pure"
        };
      }
      if (input.UnresolvedPure) {
        return {
          kind: "Input",
          type: "pure",
          index,
          value: input.UnresolvedPure.value
        };
      }
      if (input.UnresolvedObject) {
        return {
          kind: "Input",
          type: "object",
          index,
          value: input.UnresolvedObject.objectId
        };
      }
      throw new Error("Invalid input");
    }
  );
  return {
    version: 1,
    sender: transactionData.sender ?? void 0,
    expiration: transactionData.expiration?.$kind === "Epoch" ? { Epoch: Number(transactionData.expiration.Epoch) } : transactionData.expiration ? { None: true } : null,
    gasConfig: {
      owner: transactionData.gasData.owner ?? void 0,
      budget: transactionData.gasData.budget ?? void 0,
      price: transactionData.gasData.price ?? void 0,
      payment: transactionData.gasData.payment ?? void 0
    },
    inputs,
    transactions: transactionData.commands.map((command) => {
      if (command.MakeMoveVec) {
        return {
          kind: "MakeMoveVec",
          type: command.MakeMoveVec.type === null ? { None: true } : { Some: import_bcs2.TypeTagSerializer.parseFromStr(command.MakeMoveVec.type) },
          objects: command.MakeMoveVec.elements.map(
            (arg) => convertTransactionArgument(arg, inputs)
          )
        };
      }
      if (command.MergeCoins) {
        return {
          kind: "MergeCoins",
          destination: convertTransactionArgument(command.MergeCoins.destination, inputs),
          sources: command.MergeCoins.sources.map((arg) => convertTransactionArgument(arg, inputs))
        };
      }
      if (command.MoveCall) {
        return {
          kind: "MoveCall",
          target: `${command.MoveCall.package}::${command.MoveCall.module}::${command.MoveCall.function}`,
          typeArguments: command.MoveCall.typeArguments,
          arguments: command.MoveCall.arguments.map(
            (arg) => convertTransactionArgument(arg, inputs)
          )
        };
      }
      if (command.Publish) {
        return {
          kind: "Publish",
          modules: command.Publish.modules.map((mod) => Array.from((0, import_bcs.fromBase64)(mod))),
          dependencies: command.Publish.dependencies
        };
      }
      if (command.SplitCoins) {
        return {
          kind: "SplitCoins",
          coin: convertTransactionArgument(command.SplitCoins.coin, inputs),
          amounts: command.SplitCoins.amounts.map((arg) => convertTransactionArgument(arg, inputs))
        };
      }
      if (command.TransferObjects) {
        return {
          kind: "TransferObjects",
          objects: command.TransferObjects.objects.map(
            (arg) => convertTransactionArgument(arg, inputs)
          ),
          address: convertTransactionArgument(command.TransferObjects.address, inputs)
        };
      }
      if (command.Upgrade) {
        return {
          kind: "Upgrade",
          modules: command.Upgrade.modules.map((mod) => Array.from((0, import_bcs.fromBase64)(mod))),
          dependencies: command.Upgrade.dependencies,
          packageId: command.Upgrade.package,
          ticket: convertTransactionArgument(command.Upgrade.ticket, inputs)
        };
      }
      throw new Error(`Unknown transaction ${Object.keys(command)}`);
    })
  };
}
function convertTransactionArgument(arg, inputs) {
  if (arg.$kind === "GasCoin") {
    return { kind: "GasCoin" };
  }
  if (arg.$kind === "Result") {
    return { kind: "Result", index: arg.Result };
  }
  if (arg.$kind === "NestedResult") {
    return { kind: "NestedResult", index: arg.NestedResult[0], resultIndex: arg.NestedResult[1] };
  }
  if (arg.$kind === "Input") {
    return inputs[arg.Input];
  }
  throw new Error(`Invalid argument ${Object.keys(arg)}`);
}
function transactionDataFromV1(data) {
  return (0, import_valibot.parse)(import_internal.TransactionData, {
    version: 2,
    sender: data.sender ?? null,
    expiration: data.expiration ? "Epoch" in data.expiration ? { Epoch: data.expiration.Epoch } : { None: true } : null,
    gasData: {
      owner: data.gasConfig.owner ?? null,
      budget: data.gasConfig.budget?.toString() ?? null,
      price: data.gasConfig.price?.toString() ?? null,
      payment: data.gasConfig.payment?.map((ref) => ({
        digest: ref.digest,
        objectId: ref.objectId,
        version: ref.version.toString()
      })) ?? null
    },
    inputs: data.inputs.map((input) => {
      if (input.kind === "Input") {
        if ((0, import_valibot.is)(NormalizedCallArg, input.value)) {
          const value = (0, import_valibot.parse)(NormalizedCallArg, input.value);
          if (value.Object) {
            if (value.Object.ImmOrOwned) {
              return {
                Object: {
                  ImmOrOwnedObject: {
                    objectId: value.Object.ImmOrOwned.objectId,
                    version: String(value.Object.ImmOrOwned.version),
                    digest: value.Object.ImmOrOwned.digest
                  }
                }
              };
            }
            if (value.Object.Shared) {
              return {
                Object: {
                  SharedObject: {
                    mutable: value.Object.Shared.mutable ?? null,
                    initialSharedVersion: value.Object.Shared.initialSharedVersion,
                    objectId: value.Object.Shared.objectId
                  }
                }
              };
            }
            if (value.Object.Receiving) {
              return {
                Object: {
                  Receiving: {
                    digest: value.Object.Receiving.digest,
                    version: String(value.Object.Receiving.version),
                    objectId: value.Object.Receiving.objectId
                  }
                }
              };
            }
            throw new Error("Invalid object input");
          }
          return {
            Pure: {
              bytes: (0, import_bcs.toBase64)(new Uint8Array(value.Pure))
            }
          };
        }
        if (input.type === "object") {
          return {
            UnresolvedObject: {
              objectId: input.value
            }
          };
        }
        return {
          UnresolvedPure: {
            value: input.value
          }
        };
      }
      throw new Error("Invalid input");
    }),
    commands: data.transactions.map((transaction) => {
      switch (transaction.kind) {
        case "MakeMoveVec":
          return {
            MakeMoveVec: {
              type: "Some" in transaction.type ? import_bcs2.TypeTagSerializer.tagToString(transaction.type.Some) : null,
              elements: transaction.objects.map((arg) => parseV1TransactionArgument(arg))
            }
          };
        case "MergeCoins": {
          return {
            MergeCoins: {
              destination: parseV1TransactionArgument(transaction.destination),
              sources: transaction.sources.map((arg) => parseV1TransactionArgument(arg))
            }
          };
        }
        case "MoveCall": {
          const [pkg, mod, fn] = transaction.target.split("::");
          return {
            MoveCall: {
              package: pkg,
              module: mod,
              function: fn,
              typeArguments: transaction.typeArguments,
              arguments: transaction.arguments.map((arg) => parseV1TransactionArgument(arg))
            }
          };
        }
        case "Publish": {
          return {
            Publish: {
              modules: transaction.modules.map((mod) => (0, import_bcs.toBase64)(Uint8Array.from(mod))),
              dependencies: transaction.dependencies
            }
          };
        }
        case "SplitCoins": {
          return {
            SplitCoins: {
              coin: parseV1TransactionArgument(transaction.coin),
              amounts: transaction.amounts.map((arg) => parseV1TransactionArgument(arg))
            }
          };
        }
        case "TransferObjects": {
          return {
            TransferObjects: {
              objects: transaction.objects.map((arg) => parseV1TransactionArgument(arg)),
              address: parseV1TransactionArgument(transaction.address)
            }
          };
        }
        case "Upgrade": {
          return {
            Upgrade: {
              modules: transaction.modules.map((mod) => (0, import_bcs.toBase64)(Uint8Array.from(mod))),
              dependencies: transaction.dependencies,
              package: transaction.packageId,
              ticket: parseV1TransactionArgument(transaction.ticket)
            }
          };
        }
      }
      throw new Error(`Unknown transaction ${Object.keys(transaction)}`);
    })
  });
}
function parseV1TransactionArgument(arg) {
  switch (arg.kind) {
    case "GasCoin": {
      return { GasCoin: true };
    }
    case "Result":
      return { Result: arg.index };
    case "NestedResult": {
      return { NestedResult: [arg.index, arg.resultIndex] };
    }
    case "Input": {
      return { Input: arg.index };
    }
  }
}
//# sourceMappingURL=v1.js.map


/***/ }),

/***/ 3768:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var v2_exports = {};
__export(v2_exports, {
  SerializedTransactionDataV2: () => SerializedTransactionDataV2
});
module.exports = __toCommonJS(v2_exports);
var import_valibot = __nccwpck_require__(8275);
var import_internal = __nccwpck_require__(6921);
function enumUnion(options) {
  return (0, import_valibot.union)(
    Object.entries(options).map(([key, value]) => (0, import_valibot.object)({ [key]: value }))
  );
}
const Argument = enumUnion({
  GasCoin: (0, import_valibot.literal)(true),
  Input: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()),
  Result: (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()),
  NestedResult: (0, import_valibot.tuple)([(0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)()), (0, import_valibot.pipe)((0, import_valibot.number)(), (0, import_valibot.integer)())])
});
const GasData = (0, import_valibot.object)({
  budget: (0, import_valibot.nullable)(import_internal.JsonU64),
  price: (0, import_valibot.nullable)(import_internal.JsonU64),
  owner: (0, import_valibot.nullable)(import_internal.SuiAddress),
  payment: (0, import_valibot.nullable)((0, import_valibot.array)(import_internal.ObjectRef))
});
const ProgrammableMoveCall = (0, import_valibot.object)({
  package: import_internal.ObjectID,
  module: (0, import_valibot.string)(),
  function: (0, import_valibot.string)(),
  // snake case in rust
  typeArguments: (0, import_valibot.array)((0, import_valibot.string)()),
  arguments: (0, import_valibot.array)(Argument)
});
const $Intent = (0, import_valibot.object)({
  name: (0, import_valibot.string)(),
  inputs: (0, import_valibot.record)((0, import_valibot.string)(), (0, import_valibot.union)([Argument, (0, import_valibot.array)(Argument)])),
  data: (0, import_valibot.record)((0, import_valibot.string)(), (0, import_valibot.unknown)())
});
const Command = enumUnion({
  MoveCall: ProgrammableMoveCall,
  TransferObjects: (0, import_valibot.object)({
    objects: (0, import_valibot.array)(Argument),
    address: Argument
  }),
  SplitCoins: (0, import_valibot.object)({
    coin: Argument,
    amounts: (0, import_valibot.array)(Argument)
  }),
  MergeCoins: (0, import_valibot.object)({
    destination: Argument,
    sources: (0, import_valibot.array)(Argument)
  }),
  Publish: (0, import_valibot.object)({
    modules: (0, import_valibot.array)(import_internal.BCSBytes),
    dependencies: (0, import_valibot.array)(import_internal.ObjectID)
  }),
  MakeMoveVec: (0, import_valibot.object)({
    type: (0, import_valibot.nullable)((0, import_valibot.string)()),
    elements: (0, import_valibot.array)(Argument)
  }),
  Upgrade: (0, import_valibot.object)({
    modules: (0, import_valibot.array)(import_internal.BCSBytes),
    dependencies: (0, import_valibot.array)(import_internal.ObjectID),
    package: import_internal.ObjectID,
    ticket: Argument
  }),
  $Intent
});
const ObjectArg = enumUnion({
  ImmOrOwnedObject: import_internal.ObjectRef,
  SharedObject: (0, import_valibot.object)({
    objectId: import_internal.ObjectID,
    // snake case in rust
    initialSharedVersion: import_internal.JsonU64,
    mutable: (0, import_valibot.boolean)()
  }),
  Receiving: import_internal.ObjectRef
});
const CallArg = enumUnion({
  Object: ObjectArg,
  Pure: (0, import_valibot.object)({
    bytes: import_internal.BCSBytes
  }),
  UnresolvedPure: (0, import_valibot.object)({
    value: (0, import_valibot.unknown)()
  }),
  UnresolvedObject: (0, import_valibot.object)({
    objectId: import_internal.ObjectID,
    version: (0, import_valibot.optional)((0, import_valibot.nullable)(import_internal.JsonU64)),
    digest: (0, import_valibot.optional)((0, import_valibot.nullable)((0, import_valibot.string)())),
    initialSharedVersion: (0, import_valibot.optional)((0, import_valibot.nullable)(import_internal.JsonU64))
  })
});
const TransactionExpiration = enumUnion({
  None: (0, import_valibot.literal)(true),
  Epoch: import_internal.JsonU64
});
const SerializedTransactionDataV2 = (0, import_valibot.object)({
  version: (0, import_valibot.literal)(2),
  sender: (0, import_valibot.nullish)(import_internal.SuiAddress),
  expiration: (0, import_valibot.nullish)(TransactionExpiration),
  gasData: GasData,
  inputs: (0, import_valibot.array)(CallArg),
  commands: (0, import_valibot.array)(Command)
});
//# sourceMappingURL=v2.js.map


/***/ }),

/***/ 4474:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var caching_exports = {};
__export(caching_exports, {
  CachingTransactionExecutor: () => CachingTransactionExecutor
});
module.exports = __toCommonJS(caching_exports);
var import_bcs = __nccwpck_require__(6244);
var import_ObjectCache = __nccwpck_require__(7570);
var import_Transaction = __nccwpck_require__(2545);
var _client, _lastDigest;
class CachingTransactionExecutor {
  constructor({
    client,
    ...options
  }) {
    __privateAdd(this, _client);
    __privateAdd(this, _lastDigest, null);
    __privateSet(this, _client, client);
    this.cache = new import_ObjectCache.ObjectCache(options);
  }
  /**
   * Clears all Owned objects
   * Immutable objects, Shared objects, and Move function definitions will be preserved
   */
  async reset() {
    await Promise.all([
      this.cache.clearOwnedObjects(),
      this.cache.clearCustom(),
      this.waitForLastTransaction()
    ]);
  }
  async buildTransaction({
    transaction,
    ...options
  }) {
    transaction.addBuildPlugin(this.cache.asPlugin());
    return transaction.build({
      client: __privateGet(this, _client),
      ...options
    });
  }
  async executeTransaction({
    transaction,
    options,
    ...input
  }) {
    const bytes = (0, import_Transaction.isTransaction)(transaction) ? await this.buildTransaction({ transaction }) : transaction;
    const results = await __privateGet(this, _client).executeTransactionBlock({
      ...input,
      transactionBlock: bytes,
      options: {
        ...options,
        showRawEffects: true
      }
    });
    if (results.rawEffects) {
      const effects = import_bcs.bcs.TransactionEffects.parse(Uint8Array.from(results.rawEffects));
      await this.applyEffects(effects);
    }
    return results;
  }
  async signAndExecuteTransaction({
    options,
    transaction,
    ...input
  }) {
    transaction.setSenderIfNotSet(input.signer.toSuiAddress());
    const bytes = await this.buildTransaction({ transaction });
    const { signature } = await input.signer.signTransaction(bytes);
    const results = await this.executeTransaction({
      transaction: bytes,
      signature,
      options
    });
    return results;
  }
  async applyEffects(effects) {
    __privateSet(this, _lastDigest, effects.V2?.transactionDigest ?? null);
    await this.cache.applyEffects(effects);
  }
  async waitForLastTransaction() {
    if (__privateGet(this, _lastDigest)) {
      await __privateGet(this, _client).waitForTransaction({ digest: __privateGet(this, _lastDigest) });
      __privateSet(this, _lastDigest, null);
    }
  }
}
_client = new WeakMap();
_lastDigest = new WeakMap();
//# sourceMappingURL=caching.js.map


/***/ }),

/***/ 2024:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
var __privateWrapper = (obj, member, setter, getter) => ({
  set _(value) {
    __privateSet(obj, member, value, setter);
  },
  get _() {
    return __privateGet(obj, member, getter);
  }
});
var parallel_exports = {};
__export(parallel_exports, {
  ParallelTransactionExecutor: () => ParallelTransactionExecutor
});
module.exports = __toCommonJS(parallel_exports);
var import_bcs = __nccwpck_require__(8830);
var import_utils = __nccwpck_require__(5041);
var import_bcs2 = __nccwpck_require__(6244);
var import_Transaction = __nccwpck_require__(2545);
var import_TransactionData = __nccwpck_require__(1553);
var import_caching = __nccwpck_require__(4474);
var import_queue = __nccwpck_require__(8184);
var import_serial = __nccwpck_require__(6151);
var _signer, _client, _coinBatchSize, _initialCoinBalance, _minimumCoinBalance, _epochBoundaryWindow, _defaultGasBudget, _maxPoolSize, _sourceCoins, _coinPool, _cache, _objectIdQueues, _buildQueue, _executeQueue, _lastDigest, _cacheLock, _pendingTransactions, _gasPrice, _ParallelTransactionExecutor_instances, getUsedObjects_fn, execute_fn, updateCache_fn, waitForLastDigest_fn, getGasCoin_fn, getGasPrice_fn, refillCoinPool_fn;
const PARALLEL_EXECUTOR_DEFAULTS = {
  coinBatchSize: 20,
  initialCoinBalance: 200000000n,
  minimumCoinBalance: 50000000n,
  maxPoolSize: 50,
  epochBoundaryWindow: 1e3
};
class ParallelTransactionExecutor {
  constructor(options) {
    __privateAdd(this, _ParallelTransactionExecutor_instances);
    __privateAdd(this, _signer);
    __privateAdd(this, _client);
    __privateAdd(this, _coinBatchSize);
    __privateAdd(this, _initialCoinBalance);
    __privateAdd(this, _minimumCoinBalance);
    __privateAdd(this, _epochBoundaryWindow);
    __privateAdd(this, _defaultGasBudget);
    __privateAdd(this, _maxPoolSize);
    __privateAdd(this, _sourceCoins);
    __privateAdd(this, _coinPool, []);
    __privateAdd(this, _cache);
    __privateAdd(this, _objectIdQueues, /* @__PURE__ */ new Map());
    __privateAdd(this, _buildQueue, new import_queue.SerialQueue());
    __privateAdd(this, _executeQueue);
    __privateAdd(this, _lastDigest, null);
    __privateAdd(this, _cacheLock, null);
    __privateAdd(this, _pendingTransactions, 0);
    __privateAdd(this, _gasPrice, null);
    __privateSet(this, _signer, options.signer);
    __privateSet(this, _client, options.client);
    __privateSet(this, _coinBatchSize, options.coinBatchSize ?? PARALLEL_EXECUTOR_DEFAULTS.coinBatchSize);
    __privateSet(this, _initialCoinBalance, options.initialCoinBalance ?? PARALLEL_EXECUTOR_DEFAULTS.initialCoinBalance);
    __privateSet(this, _minimumCoinBalance, options.minimumCoinBalance ?? PARALLEL_EXECUTOR_DEFAULTS.minimumCoinBalance);
    __privateSet(this, _defaultGasBudget, options.defaultGasBudget ?? __privateGet(this, _minimumCoinBalance));
    __privateSet(this, _epochBoundaryWindow, options.epochBoundaryWindow ?? PARALLEL_EXECUTOR_DEFAULTS.epochBoundaryWindow);
    __privateSet(this, _maxPoolSize, options.maxPoolSize ?? PARALLEL_EXECUTOR_DEFAULTS.maxPoolSize);
    __privateSet(this, _cache, new import_caching.CachingTransactionExecutor({
      client: options.client,
      cache: options.cache
    }));
    __privateSet(this, _executeQueue, new import_queue.ParallelQueue(__privateGet(this, _maxPoolSize)));
    __privateSet(this, _sourceCoins, options.sourceCoins ? new Map(options.sourceCoins.map((id) => [id, null])) : null);
  }
  resetCache() {
    __privateSet(this, _gasPrice, null);
    return __privateMethod(this, _ParallelTransactionExecutor_instances, updateCache_fn).call(this, () => __privateGet(this, _cache).reset());
  }
  async waitForLastTransaction() {
    await __privateMethod(this, _ParallelTransactionExecutor_instances, updateCache_fn).call(this, () => __privateMethod(this, _ParallelTransactionExecutor_instances, waitForLastDigest_fn).call(this));
  }
  async executeTransaction(transaction, options, additionalSignatures = []) {
    const { promise, resolve, reject } = (0, import_utils.promiseWithResolvers)();
    const usedObjects = await __privateMethod(this, _ParallelTransactionExecutor_instances, getUsedObjects_fn).call(this, transaction);
    const execute = () => {
      __privateGet(this, _executeQueue).runTask(() => {
        const promise2 = __privateMethod(this, _ParallelTransactionExecutor_instances, execute_fn).call(this, transaction, usedObjects, options, additionalSignatures);
        return promise2.then(resolve, reject);
      });
    };
    const conflicts = /* @__PURE__ */ new Set();
    usedObjects.forEach((objectId) => {
      const queue = __privateGet(this, _objectIdQueues).get(objectId);
      if (queue) {
        conflicts.add(objectId);
        __privateGet(this, _objectIdQueues).get(objectId).push(() => {
          conflicts.delete(objectId);
          if (conflicts.size === 0) {
            execute();
          }
        });
      } else {
        __privateGet(this, _objectIdQueues).set(objectId, []);
      }
    });
    if (conflicts.size === 0) {
      execute();
    }
    return promise;
  }
}
_signer = new WeakMap();
_client = new WeakMap();
_coinBatchSize = new WeakMap();
_initialCoinBalance = new WeakMap();
_minimumCoinBalance = new WeakMap();
_epochBoundaryWindow = new WeakMap();
_defaultGasBudget = new WeakMap();
_maxPoolSize = new WeakMap();
_sourceCoins = new WeakMap();
_coinPool = new WeakMap();
_cache = new WeakMap();
_objectIdQueues = new WeakMap();
_buildQueue = new WeakMap();
_executeQueue = new WeakMap();
_lastDigest = new WeakMap();
_cacheLock = new WeakMap();
_pendingTransactions = new WeakMap();
_gasPrice = new WeakMap();
_ParallelTransactionExecutor_instances = new WeakSet();
getUsedObjects_fn = async function(transaction) {
  const usedObjects = /* @__PURE__ */ new Set();
  let serialized = false;
  transaction.addSerializationPlugin(async (blockData, _options, next) => {
    await next();
    if (serialized) {
      return;
    }
    serialized = true;
    blockData.inputs.forEach((input) => {
      if (input.Object?.ImmOrOwnedObject?.objectId) {
        usedObjects.add(input.Object.ImmOrOwnedObject.objectId);
      } else if (input.Object?.Receiving?.objectId) {
        usedObjects.add(input.Object.Receiving.objectId);
      } else if (input.UnresolvedObject?.objectId && !input.UnresolvedObject.initialSharedVersion) {
        usedObjects.add(input.UnresolvedObject.objectId);
      }
    });
  });
  await transaction.prepareForSerialization({ client: __privateGet(this, _client) });
  return usedObjects;
};
execute_fn = async function(transaction, usedObjects, options, additionalSignatures = []) {
  let gasCoin;
  try {
    transaction.setSenderIfNotSet(__privateGet(this, _signer).toSuiAddress());
    await __privateGet(this, _buildQueue).runTask(async () => {
      const data = transaction.getData();
      if (!data.gasData.price) {
        transaction.setGasPrice(await __privateMethod(this, _ParallelTransactionExecutor_instances, getGasPrice_fn).call(this));
      }
      transaction.setGasBudgetIfNotSet(__privateGet(this, _defaultGasBudget));
      await __privateMethod(this, _ParallelTransactionExecutor_instances, updateCache_fn).call(this);
      gasCoin = await __privateMethod(this, _ParallelTransactionExecutor_instances, getGasCoin_fn).call(this);
      __privateWrapper(this, _pendingTransactions)._++;
      transaction.setGasPayment([
        {
          objectId: gasCoin.id,
          version: gasCoin.version,
          digest: gasCoin.digest
        }
      ]);
      await __privateGet(this, _cache).buildTransaction({ transaction, onlyTransactionKind: true });
    });
    const bytes = await transaction.build({ client: __privateGet(this, _client) });
    const { signature } = await __privateGet(this, _signer).signTransaction(bytes);
    const results = await __privateGet(this, _cache).executeTransaction({
      transaction: bytes,
      signature: [signature, ...additionalSignatures],
      options: {
        ...options,
        showEffects: true
      }
    });
    const effectsBytes = Uint8Array.from(results.rawEffects);
    const effects = import_bcs2.bcs.TransactionEffects.parse(effectsBytes);
    const gasResult = (0, import_serial.getGasCoinFromEffects)(effects);
    const gasUsed = effects.V2?.gasUsed;
    if (gasCoin && gasUsed && gasResult.owner === __privateGet(this, _signer).toSuiAddress()) {
      const totalUsed = BigInt(gasUsed.computationCost) + BigInt(gasUsed.storageCost) + BigInt(gasUsed.storageCost) - BigInt(gasUsed.storageRebate);
      let usesGasCoin = false;
      new import_TransactionData.TransactionDataBuilder(transaction.getData()).mapArguments((arg) => {
        if (arg.$kind === "GasCoin") {
          usesGasCoin = true;
        }
        return arg;
      });
      if (!usesGasCoin && gasCoin.balance >= __privateGet(this, _minimumCoinBalance)) {
        __privateGet(this, _coinPool).push({
          id: gasResult.ref.objectId,
          version: gasResult.ref.version,
          digest: gasResult.ref.digest,
          balance: gasCoin.balance - totalUsed
        });
      } else {
        if (!__privateGet(this, _sourceCoins)) {
          __privateSet(this, _sourceCoins, /* @__PURE__ */ new Map());
        }
        __privateGet(this, _sourceCoins).set(gasResult.ref.objectId, gasResult.ref);
      }
    }
    __privateSet(this, _lastDigest, results.digest);
    return {
      digest: results.digest,
      effects: (0, import_bcs.toBase64)(effectsBytes),
      data: results
    };
  } catch (error) {
    if (gasCoin) {
      if (!__privateGet(this, _sourceCoins)) {
        __privateSet(this, _sourceCoins, /* @__PURE__ */ new Map());
      }
      __privateGet(this, _sourceCoins).set(gasCoin.id, null);
    }
    await __privateMethod(this, _ParallelTransactionExecutor_instances, updateCache_fn).call(this, async () => {
      await Promise.all([
        __privateGet(this, _cache).cache.deleteObjects([...usedObjects]),
        __privateMethod(this, _ParallelTransactionExecutor_instances, waitForLastDigest_fn).call(this)
      ]);
    });
    throw error;
  } finally {
    usedObjects.forEach((objectId) => {
      const queue = __privateGet(this, _objectIdQueues).get(objectId);
      if (queue && queue.length > 0) {
        queue.shift()();
      } else if (queue) {
        __privateGet(this, _objectIdQueues).delete(objectId);
      }
    });
    __privateWrapper(this, _pendingTransactions)._--;
  }
};
updateCache_fn = async function(fn) {
  if (__privateGet(this, _cacheLock)) {
    await __privateGet(this, _cacheLock);
  }
  __privateSet(this, _cacheLock, fn?.().then(
    () => {
      __privateSet(this, _cacheLock, null);
    },
    () => {
    }
  ) ?? null);
};
waitForLastDigest_fn = async function() {
  const digest = __privateGet(this, _lastDigest);
  if (digest) {
    __privateSet(this, _lastDigest, null);
    await __privateGet(this, _client).waitForTransaction({ digest });
  }
};
getGasCoin_fn = async function() {
  if (__privateGet(this, _coinPool).length === 0 && __privateGet(this, _pendingTransactions) <= __privateGet(this, _maxPoolSize)) {
    await __privateMethod(this, _ParallelTransactionExecutor_instances, refillCoinPool_fn).call(this);
  }
  if (__privateGet(this, _coinPool).length === 0) {
    throw new Error("No coins available");
  }
  const coin = __privateGet(this, _coinPool).shift();
  return coin;
};
getGasPrice_fn = async function() {
  const remaining = __privateGet(this, _gasPrice) ? __privateGet(this, _gasPrice).expiration - __privateGet(this, _epochBoundaryWindow) - Date.now() : 0;
  if (remaining > 0) {
    return __privateGet(this, _gasPrice).price;
  }
  if (__privateGet(this, _gasPrice)) {
    const timeToNextEpoch = Math.max(
      __privateGet(this, _gasPrice).expiration + __privateGet(this, _epochBoundaryWindow) - Date.now(),
      1e3
    );
    await new Promise((resolve) => setTimeout(resolve, timeToNextEpoch));
  }
  const state = await __privateGet(this, _client).getLatestSuiSystemState();
  __privateSet(this, _gasPrice, {
    price: BigInt(state.referenceGasPrice),
    expiration: Number.parseInt(state.epochStartTimestampMs, 10) + Number.parseInt(state.epochDurationMs, 10)
  });
  return __privateMethod(this, _ParallelTransactionExecutor_instances, getGasPrice_fn).call(this);
};
refillCoinPool_fn = async function() {
  const batchSize = Math.min(
    __privateGet(this, _coinBatchSize),
    __privateGet(this, _maxPoolSize) - (__privateGet(this, _coinPool).length + __privateGet(this, _pendingTransactions)) + 1
  );
  if (batchSize === 0) {
    return;
  }
  const txb = new import_Transaction.Transaction();
  const address = __privateGet(this, _signer).toSuiAddress();
  txb.setSender(address);
  if (__privateGet(this, _sourceCoins)) {
    const refs = [];
    const ids = [];
    for (const [id, ref] of __privateGet(this, _sourceCoins)) {
      if (ref) {
        refs.push(ref);
      } else {
        ids.push(id);
      }
    }
    if (ids.length > 0) {
      const coins = await __privateGet(this, _client).multiGetObjects({
        ids
      });
      refs.push(
        ...coins.filter((coin) => coin.data !== null).map(({ data }) => ({
          objectId: data.objectId,
          version: data.version,
          digest: data.digest
        }))
      );
    }
    txb.setGasPayment(refs);
    __privateSet(this, _sourceCoins, /* @__PURE__ */ new Map());
  }
  const amounts = new Array(batchSize).fill(__privateGet(this, _initialCoinBalance));
  const results = txb.splitCoins(txb.gas, amounts);
  const coinResults = [];
  for (let i = 0; i < amounts.length; i++) {
    coinResults.push(results[i]);
  }
  txb.transferObjects(coinResults, address);
  await this.waitForLastTransaction();
  const result = await __privateGet(this, _client).signAndExecuteTransaction({
    transaction: txb,
    signer: __privateGet(this, _signer),
    options: {
      showRawEffects: true
    }
  });
  const effects = import_bcs2.bcs.TransactionEffects.parse(Uint8Array.from(result.rawEffects));
  effects.V2?.changedObjects.forEach(([id, { outputState }], i) => {
    if (i === effects.V2?.gasObjectIndex || !outputState.ObjectWrite) {
      return;
    }
    __privateGet(this, _coinPool).push({
      id,
      version: effects.V2.lamportVersion,
      digest: outputState.ObjectWrite[0],
      balance: BigInt(__privateGet(this, _initialCoinBalance))
    });
  });
  if (!__privateGet(this, _sourceCoins)) {
    __privateSet(this, _sourceCoins, /* @__PURE__ */ new Map());
  }
  const gasObject = (0, import_serial.getGasCoinFromEffects)(effects).ref;
  __privateGet(this, _sourceCoins).set(gasObject.objectId, gasObject);
  await __privateGet(this, _client).waitForTransaction({ digest: result.digest });
};
//# sourceMappingURL=parallel.js.map


/***/ }),

/***/ 8184:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var queue_exports = {};
__export(queue_exports, {
  ParallelQueue: () => ParallelQueue,
  SerialQueue: () => SerialQueue
});
module.exports = __toCommonJS(queue_exports);
var _queue, _queue2;
class SerialQueue {
  constructor() {
    __privateAdd(this, _queue, []);
  }
  async runTask(task) {
    return new Promise((resolve, reject) => {
      __privateGet(this, _queue).push(() => {
        task().finally(() => {
          __privateGet(this, _queue).shift();
          if (__privateGet(this, _queue).length > 0) {
            __privateGet(this, _queue)[0]();
          }
        }).then(resolve, reject);
      });
      if (__privateGet(this, _queue).length === 1) {
        __privateGet(this, _queue)[0]();
      }
    });
  }
}
_queue = new WeakMap();
class ParallelQueue {
  constructor(maxTasks) {
    __privateAdd(this, _queue2, []);
    this.activeTasks = 0;
    this.maxTasks = maxTasks;
  }
  runTask(task) {
    return new Promise((resolve, reject) => {
      if (this.activeTasks < this.maxTasks) {
        this.activeTasks++;
        task().finally(() => {
          if (__privateGet(this, _queue2).length > 0) {
            __privateGet(this, _queue2).shift()();
          } else {
            this.activeTasks--;
          }
        }).then(resolve, reject);
      } else {
        __privateGet(this, _queue2).push(() => {
          task().finally(() => {
            if (__privateGet(this, _queue2).length > 0) {
              __privateGet(this, _queue2).shift()();
            } else {
              this.activeTasks--;
            }
          }).then(resolve, reject);
        });
      }
    });
  }
}
_queue2 = new WeakMap();
//# sourceMappingURL=queue.js.map


/***/ }),

/***/ 6151:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __typeError = (msg) => {
  throw TypeError(msg);
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var serial_exports = {};
__export(serial_exports, {
  SerialTransactionExecutor: () => SerialTransactionExecutor,
  getGasCoinFromEffects: () => getGasCoinFromEffects
});
module.exports = __toCommonJS(serial_exports);
var import_bcs = __nccwpck_require__(8830);
var import_Transaction = __nccwpck_require__(2545);
var import_caching = __nccwpck_require__(4474);
var import_queue = __nccwpck_require__(8184);
var _queue, _signer, _cache, _defaultGasBudget, _cacheGasCoin, _buildTransaction;
class SerialTransactionExecutor {
  constructor({
    signer,
    defaultGasBudget = 50000000n,
    ...options
  }) {
    __privateAdd(this, _queue, new import_queue.SerialQueue());
    __privateAdd(this, _signer);
    __privateAdd(this, _cache);
    __privateAdd(this, _defaultGasBudget);
    __privateAdd(this, _cacheGasCoin, async (effects) => {
      if (!effects.V2) {
        return;
      }
      const gasCoin = getGasCoinFromEffects(effects).ref;
      if (gasCoin) {
        __privateGet(this, _cache).cache.setCustom("gasCoin", gasCoin);
      } else {
        __privateGet(this, _cache).cache.deleteCustom("gasCoin");
      }
    });
    __privateAdd(this, _buildTransaction, async (transaction) => {
      const gasCoin = await __privateGet(this, _cache).cache.getCustom("gasCoin");
      const copy = import_Transaction.Transaction.from(transaction);
      if (gasCoin) {
        copy.setGasPayment([gasCoin]);
      }
      copy.setGasBudgetIfNotSet(__privateGet(this, _defaultGasBudget));
      copy.setSenderIfNotSet(__privateGet(this, _signer).toSuiAddress());
      return __privateGet(this, _cache).buildTransaction({ transaction: copy });
    });
    __privateSet(this, _signer, signer);
    __privateSet(this, _defaultGasBudget, defaultGasBudget);
    __privateSet(this, _cache, new import_caching.CachingTransactionExecutor({
      client: options.client,
      cache: options.cache,
      onEffects: (effects) => __privateGet(this, _cacheGasCoin).call(this, effects)
    }));
  }
  async applyEffects(effects) {
    return __privateGet(this, _cache).applyEffects(effects);
  }
  async buildTransaction(transaction) {
    return __privateGet(this, _queue).runTask(() => __privateGet(this, _buildTransaction).call(this, transaction));
  }
  resetCache() {
    return __privateGet(this, _cache).reset();
  }
  waitForLastTransaction() {
    return __privateGet(this, _cache).waitForLastTransaction();
  }
  executeTransaction(transaction, options, additionalSignatures = []) {
    return __privateGet(this, _queue).runTask(async () => {
      const bytes = (0, import_Transaction.isTransaction)(transaction) ? await __privateGet(this, _buildTransaction).call(this, transaction) : transaction;
      const { signature } = await __privateGet(this, _signer).signTransaction(bytes);
      const results = await __privateGet(this, _cache).executeTransaction({
        signature: [signature, ...additionalSignatures],
        transaction: bytes,
        options
      }).catch(async (error) => {
        await this.resetCache();
        throw error;
      });
      const effectsBytes = Uint8Array.from(results.rawEffects);
      return {
        digest: results.digest,
        effects: (0, import_bcs.toBase64)(effectsBytes),
        data: results
      };
    });
  }
}
_queue = new WeakMap();
_signer = new WeakMap();
_cache = new WeakMap();
_defaultGasBudget = new WeakMap();
_cacheGasCoin = new WeakMap();
_buildTransaction = new WeakMap();
function getGasCoinFromEffects(effects) {
  if (!effects.V2) {
    throw new Error("Unexpected effects version");
  }
  const gasObjectChange = effects.V2.changedObjects[effects.V2.gasObjectIndex];
  if (!gasObjectChange) {
    throw new Error("Gas object not found in effects");
  }
  const [objectId, { outputState }] = gasObjectChange;
  if (!outputState.ObjectWrite) {
    throw new Error("Unexpected gas object state");
  }
  const [digest, owner] = outputState.ObjectWrite;
  return {
    ref: {
      objectId,
      digest,
      version: effects.V2.lamportVersion
    },
    owner: owner.AddressOwner || owner.ObjectOwner
  };
}
//# sourceMappingURL=serial.js.map


/***/ }),

/***/ 7689:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var hash_exports = {};
__export(hash_exports, {
  hashTypedData: () => hashTypedData
});
module.exports = __toCommonJS(hash_exports);
var import_blake2b = __nccwpck_require__(5596);
function hashTypedData(typeTag, data) {
  const typeTagBytes = Array.from(`${typeTag}::`).map((e) => e.charCodeAt(0));
  const dataWithTag = new Uint8Array(typeTagBytes.length + data.length);
  dataWithTag.set(typeTagBytes);
  dataWithTag.set(data, typeTagBytes.length);
  return (0, import_blake2b.blake2b)(dataWithTag, { dkLen: 32 });
}
//# sourceMappingURL=hash.js.map


/***/ }),

/***/ 9417:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var transactions_exports = {};
__export(transactions_exports, {
  Arguments: () => import_Arguments.Arguments,
  AsyncCache: () => import_ObjectCache.AsyncCache,
  Commands: () => import_Commands.Commands,
  Inputs: () => import_Inputs.Inputs,
  ObjectCache: () => import_ObjectCache.ObjectCache,
  ParallelTransactionExecutor: () => import_parallel.ParallelTransactionExecutor,
  SerialTransactionExecutor: () => import_serial.SerialTransactionExecutor,
  Transaction: () => import_Transaction.Transaction,
  TransactionDataBuilder: () => import_TransactionData.TransactionDataBuilder,
  UpgradePolicy: () => import_Commands.UpgradePolicy,
  coinWithBalance: () => import_CoinWithBalance.coinWithBalance,
  getPureBcsSchema: () => import_serializer.getPureBcsSchema,
  isArgument: () => import_utils2.isArgument,
  isTransaction: () => import_Transaction.isTransaction,
  namedPackagesPlugin: () => import_NamedPackagesPlugin.namedPackagesPlugin,
  normalizedTypeToMoveTypeSignature: () => import_serializer.normalizedTypeToMoveTypeSignature
});
module.exports = __toCommonJS(transactions_exports);
var import_serializer = __nccwpck_require__(1649);
var import_Inputs = __nccwpck_require__(7484);
var import_Commands = __nccwpck_require__(8783);
var import_Transaction = __nccwpck_require__(2545);
var import_TransactionData = __nccwpck_require__(1553);
var import_ObjectCache = __nccwpck_require__(7570);
var import_serial = __nccwpck_require__(6151);
var import_parallel = __nccwpck_require__(2024);
var import_CoinWithBalance = __nccwpck_require__(9258);
var import_Arguments = __nccwpck_require__(4845);
var import_NamedPackagesPlugin = __nccwpck_require__(6153);
var import_utils2 = __nccwpck_require__(6500);
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 9258:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var CoinWithBalance_exports = {};
__export(CoinWithBalance_exports, {
  coinWithBalance: () => coinWithBalance
});
module.exports = __toCommonJS(CoinWithBalance_exports);
var import_valibot = __nccwpck_require__(8275);
var import_bcs = __nccwpck_require__(6244);
var import_sui_types = __nccwpck_require__(4818);
var import_Commands = __nccwpck_require__(8783);
var import_Inputs = __nccwpck_require__(7484);
var import_json_rpc_resolver = __nccwpck_require__(1700);
const COIN_WITH_BALANCE = "CoinWithBalance";
const SUI_TYPE = (0, import_sui_types.normalizeStructTag)("0x2::sui::SUI");
function coinWithBalance({
  type = SUI_TYPE,
  balance,
  useGasCoin = true
}) {
  let coinResult = null;
  return (tx) => {
    if (coinResult) {
      return coinResult;
    }
    tx.addIntentResolver(COIN_WITH_BALANCE, resolveCoinBalance);
    const coinType = type === "gas" ? type : (0, import_sui_types.normalizeStructTag)(type);
    coinResult = tx.add(
      import_Commands.Commands.Intent({
        name: COIN_WITH_BALANCE,
        inputs: {},
        data: {
          type: coinType === SUI_TYPE && useGasCoin ? "gas" : coinType,
          balance: BigInt(balance)
        }
      })
    );
    return coinResult;
  };
}
const CoinWithBalanceData = (0, import_valibot.object)({
  type: (0, import_valibot.string)(),
  balance: (0, import_valibot.bigint)()
});
async function resolveCoinBalance(transactionData, buildOptions, next) {
  const coinTypes = /* @__PURE__ */ new Set();
  const totalByType = /* @__PURE__ */ new Map();
  if (!transactionData.sender) {
    throw new Error("Sender must be set to resolve CoinWithBalance");
  }
  for (const command of transactionData.commands) {
    if (command.$kind === "$Intent" && command.$Intent.name === COIN_WITH_BALANCE) {
      const { type, balance } = (0, import_valibot.parse)(CoinWithBalanceData, command.$Intent.data);
      if (type !== "gas" && balance > 0n) {
        coinTypes.add(type);
      }
      totalByType.set(type, (totalByType.get(type) ?? 0n) + balance);
    }
  }
  const usedIds = /* @__PURE__ */ new Set();
  for (const input of transactionData.inputs) {
    if (input.Object?.ImmOrOwnedObject) {
      usedIds.add(input.Object.ImmOrOwnedObject.objectId);
    }
    if (input.UnresolvedObject?.objectId) {
      usedIds.add(input.UnresolvedObject.objectId);
    }
  }
  const coinsByType = /* @__PURE__ */ new Map();
  const client = (0, import_json_rpc_resolver.getClient)(buildOptions);
  await Promise.all(
    [...coinTypes].map(async (coinType) => {
      coinsByType.set(
        coinType,
        await getCoinsOfType({
          coinType,
          balance: totalByType.get(coinType),
          client,
          owner: transactionData.sender,
          usedIds
        })
      );
    })
  );
  const mergedCoins = /* @__PURE__ */ new Map();
  mergedCoins.set("gas", { $kind: "GasCoin", GasCoin: true });
  for (const [index, transaction] of transactionData.commands.entries()) {
    if (transaction.$kind !== "$Intent" || transaction.$Intent.name !== COIN_WITH_BALANCE) {
      continue;
    }
    const { type, balance } = transaction.$Intent.data;
    if (balance === 0n && type !== "gas") {
      transactionData.replaceCommand(
        index,
        import_Commands.Commands.MoveCall({ target: "0x2::coin::zero", typeArguments: [type] })
      );
      continue;
    }
    const commands = [];
    if (!mergedCoins.has(type)) {
      const [first, ...rest] = coinsByType.get(type).map(
        (coin) => transactionData.addInput(
          "object",
          import_Inputs.Inputs.ObjectRef({
            objectId: coin.coinObjectId,
            digest: coin.digest,
            version: coin.version
          })
        )
      );
      if (rest.length > 0) {
        commands.push(import_Commands.Commands.MergeCoins(first, rest));
      }
      mergedCoins.set(type, first);
    }
    commands.push(
      import_Commands.Commands.SplitCoins(mergedCoins.get(type), [
        transactionData.addInput("pure", import_Inputs.Inputs.Pure(import_bcs.bcs.u64().serialize(balance)))
      ])
    );
    transactionData.replaceCommand(index, commands);
    transactionData.mapArguments((arg) => {
      if (arg.$kind === "Result" && arg.Result === index) {
        return {
          $kind: "NestedResult",
          NestedResult: [index + commands.length - 1, 0]
        };
      }
      return arg;
    });
  }
  return next();
}
async function getCoinsOfType({
  coinType,
  balance,
  client,
  owner,
  usedIds
}) {
  let remainingBalance = balance;
  const coins = [];
  return loadMoreCoins();
  async function loadMoreCoins(cursor = null) {
    const { data, hasNextPage, nextCursor } = await client.getCoins({ owner, coinType, cursor });
    const sortedCoins = data.sort((a, b) => Number(BigInt(b.balance) - BigInt(a.balance)));
    for (const coin of sortedCoins) {
      if (usedIds.has(coin.coinObjectId)) {
        continue;
      }
      const coinBalance = BigInt(coin.balance);
      coins.push(coin);
      remainingBalance -= coinBalance;
      if (remainingBalance <= 0) {
        return coins;
      }
    }
    if (hasNextPage) {
      return loadMoreCoins(nextCursor);
    }
    throw new Error(`Not enough coins of type ${coinType} to satisfy requested balance`);
  }
}
//# sourceMappingURL=CoinWithBalance.js.map


/***/ }),

/***/ 1700:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var json_rpc_resolver_exports = {};
__export(json_rpc_resolver_exports, {
  getClient: () => getClient,
  resolveTransactionData: () => resolveTransactionData
});
module.exports = __toCommonJS(json_rpc_resolver_exports);
var import_valibot = __nccwpck_require__(8275);
var import_bcs = __nccwpck_require__(6244);
var import_utils = __nccwpck_require__(3973);
var import_internal = __nccwpck_require__(6921);
var import_Inputs = __nccwpck_require__(7484);
var import_serializer = __nccwpck_require__(1649);
var import_utils2 = __nccwpck_require__(5041);
const MAX_OBJECTS_PER_FETCH = 50;
const GAS_SAFE_OVERHEAD = 1000n;
const MAX_GAS = 5e10;
async function resolveTransactionData(transactionData, options, next) {
  await normalizeInputs(transactionData, options);
  await resolveObjectReferences(transactionData, options);
  if (!options.onlyTransactionKind) {
    await setGasPrice(transactionData, options);
    await setGasBudget(transactionData, options);
    await setGasPayment(transactionData, options);
  }
  await validate(transactionData);
  return await next();
}
async function setGasPrice(transactionData, options) {
  if (!transactionData.gasConfig.price) {
    transactionData.gasConfig.price = String(await getClient(options).getReferenceGasPrice());
  }
}
async function setGasBudget(transactionData, options) {
  if (transactionData.gasConfig.budget) {
    return;
  }
  const dryRunResult = await getClient(options).dryRunTransactionBlock({
    transactionBlock: transactionData.build({
      overrides: {
        gasData: {
          budget: String(MAX_GAS),
          payment: []
        }
      }
    })
  });
  if (dryRunResult.effects.status.status !== "success") {
    throw new Error(
      `Dry run failed, could not automatically determine a budget: ${dryRunResult.effects.status.error}`,
      { cause: dryRunResult }
    );
  }
  const safeOverhead = GAS_SAFE_OVERHEAD * BigInt(transactionData.gasConfig.price || 1n);
  const baseComputationCostWithOverhead = BigInt(dryRunResult.effects.gasUsed.computationCost) + safeOverhead;
  const gasBudget = baseComputationCostWithOverhead + BigInt(dryRunResult.effects.gasUsed.storageCost) - BigInt(dryRunResult.effects.gasUsed.storageRebate);
  transactionData.gasConfig.budget = String(
    gasBudget > baseComputationCostWithOverhead ? gasBudget : baseComputationCostWithOverhead
  );
}
async function setGasPayment(transactionData, options) {
  if (!transactionData.gasConfig.payment) {
    const coins = await getClient(options).getCoins({
      owner: transactionData.gasConfig.owner || transactionData.sender,
      coinType: import_utils.SUI_TYPE_ARG
    });
    const paymentCoins = coins.data.filter((coin) => {
      const matchingInput = transactionData.inputs.find((input) => {
        if (input.Object?.ImmOrOwnedObject) {
          return coin.coinObjectId === input.Object.ImmOrOwnedObject.objectId;
        }
        return false;
      });
      return !matchingInput;
    }).map((coin) => ({
      objectId: coin.coinObjectId,
      digest: coin.digest,
      version: coin.version
    }));
    if (!paymentCoins.length) {
      throw new Error("No valid gas coins found for the transaction.");
    }
    transactionData.gasConfig.payment = paymentCoins.map((payment) => (0, import_valibot.parse)(import_internal.ObjectRef, payment));
  }
}
async function resolveObjectReferences(transactionData, options) {
  const objectsToResolve = transactionData.inputs.filter((input) => {
    return input.UnresolvedObject && !(input.UnresolvedObject.version || input.UnresolvedObject?.initialSharedVersion);
  });
  const dedupedIds = [
    ...new Set(
      objectsToResolve.map((input) => (0, import_utils.normalizeSuiObjectId)(input.UnresolvedObject.objectId))
    )
  ];
  const objectChunks = dedupedIds.length ? (0, import_utils2.chunk)(dedupedIds, MAX_OBJECTS_PER_FETCH) : [];
  const resolved = (await Promise.all(
    objectChunks.map(
      (chunk2) => getClient(options).multiGetObjects({
        ids: chunk2,
        options: { showOwner: true }
      })
    )
  )).flat();
  const responsesById = new Map(
    dedupedIds.map((id, index) => {
      return [id, resolved[index]];
    })
  );
  const invalidObjects = Array.from(responsesById).filter(([_, obj]) => obj.error).map(([_, obj]) => JSON.stringify(obj.error));
  if (invalidObjects.length) {
    throw new Error(`The following input objects are invalid: ${invalidObjects.join(", ")}`);
  }
  const objects = resolved.map((object) => {
    if (object.error || !object.data) {
      throw new Error(`Failed to fetch object: ${object.error}`);
    }
    const owner = object.data.owner;
    const initialSharedVersion = owner && typeof owner === "object" && "Shared" in owner ? owner.Shared.initial_shared_version : null;
    return {
      objectId: object.data.objectId,
      digest: object.data.digest,
      version: object.data.version,
      initialSharedVersion
    };
  });
  const objectsById = new Map(
    dedupedIds.map((id, index) => {
      return [id, objects[index]];
    })
  );
  for (const [index, input] of transactionData.inputs.entries()) {
    if (!input.UnresolvedObject) {
      continue;
    }
    let updated;
    const id = (0, import_utils.normalizeSuiAddress)(input.UnresolvedObject.objectId);
    const object = objectsById.get(id);
    if (input.UnresolvedObject.initialSharedVersion ?? object?.initialSharedVersion) {
      updated = import_Inputs.Inputs.SharedObjectRef({
        objectId: id,
        initialSharedVersion: input.UnresolvedObject.initialSharedVersion || object?.initialSharedVersion,
        mutable: isUsedAsMutable(transactionData, index)
      });
    } else if (isUsedAsReceiving(transactionData, index)) {
      updated = import_Inputs.Inputs.ReceivingRef(
        {
          objectId: id,
          digest: input.UnresolvedObject.digest ?? object?.digest,
          version: input.UnresolvedObject.version ?? object?.version
        }
      );
    }
    transactionData.inputs[transactionData.inputs.indexOf(input)] = updated ?? import_Inputs.Inputs.ObjectRef({
      objectId: id,
      digest: input.UnresolvedObject.digest ?? object?.digest,
      version: input.UnresolvedObject.version ?? object?.version
    });
  }
}
async function normalizeInputs(transactionData, options) {
  const { inputs, commands } = transactionData;
  const moveCallsToResolve = [];
  const moveFunctionsToResolve = /* @__PURE__ */ new Set();
  commands.forEach((command) => {
    if (command.MoveCall) {
      if (command.MoveCall._argumentTypes) {
        return;
      }
      const inputs2 = command.MoveCall.arguments.map((arg) => {
        if (arg.$kind === "Input") {
          return transactionData.inputs[arg.Input];
        }
        return null;
      });
      const needsResolution = inputs2.some(
        (input) => input?.UnresolvedPure || input?.UnresolvedObject
      );
      if (needsResolution) {
        const functionName = `${command.MoveCall.package}::${command.MoveCall.module}::${command.MoveCall.function}`;
        moveFunctionsToResolve.add(functionName);
        moveCallsToResolve.push(command.MoveCall);
      }
    }
    switch (command.$kind) {
      case "SplitCoins":
        command.SplitCoins.amounts.forEach((amount) => {
          normalizeRawArgument(amount, import_bcs.bcs.U64, transactionData);
        });
        break;
      case "TransferObjects":
        normalizeRawArgument(command.TransferObjects.address, import_bcs.bcs.Address, transactionData);
        break;
    }
  });
  const moveFunctionParameters = /* @__PURE__ */ new Map();
  if (moveFunctionsToResolve.size > 0) {
    const client = getClient(options);
    await Promise.all(
      [...moveFunctionsToResolve].map(async (functionName) => {
        const [packageId, moduleId, functionId] = functionName.split("::");
        const def = await client.getNormalizedMoveFunction({
          package: packageId,
          module: moduleId,
          function: functionId
        });
        moveFunctionParameters.set(
          functionName,
          def.parameters.map((param) => (0, import_serializer.normalizedTypeToMoveTypeSignature)(param))
        );
      })
    );
  }
  if (moveCallsToResolve.length) {
    await Promise.all(
      moveCallsToResolve.map(async (moveCall) => {
        const parameters = moveFunctionParameters.get(
          `${moveCall.package}::${moveCall.module}::${moveCall.function}`
        );
        if (!parameters) {
          return;
        }
        const hasTxContext = parameters.length > 0 && (0, import_serializer.isTxContext)(parameters.at(-1));
        const params = hasTxContext ? parameters.slice(0, parameters.length - 1) : parameters;
        moveCall._argumentTypes = params;
      })
    );
  }
  commands.forEach((command) => {
    if (!command.MoveCall) {
      return;
    }
    const moveCall = command.MoveCall;
    const fnName = `${moveCall.package}::${moveCall.module}::${moveCall.function}`;
    const params = moveCall._argumentTypes;
    if (!params) {
      return;
    }
    if (params.length !== command.MoveCall.arguments.length) {
      throw new Error(`Incorrect number of arguments for ${fnName}`);
    }
    params.forEach((param, i) => {
      const arg = moveCall.arguments[i];
      if (arg.$kind !== "Input") return;
      const input = inputs[arg.Input];
      if (!input.UnresolvedPure && !input.UnresolvedObject) {
        return;
      }
      const inputValue = input.UnresolvedPure?.value ?? input.UnresolvedObject?.objectId;
      const schema = (0, import_serializer.getPureBcsSchema)(param.body);
      if (schema) {
        arg.type = "pure";
        inputs[inputs.indexOf(input)] = import_Inputs.Inputs.Pure(schema.serialize(inputValue));
        return;
      }
      if (typeof inputValue !== "string") {
        throw new Error(
          `Expect the argument to be an object id string, got ${JSON.stringify(
            inputValue,
            null,
            2
          )}`
        );
      }
      arg.type = "object";
      const unresolvedObject = input.UnresolvedPure ? {
        $kind: "UnresolvedObject",
        UnresolvedObject: {
          objectId: inputValue
        }
      } : input;
      inputs[arg.Input] = unresolvedObject;
    });
  });
}
function validate(transactionData) {
  transactionData.inputs.forEach((input, index) => {
    if (input.$kind !== "Object" && input.$kind !== "Pure") {
      throw new Error(
        `Input at index ${index} has not been resolved.  Expected a Pure or Object input, but found ${JSON.stringify(
          input
        )}`
      );
    }
  });
}
function normalizeRawArgument(arg, schema, transactionData) {
  if (arg.$kind !== "Input") {
    return;
  }
  const input = transactionData.inputs[arg.Input];
  if (input.$kind !== "UnresolvedPure") {
    return;
  }
  transactionData.inputs[arg.Input] = import_Inputs.Inputs.Pure(schema.serialize(input.UnresolvedPure.value));
}
function isUsedAsMutable(transactionData, index) {
  let usedAsMutable = false;
  transactionData.getInputUses(index, (arg, tx) => {
    if (tx.MoveCall && tx.MoveCall._argumentTypes) {
      const argIndex = tx.MoveCall.arguments.indexOf(arg);
      usedAsMutable = tx.MoveCall._argumentTypes[argIndex].ref !== "&" || usedAsMutable;
    }
    if (tx.$kind === "MakeMoveVec" || tx.$kind === "MergeCoins" || tx.$kind === "SplitCoins") {
      usedAsMutable = true;
    }
  });
  return usedAsMutable;
}
function isUsedAsReceiving(transactionData, index) {
  let usedAsReceiving = false;
  transactionData.getInputUses(index, (arg, tx) => {
    if (tx.MoveCall && tx.MoveCall._argumentTypes) {
      const argIndex = tx.MoveCall.arguments.indexOf(arg);
      usedAsReceiving = isReceivingType(tx.MoveCall._argumentTypes[argIndex]) || usedAsReceiving;
    }
  });
  return usedAsReceiving;
}
function isReceivingType(type) {
  if (typeof type.body !== "object" || !("datatype" in type.body)) {
    return false;
  }
  return type.body.datatype.package === "0x2" && type.body.datatype.module === "transfer" && type.body.datatype.type === "Receiving";
}
function getClient(options) {
  if (!options.client) {
    throw new Error(
      `No sui client passed to Transaction#build, but transaction data was not sufficient to build offline.`
    );
  }
  return options.client;
}
//# sourceMappingURL=json-rpc-resolver.js.map


/***/ }),

/***/ 3714:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var object_exports = {};
__export(object_exports, {
  createObjectMethods: () => createObjectMethods
});
module.exports = __toCommonJS(object_exports);
function createObjectMethods(makeObject) {
  function object(value) {
    return makeObject(value);
  }
  object.system = () => object("0x5");
  object.clock = () => object("0x6");
  object.random = () => object("0x8");
  object.denyList = () => object("0x403");
  object.option = ({ type, value }) => (tx) => tx.moveCall({
    typeArguments: [type],
    target: `0x1::option::${value === null ? "none" : "some"}`,
    arguments: value === null ? [] : [tx.object(value)]
  });
  return object;
}
//# sourceMappingURL=object.js.map


/***/ }),

/***/ 6153:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var NamedPackagesPlugin_exports = {};
__export(NamedPackagesPlugin_exports, {
  namedPackagesPlugin: () => namedPackagesPlugin
});
module.exports = __toCommonJS(NamedPackagesPlugin_exports);
var import_sui_types = __nccwpck_require__(4818);
var import_utils = __nccwpck_require__(1767);
const namedPackagesPlugin = ({
  url,
  pageSize = 50,
  overrides = { packages: {}, types: {} }
}) => {
  Object.keys(overrides.types).forEach((type) => {
    if ((0, import_sui_types.parseStructTag)(type).typeParams.length > 0)
      throw new Error(
        "Type overrides must be first-level only. If you want to supply generic types, just pass each type individually."
      );
  });
  const cache = overrides;
  return async (transactionData, _buildOptions, next) => {
    const names = (0, import_utils.findNamesInTransaction)(transactionData);
    const [packages, types] = await Promise.all([
      resolvePackages(
        names.packages.filter((x) => !cache.packages[x]),
        url,
        pageSize
      ),
      resolveTypes(
        [...(0, import_utils.getFirstLevelNamedTypes)(names.types)].filter((x) => !cache.types[x]),
        url,
        pageSize
      )
    ]);
    Object.assign(cache.packages, packages);
    Object.assign(cache.types, types);
    const composedTypes = (0, import_utils.populateNamedTypesFromCache)(names.types, cache.types);
    (0, import_utils.replaceNames)(transactionData, {
      packages: { ...cache.packages },
      // we include the "composed" type cache too.
      types: composedTypes
    });
    await next();
  };
  async function resolvePackages(packages, apiUrl, pageSize2) {
    if (packages.length === 0) return {};
    const batches = (0, import_utils.batch)(packages, pageSize2);
    const results = {};
    await Promise.all(
      batches.map(async (batch2) => {
        const response = await fetch(`${apiUrl}/v1/resolution/bulk`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            names: batch2
          })
        });
        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}));
          throw new Error(`Failed to resolve packages: ${errorBody?.message}`);
        }
        const data = await response.json();
        if (!data?.resolution) return;
        for (const pkg of Object.keys(data?.resolution)) {
          const pkgData = data.resolution[pkg]?.package_id;
          if (!pkgData) continue;
          results[pkg] = pkgData;
        }
      })
    );
    return results;
  }
  async function resolveTypes(types, apiUrl, pageSize2) {
    if (types.length === 0) return {};
    const batches = (0, import_utils.batch)(types, pageSize2);
    const results = {};
    await Promise.all(
      batches.map(async (batch2) => {
        const response = await fetch(`${apiUrl}/v1/struct-definition/bulk`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            types: batch2
          })
        });
        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}));
          throw new Error(`Failed to resolve types: ${errorBody?.message}`);
        }
        const data = await response.json();
        if (!data?.resolution) return;
        for (const type of Object.keys(data?.resolution)) {
          const typeData = data.resolution[type]?.type_tag;
          if (!typeData) continue;
          results[type] = typeData;
        }
      })
    );
    return results;
  }
};
//# sourceMappingURL=NamedPackagesPlugin.js.map


/***/ }),

/***/ 1767:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var utils_exports = {};
__export(utils_exports, {
  batch: () => batch,
  findNamesInTransaction: () => findNamesInTransaction,
  getFirstLevelNamedTypes: () => getFirstLevelNamedTypes,
  populateNamedTypesFromCache: () => populateNamedTypesFromCache,
  replaceNames: () => replaceNames
});
module.exports = __toCommonJS(utils_exports);
var import_move_registry = __nccwpck_require__(7514);
var import_sui_types = __nccwpck_require__(4818);
const NAME_SEPARATOR = "/";
function findNamesInTransaction(builder) {
  const packages = /* @__PURE__ */ new Set();
  const types = /* @__PURE__ */ new Set();
  for (const command of builder.commands) {
    if (command.MakeMoveVec?.type) {
      getNamesFromTypeList([command.MakeMoveVec.type]).forEach((type) => {
        types.add(type);
      });
      continue;
    }
    if (!("MoveCall" in command)) continue;
    const tx = command.MoveCall;
    if (!tx) continue;
    const pkg = tx.package.split("::")[0];
    if (hasMvrName(pkg)) {
      if (!(0, import_move_registry.isValidNamedPackage)(pkg)) throw new Error(`Invalid package name: ${pkg}`);
      packages.add(pkg);
    }
    getNamesFromTypeList(tx.typeArguments ?? []).forEach((type) => {
      types.add(type);
    });
  }
  return {
    packages: [...packages],
    types: [...types]
  };
}
function getFirstLevelNamedTypes(types) {
  const results = /* @__PURE__ */ new Set();
  for (const type of types) {
    findMvrNames(type).forEach((name) => results.add(name));
  }
  return results;
}
function findMvrNames(type) {
  const types = /* @__PURE__ */ new Set();
  if (typeof type === "string" && !hasMvrName(type)) return types;
  const tag = isStructTag(type) ? type : (0, import_sui_types.parseStructTag)(type);
  if (hasMvrName(tag.address)) types.add(`${tag.address}::${tag.module}::${tag.name}`);
  for (const param of tag.typeParams) {
    findMvrNames(param).forEach((name) => types.add(name));
  }
  return types;
}
function populateNamedTypesFromCache(types, typeCache) {
  const composedTypes = {};
  types.forEach((type) => {
    const normalized = (0, import_sui_types.normalizeStructTag)(findAndReplaceCachedTypes(type, typeCache));
    composedTypes[type] = normalized;
  });
  return composedTypes;
}
function findAndReplaceCachedTypes(tag, typeCache) {
  const type = isStructTag(tag) ? tag : (0, import_sui_types.parseStructTag)(tag);
  const typeTag = `${type.address}::${type.module}::${type.name}`;
  const cacheHit = typeCache[typeTag];
  return {
    ...type,
    address: cacheHit ? cacheHit.split("::")[0] : type.address,
    typeParams: type.typeParams.map((param) => findAndReplaceCachedTypes(param, typeCache))
  };
}
function replaceNames(builder, cache) {
  for (const command of builder.commands) {
    if (command.MakeMoveVec?.type) {
      if (!hasMvrName(command.MakeMoveVec.type)) continue;
      if (!cache.types[command.MakeMoveVec.type])
        throw new Error(`No resolution found for type: ${command.MakeMoveVec.type}`);
      command.MakeMoveVec.type = cache.types[command.MakeMoveVec.type];
    }
    const tx = command.MoveCall;
    if (!tx) continue;
    const nameParts = tx.package.split("::");
    const name = nameParts[0];
    if (hasMvrName(name) && !cache.packages[name])
      throw new Error(`No address found for package: ${name}`);
    if (hasMvrName(name)) {
      nameParts[0] = cache.packages[name];
      tx.package = nameParts.join("::");
    }
    const types = tx.typeArguments;
    if (!types) continue;
    for (let i = 0; i < types.length; i++) {
      if (!hasMvrName(types[i])) continue;
      if (!cache.types[types[i]]) throw new Error(`No resolution found for type: ${types[i]}`);
      types[i] = cache.types[types[i]];
    }
    tx.typeArguments = types;
  }
}
function batch(arr, size) {
  const batches = [];
  for (let i = 0; i < arr.length; i += size) {
    batches.push(arr.slice(i, i + size));
  }
  return batches;
}
function getNamesFromTypeList(types) {
  const names = /* @__PURE__ */ new Set();
  for (const type of types) {
    if (hasMvrName(type)) {
      if (!(0, import_move_registry.isValidNamedType)(type)) throw new Error(`Invalid type with names: ${type}`);
      names.add(type);
    }
  }
  return names;
}
function hasMvrName(nameOrType) {
  return nameOrType.includes(NAME_SEPARATOR) || nameOrType.includes("@") || nameOrType.includes(".sui");
}
function isStructTag(type) {
  return typeof type === "object" && "address" in type && "module" in type && "name" in type && "typeParams" in type;
}
//# sourceMappingURL=utils.js.map


/***/ }),

/***/ 59:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var pure_exports = {};
__export(pure_exports, {
  createPure: () => createPure
});
module.exports = __toCommonJS(pure_exports);
var import_bcs = __nccwpck_require__(8830);
var import_bcs2 = __nccwpck_require__(6244);
var import_pure = __nccwpck_require__(5388);
function createPure(makePure) {
  function pure(typeOrSerializedValue, value) {
    if (typeof typeOrSerializedValue === "string") {
      return makePure((0, import_pure.pureBcsSchemaFromTypeName)(typeOrSerializedValue).serialize(value));
    }
    if (typeOrSerializedValue instanceof Uint8Array || (0, import_bcs.isSerializedBcs)(typeOrSerializedValue)) {
      return makePure(typeOrSerializedValue);
    }
    throw new Error("tx.pure must be called either a bcs type name, or a serialized bcs value");
  }
  pure.u8 = (value) => makePure(import_bcs2.bcs.U8.serialize(value));
  pure.u16 = (value) => makePure(import_bcs2.bcs.U16.serialize(value));
  pure.u32 = (value) => makePure(import_bcs2.bcs.U32.serialize(value));
  pure.u64 = (value) => makePure(import_bcs2.bcs.U64.serialize(value));
  pure.u128 = (value) => makePure(import_bcs2.bcs.U128.serialize(value));
  pure.u256 = (value) => makePure(import_bcs2.bcs.U256.serialize(value));
  pure.bool = (value) => makePure(import_bcs2.bcs.Bool.serialize(value));
  pure.string = (value) => makePure(import_bcs2.bcs.String.serialize(value));
  pure.address = (value) => makePure(import_bcs2.bcs.Address.serialize(value));
  pure.id = pure.address;
  pure.vector = (type, value) => {
    return makePure(
      import_bcs2.bcs.vector((0, import_pure.pureBcsSchemaFromTypeName)(type)).serialize(value)
    );
  };
  pure.option = (type, value) => {
    return makePure(import_bcs2.bcs.option((0, import_pure.pureBcsSchemaFromTypeName)(type)).serialize(value));
  };
  return pure;
}
//# sourceMappingURL=pure.js.map


/***/ }),

/***/ 1649:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var serializer_exports = {};
__export(serializer_exports, {
  getPureBcsSchema: () => getPureBcsSchema,
  isTxContext: () => isTxContext,
  normalizedTypeToMoveTypeSignature: () => normalizedTypeToMoveTypeSignature,
  pureBcsSchemaFromOpenMoveTypeSignatureBody: () => pureBcsSchemaFromOpenMoveTypeSignatureBody
});
module.exports = __toCommonJS(serializer_exports);
var import_bcs = __nccwpck_require__(6244);
var import_utils = __nccwpck_require__(3973);
var import_sui_types = __nccwpck_require__(4818);
const OBJECT_MODULE_NAME = "object";
const ID_STRUCT_NAME = "ID";
const STD_ASCII_MODULE_NAME = "ascii";
const STD_ASCII_STRUCT_NAME = "String";
const STD_UTF8_MODULE_NAME = "string";
const STD_UTF8_STRUCT_NAME = "String";
const STD_OPTION_MODULE_NAME = "option";
const STD_OPTION_STRUCT_NAME = "Option";
function isTxContext(param) {
  const struct = typeof param.body === "object" && "datatype" in param.body ? param.body.datatype : null;
  return !!struct && (0, import_sui_types.normalizeSuiAddress)(struct.package) === (0, import_sui_types.normalizeSuiAddress)("0x2") && struct.module === "tx_context" && struct.type === "TxContext";
}
function getPureBcsSchema(typeSignature) {
  if (typeof typeSignature === "string") {
    switch (typeSignature) {
      case "address":
        return import_bcs.bcs.Address;
      case "bool":
        return import_bcs.bcs.Bool;
      case "u8":
        return import_bcs.bcs.U8;
      case "u16":
        return import_bcs.bcs.U16;
      case "u32":
        return import_bcs.bcs.U32;
      case "u64":
        return import_bcs.bcs.U64;
      case "u128":
        return import_bcs.bcs.U128;
      case "u256":
        return import_bcs.bcs.U256;
      default:
        throw new Error(`Unknown type signature ${typeSignature}`);
    }
  }
  if ("vector" in typeSignature) {
    if (typeSignature.vector === "u8") {
      return import_bcs.bcs.vector(import_bcs.bcs.U8).transform({
        input: (val) => typeof val === "string" ? new TextEncoder().encode(val) : val,
        output: (val) => val
      });
    }
    const type = getPureBcsSchema(typeSignature.vector);
    return type ? import_bcs.bcs.vector(type) : null;
  }
  if ("datatype" in typeSignature) {
    const pkg = (0, import_sui_types.normalizeSuiAddress)(typeSignature.datatype.package);
    if (pkg === (0, import_sui_types.normalizeSuiAddress)(import_utils.MOVE_STDLIB_ADDRESS)) {
      if (typeSignature.datatype.module === STD_ASCII_MODULE_NAME && typeSignature.datatype.type === STD_ASCII_STRUCT_NAME) {
        return import_bcs.bcs.String;
      }
      if (typeSignature.datatype.module === STD_UTF8_MODULE_NAME && typeSignature.datatype.type === STD_UTF8_STRUCT_NAME) {
        return import_bcs.bcs.String;
      }
      if (typeSignature.datatype.module === STD_OPTION_MODULE_NAME && typeSignature.datatype.type === STD_OPTION_STRUCT_NAME) {
        const type = getPureBcsSchema(typeSignature.datatype.typeParameters[0]);
        return type ? import_bcs.bcs.vector(type) : null;
      }
    }
    if (pkg === (0, import_sui_types.normalizeSuiAddress)(import_utils.SUI_FRAMEWORK_ADDRESS) && typeSignature.datatype.module === OBJECT_MODULE_NAME && typeSignature.datatype.type === ID_STRUCT_NAME) {
      return import_bcs.bcs.Address;
    }
  }
  return null;
}
function normalizedTypeToMoveTypeSignature(type) {
  if (typeof type === "object" && "Reference" in type) {
    return {
      ref: "&",
      body: normalizedTypeToMoveTypeSignatureBody(type.Reference)
    };
  }
  if (typeof type === "object" && "MutableReference" in type) {
    return {
      ref: "&mut",
      body: normalizedTypeToMoveTypeSignatureBody(type.MutableReference)
    };
  }
  return {
    ref: null,
    body: normalizedTypeToMoveTypeSignatureBody(type)
  };
}
function normalizedTypeToMoveTypeSignatureBody(type) {
  if (typeof type === "string") {
    switch (type) {
      case "Address":
        return "address";
      case "Bool":
        return "bool";
      case "U8":
        return "u8";
      case "U16":
        return "u16";
      case "U32":
        return "u32";
      case "U64":
        return "u64";
      case "U128":
        return "u128";
      case "U256":
        return "u256";
      default:
        throw new Error(`Unexpected type ${type}`);
    }
  }
  if ("Vector" in type) {
    return { vector: normalizedTypeToMoveTypeSignatureBody(type.Vector) };
  }
  if ("Struct" in type) {
    return {
      datatype: {
        package: type.Struct.address,
        module: type.Struct.module,
        type: type.Struct.name,
        typeParameters: type.Struct.typeArguments.map(normalizedTypeToMoveTypeSignatureBody)
      }
    };
  }
  if ("TypeParameter" in type) {
    return { typeParameter: type.TypeParameter };
  }
  throw new Error(`Unexpected type ${JSON.stringify(type)}`);
}
function pureBcsSchemaFromOpenMoveTypeSignatureBody(typeSignature) {
  if (typeof typeSignature === "string") {
    switch (typeSignature) {
      case "address":
        return import_bcs.bcs.Address;
      case "bool":
        return import_bcs.bcs.Bool;
      case "u8":
        return import_bcs.bcs.U8;
      case "u16":
        return import_bcs.bcs.U16;
      case "u32":
        return import_bcs.bcs.U32;
      case "u64":
        return import_bcs.bcs.U64;
      case "u128":
        return import_bcs.bcs.U128;
      case "u256":
        return import_bcs.bcs.U256;
      default:
        throw new Error(`Unknown type signature ${typeSignature}`);
    }
  }
  if ("vector" in typeSignature) {
    return import_bcs.bcs.vector(pureBcsSchemaFromOpenMoveTypeSignatureBody(typeSignature.vector));
  }
  throw new Error(`Expected pure typeSignature, but got ${JSON.stringify(typeSignature)}`);
}
//# sourceMappingURL=serializer.js.map


/***/ }),

/***/ 6500:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var utils_exports = {};
__export(utils_exports, {
  extractMutableReference: () => extractMutableReference,
  extractReference: () => extractReference,
  extractStructTag: () => extractStructTag,
  getIdFromCallArg: () => getIdFromCallArg,
  isArgument: () => isArgument
});
module.exports = __toCommonJS(utils_exports);
var import_valibot = __nccwpck_require__(8275);
var import_sui_types = __nccwpck_require__(4818);
var import_internal = __nccwpck_require__(6921);
function extractMutableReference(normalizedType) {
  return typeof normalizedType === "object" && "MutableReference" in normalizedType ? normalizedType.MutableReference : void 0;
}
function extractReference(normalizedType) {
  return typeof normalizedType === "object" && "Reference" in normalizedType ? normalizedType.Reference : void 0;
}
function extractStructTag(normalizedType) {
  if (typeof normalizedType === "object" && "Struct" in normalizedType) {
    return normalizedType;
  }
  const ref = extractReference(normalizedType);
  const mutRef = extractMutableReference(normalizedType);
  if (typeof ref === "object" && "Struct" in ref) {
    return ref;
  }
  if (typeof mutRef === "object" && "Struct" in mutRef) {
    return mutRef;
  }
  return void 0;
}
function getIdFromCallArg(arg) {
  if (typeof arg === "string") {
    return (0, import_sui_types.normalizeSuiAddress)(arg);
  }
  if (arg.Object) {
    if (arg.Object.ImmOrOwnedObject) {
      return (0, import_sui_types.normalizeSuiAddress)(arg.Object.ImmOrOwnedObject.objectId);
    }
    if (arg.Object.Receiving) {
      return (0, import_sui_types.normalizeSuiAddress)(arg.Object.Receiving.objectId);
    }
    return (0, import_sui_types.normalizeSuiAddress)(arg.Object.SharedObject.objectId);
  }
  if (arg.UnresolvedObject) {
    return (0, import_sui_types.normalizeSuiAddress)(arg.UnresolvedObject.objectId);
  }
  return void 0;
}
function isArgument(value) {
  return (0, import_valibot.is)(import_internal.Argument, value);
}
//# sourceMappingURL=utils.js.map


/***/ }),

/***/ 9260:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var constants_exports = {};
__export(constants_exports, {
  MIST_PER_SUI: () => MIST_PER_SUI,
  MOVE_STDLIB_ADDRESS: () => MOVE_STDLIB_ADDRESS,
  SUI_CLOCK_OBJECT_ID: () => SUI_CLOCK_OBJECT_ID,
  SUI_DECIMALS: () => SUI_DECIMALS,
  SUI_FRAMEWORK_ADDRESS: () => SUI_FRAMEWORK_ADDRESS,
  SUI_SYSTEM_ADDRESS: () => SUI_SYSTEM_ADDRESS,
  SUI_SYSTEM_MODULE_NAME: () => SUI_SYSTEM_MODULE_NAME,
  SUI_SYSTEM_STATE_OBJECT_ID: () => SUI_SYSTEM_STATE_OBJECT_ID,
  SUI_TYPE_ARG: () => SUI_TYPE_ARG
});
module.exports = __toCommonJS(constants_exports);
var import_sui_types = __nccwpck_require__(4818);
const SUI_DECIMALS = 9;
const MIST_PER_SUI = BigInt(1e9);
const MOVE_STDLIB_ADDRESS = "0x1";
const SUI_FRAMEWORK_ADDRESS = "0x2";
const SUI_SYSTEM_ADDRESS = "0x3";
const SUI_CLOCK_OBJECT_ID = (0, import_sui_types.normalizeSuiObjectId)("0x6");
const SUI_SYSTEM_MODULE_NAME = "sui_system";
const SUI_TYPE_ARG = `${SUI_FRAMEWORK_ADDRESS}::sui::SUI`;
const SUI_SYSTEM_STATE_OBJECT_ID = (0, import_sui_types.normalizeSuiObjectId)("0x5");
//# sourceMappingURL=constants.js.map


/***/ }),

/***/ 3100:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var dynamic_fields_exports = {};
__export(dynamic_fields_exports, {
  deriveDynamicFieldID: () => deriveDynamicFieldID
});
module.exports = __toCommonJS(dynamic_fields_exports);
var import_bcs = __nccwpck_require__(8830);
var import_blake2b = __nccwpck_require__(5596);
var import_bcs2 = __nccwpck_require__(6244);
function deriveDynamicFieldID(parentId, typeTag, key) {
  const address = import_bcs2.bcs.Address.serialize(parentId).toBytes();
  const tag = import_bcs2.bcs.TypeTag.serialize(typeTag).toBytes();
  const keyLength = import_bcs2.bcs.u64().serialize(key.length).toBytes();
  const hash = import_blake2b.blake2b.create({
    dkLen: 32
  });
  hash.update(new Uint8Array([240]));
  hash.update(address);
  hash.update(keyLength);
  hash.update(key);
  hash.update(tag);
  return `0x${(0, import_bcs.toHex)(hash.digest().slice(0, 32))}`;
}
//# sourceMappingURL=dynamic-fields.js.map


/***/ }),

/***/ 1918:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var format_exports = {};
__export(format_exports, {
  formatAddress: () => formatAddress,
  formatDigest: () => formatDigest
});
module.exports = __toCommonJS(format_exports);
const ELLIPSIS = "\u2026";
function formatAddress(address) {
  if (address.length <= 6) {
    return address;
  }
  const offset = address.startsWith("0x") ? 2 : 0;
  return `0x${address.slice(offset, offset + 4)}${ELLIPSIS}${address.slice(-4)}`;
}
function formatDigest(digest) {
  return `${digest.slice(0, 10)}${ELLIPSIS}`;
}
//# sourceMappingURL=format.js.map


/***/ }),

/***/ 3973:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var utils_exports = {};
__export(utils_exports, {
  MIST_PER_SUI: () => import_constants.MIST_PER_SUI,
  MOVE_STDLIB_ADDRESS: () => import_constants.MOVE_STDLIB_ADDRESS,
  SUI_ADDRESS_LENGTH: () => import_sui_types.SUI_ADDRESS_LENGTH,
  SUI_CLOCK_OBJECT_ID: () => import_constants.SUI_CLOCK_OBJECT_ID,
  SUI_DECIMALS: () => import_constants.SUI_DECIMALS,
  SUI_FRAMEWORK_ADDRESS: () => import_constants.SUI_FRAMEWORK_ADDRESS,
  SUI_SYSTEM_ADDRESS: () => import_constants.SUI_SYSTEM_ADDRESS,
  SUI_SYSTEM_MODULE_NAME: () => import_constants.SUI_SYSTEM_MODULE_NAME,
  SUI_SYSTEM_STATE_OBJECT_ID: () => import_constants.SUI_SYSTEM_STATE_OBJECT_ID,
  SUI_TYPE_ARG: () => import_constants.SUI_TYPE_ARG,
  deriveDynamicFieldID: () => import_dynamic_fields.deriveDynamicFieldID,
  formatAddress: () => import_format.formatAddress,
  formatDigest: () => import_format.formatDigest,
  fromB64: () => import_bcs.fromB64,
  fromBase58: () => import_bcs.fromBase58,
  fromBase64: () => import_bcs.fromBase64,
  fromHEX: () => import_bcs.fromHEX,
  fromHex: () => import_bcs.fromHex,
  isValidNamedPackage: () => import_move_registry.isValidNamedPackage,
  isValidNamedType: () => import_move_registry.isValidNamedType,
  isValidSuiAddress: () => import_sui_types.isValidSuiAddress,
  isValidSuiNSName: () => import_suins.isValidSuiNSName,
  isValidSuiObjectId: () => import_sui_types.isValidSuiObjectId,
  isValidTransactionDigest: () => import_sui_types.isValidTransactionDigest,
  normalizeStructTag: () => import_sui_types.normalizeStructTag,
  normalizeSuiAddress: () => import_sui_types.normalizeSuiAddress,
  normalizeSuiNSName: () => import_suins.normalizeSuiNSName,
  normalizeSuiObjectId: () => import_sui_types.normalizeSuiObjectId,
  parseStructTag: () => import_sui_types.parseStructTag,
  toB64: () => import_bcs.toB64,
  toBase58: () => import_bcs.toBase58,
  toBase64: () => import_bcs.toBase64,
  toHEX: () => import_bcs.toHEX,
  toHex: () => import_bcs.toHex
});
module.exports = __toCommonJS(utils_exports);
var import_format = __nccwpck_require__(1918);
var import_sui_types = __nccwpck_require__(4818);
var import_bcs = __nccwpck_require__(8830);
var import_suins = __nccwpck_require__(8593);
var import_constants = __nccwpck_require__(9260);
var import_move_registry = __nccwpck_require__(7514);
var import_dynamic_fields = __nccwpck_require__(3100);
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 7514:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var move_registry_exports = {};
__export(move_registry_exports, {
  isValidNamedPackage: () => isValidNamedPackage,
  isValidNamedType: () => isValidNamedType
});
module.exports = __toCommonJS(move_registry_exports);
var import_suins = __nccwpck_require__(8593);
const NAME_PATTERN = /^([a-z0-9]+(?:-[a-z0-9]+)*)$/;
const VERSION_REGEX = /^\d+$/;
const MAX_APP_SIZE = 64;
const NAME_SEPARATOR = "/";
const isValidNamedPackage = (name) => {
  const parts = name.split(NAME_SEPARATOR);
  if (parts.length < 2 || parts.length > 3) return false;
  const [org, app, version] = parts;
  if (version !== void 0 && !VERSION_REGEX.test(version)) return false;
  if (!(0, import_suins.isValidSuiNSName)(org)) return false;
  return NAME_PATTERN.test(app) && app.length < MAX_APP_SIZE;
};
const isValidNamedType = (type) => {
  const splitType = type.split(/::|<|>|,/);
  for (const t of splitType) {
    if (t.includes(NAME_SEPARATOR) && !isValidNamedPackage(t)) return false;
  }
  return true;
};
//# sourceMappingURL=move-registry.js.map


/***/ }),

/***/ 4818:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var sui_types_exports = {};
__export(sui_types_exports, {
  SUI_ADDRESS_LENGTH: () => SUI_ADDRESS_LENGTH,
  isValidSuiAddress: () => isValidSuiAddress,
  isValidSuiObjectId: () => isValidSuiObjectId,
  isValidTransactionDigest: () => isValidTransactionDigest,
  normalizeStructTag: () => normalizeStructTag,
  normalizeSuiAddress: () => normalizeSuiAddress,
  normalizeSuiObjectId: () => normalizeSuiObjectId,
  parseStructTag: () => parseStructTag
});
module.exports = __toCommonJS(sui_types_exports);
var import_bcs = __nccwpck_require__(8830);
var import_move_registry = __nccwpck_require__(7514);
const TX_DIGEST_LENGTH = 32;
function isValidTransactionDigest(value) {
  try {
    const buffer = (0, import_bcs.fromBase58)(value);
    return buffer.length === TX_DIGEST_LENGTH;
  } catch (e) {
    return false;
  }
}
const SUI_ADDRESS_LENGTH = 32;
function isValidSuiAddress(value) {
  return isHex(value) && getHexByteLength(value) === SUI_ADDRESS_LENGTH;
}
function isValidSuiObjectId(value) {
  return isValidSuiAddress(value);
}
function parseTypeTag(type) {
  if (!type.includes("::")) return type;
  return parseStructTag(type);
}
function parseStructTag(type) {
  const [address, module2] = type.split("::");
  const isMvrPackage = (0, import_move_registry.isValidNamedPackage)(address);
  const rest = type.slice(address.length + module2.length + 4);
  const name = rest.includes("<") ? rest.slice(0, rest.indexOf("<")) : rest;
  const typeParams = rest.includes("<") ? (0, import_bcs.splitGenericParameters)(rest.slice(rest.indexOf("<") + 1, rest.lastIndexOf(">"))).map(
    (typeParam) => parseTypeTag(typeParam.trim())
  ) : [];
  return {
    address: isMvrPackage ? address : normalizeSuiAddress(address),
    module: module2,
    name,
    typeParams
  };
}
function normalizeStructTag(type) {
  const { address, module: module2, name, typeParams } = typeof type === "string" ? parseStructTag(type) : type;
  const formattedTypeParams = typeParams?.length > 0 ? `<${typeParams.map(
    (typeParam) => typeof typeParam === "string" ? typeParam : normalizeStructTag(typeParam)
  ).join(",")}>` : "";
  return `${address}::${module2}::${name}${formattedTypeParams}`;
}
function normalizeSuiAddress(value, forceAdd0x = false) {
  let address = value.toLowerCase();
  if (!forceAdd0x && address.startsWith("0x")) {
    address = address.slice(2);
  }
  return `0x${address.padStart(SUI_ADDRESS_LENGTH * 2, "0")}`;
}
function normalizeSuiObjectId(value, forceAdd0x = false) {
  return normalizeSuiAddress(value, forceAdd0x);
}
function isHex(value) {
  return /^(0x|0X)?[a-fA-F0-9]+$/.test(value) && value.length % 2 === 0;
}
function getHexByteLength(value) {
  return /^(0x|0X)/.test(value) ? (value.length - 2) / 2 : value.length / 2;
}
//# sourceMappingURL=sui-types.js.map


/***/ }),

/***/ 8593:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var suins_exports = {};
__export(suins_exports, {
  isValidSuiNSName: () => isValidSuiNSName,
  normalizeSuiNSName: () => normalizeSuiNSName
});
module.exports = __toCommonJS(suins_exports);
const SUI_NS_NAME_REGEX = /^(?!.*(^(?!@)|[-.@])($|[-.@]))(?:[a-z0-9-]{0,63}(?:\.[a-z0-9-]{0,63})*)?@[a-z0-9-]{0,63}$/i;
const SUI_NS_DOMAIN_REGEX = /^(?!.*(^|[-.])($|[-.]))(?:[a-z0-9-]{0,63}\.)+sui$/i;
const MAX_SUI_NS_NAME_LENGTH = 235;
function isValidSuiNSName(name) {
  if (name.length > MAX_SUI_NS_NAME_LENGTH) {
    return false;
  }
  if (name.includes("@")) {
    return SUI_NS_NAME_REGEX.test(name);
  }
  return SUI_NS_DOMAIN_REGEX.test(name);
}
function normalizeSuiNSName(name, format = "at") {
  const lowerCase = name.toLowerCase();
  let parts;
  if (lowerCase.includes("@")) {
    if (!SUI_NS_NAME_REGEX.test(lowerCase)) {
      throw new Error(`Invalid SuiNS name ${name}`);
    }
    const [labels, domain] = lowerCase.split("@");
    parts = [...labels ? labels.split(".") : [], domain];
  } else {
    if (!SUI_NS_DOMAIN_REGEX.test(lowerCase)) {
      throw new Error(`Invalid SuiNS name ${name}`);
    }
    parts = lowerCase.split(".").slice(0, -1);
  }
  if (format === "dot") {
    return `${parts.join(".")}.sui`;
  }
  return `${parts.slice(0, -1).join(".")}@${parts[parts.length - 1]}`;
}
//# sourceMappingURL=suins.js.map


/***/ }),

/***/ 4531:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var version_exports = {};
__export(version_exports, {
  PACKAGE_VERSION: () => PACKAGE_VERSION,
  TARGETED_RPC_VERSION: () => TARGETED_RPC_VERSION
});
module.exports = __toCommonJS(version_exports);
const PACKAGE_VERSION = "1.29.1";
const TARGETED_RPC_VERSION = "1.49.0";
//# sourceMappingURL=version.js.map


/***/ }),

/***/ 8246:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var b58_exports = {};
__export(b58_exports, {
  fromBase58: () => fromBase58,
  toBase58: () => toBase58
});
module.exports = __toCommonJS(b58_exports);
var import_base = __nccwpck_require__(628);
const toBase58 = (buffer) => import_base.base58.encode(buffer);
const fromBase58 = (str) => import_base.base58.decode(str);
//# sourceMappingURL=b58.js.map


/***/ }),

/***/ 1853:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var b64_exports = {};
__export(b64_exports, {
  fromBase64: () => fromBase64,
  toBase64: () => toBase64
});
module.exports = __toCommonJS(b64_exports);
function fromBase64(base64String) {
  return Uint8Array.from(atob(base64String), (char) => char.charCodeAt(0));
}
const CHUNK_SIZE = 8192;
function toBase64(bytes) {
  if (bytes.length < CHUNK_SIZE) {
    return btoa(String.fromCharCode(...bytes));
  }
  let output = "";
  for (var i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.slice(i, i + CHUNK_SIZE);
    output += String.fromCharCode(...chunk);
  }
  return btoa(output);
}
//# sourceMappingURL=b64.js.map


/***/ }),

/***/ 860:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var chunk_exports = {};
__export(chunk_exports, {
  chunk: () => chunk
});
module.exports = __toCommonJS(chunk_exports);
function chunk(array, size) {
  return Array.from({ length: Math.ceil(array.length / size) }, (_, i) => {
    return array.slice(i * size, (i + 1) * size);
  });
}
//# sourceMappingURL=chunk.js.map


/***/ }),

/***/ 3264:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var hex_exports = {};
__export(hex_exports, {
  fromHex: () => fromHex,
  toHex: () => toHex
});
module.exports = __toCommonJS(hex_exports);
function fromHex(hexStr) {
  const normalized = hexStr.startsWith("0x") ? hexStr.slice(2) : hexStr;
  const padded = normalized.length % 2 === 0 ? normalized : `0${normalized}`;
  const intArr = padded.match(/[0-9a-fA-F]{2}/g)?.map((byte) => parseInt(byte, 16)) ?? [];
  if (intArr.length !== padded.length / 2) {
    throw new Error(`Invalid hex string ${hexStr}`);
  }
  return Uint8Array.from(intArr);
}
function toHex(bytes) {
  return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
}
//# sourceMappingURL=hex.js.map


/***/ }),

/***/ 5041:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var index_exports = {};
__export(index_exports, {
  chunk: () => import_chunk.chunk,
  fromBase58: () => import_b58.fromBase58,
  fromBase64: () => import_b64.fromBase64,
  fromHex: () => import_hex.fromHex,
  promiseWithResolvers: () => import_with_resolver.promiseWithResolvers,
  toBase58: () => import_b58.toBase58,
  toBase64: () => import_b64.toBase64,
  toHex: () => import_hex.toHex
});
module.exports = __toCommonJS(index_exports);
var import_b58 = __nccwpck_require__(8246);
var import_b64 = __nccwpck_require__(1853);
var import_hex = __nccwpck_require__(3264);
var import_chunk = __nccwpck_require__(860);
var import_with_resolver = __nccwpck_require__(1556);
//# sourceMappingURL=index.js.map


/***/ }),

/***/ 1556:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var with_resolver_exports = {};
__export(with_resolver_exports, {
  promiseWithResolvers: () => promiseWithResolvers
});
module.exports = __toCommonJS(with_resolver_exports);
function promiseWithResolvers() {
  let resolver;
  let rejecter;
  const promise = new Promise((resolve, reject) => {
    resolver = resolve;
    rejecter = reject;
  });
  return {
    promise,
    resolve: resolver,
    reject: rejecter
  };
}
//# sourceMappingURL=with-resolver.js.map


/***/ }),

/***/ 8275:
/***/ ((module) => {


var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  BIC_REGEX: () => BIC_REGEX,
  CUID2_REGEX: () => CUID2_REGEX,
  DECIMAL_REGEX: () => DECIMAL_REGEX,
  EMAIL_REGEX: () => EMAIL_REGEX,
  EMOJI_REGEX: () => EMOJI_REGEX,
  HEXADECIMAL_REGEX: () => HEXADECIMAL_REGEX,
  HEX_COLOR_REGEX: () => HEX_COLOR_REGEX,
  IMEI_REGEX: () => IMEI_REGEX,
  IPV4_REGEX: () => IPV4_REGEX,
  IPV6_REGEX: () => IPV6_REGEX,
  IP_REGEX: () => IP_REGEX,
  ISO_DATE_REGEX: () => ISO_DATE_REGEX,
  ISO_DATE_TIME_REGEX: () => ISO_DATE_TIME_REGEX,
  ISO_TIMESTAMP_REGEX: () => ISO_TIMESTAMP_REGEX,
  ISO_TIME_REGEX: () => ISO_TIME_REGEX,
  ISO_TIME_SECOND_REGEX: () => ISO_TIME_SECOND_REGEX,
  ISO_WEEK_REGEX: () => ISO_WEEK_REGEX,
  MAC48_REGEX: () => MAC48_REGEX,
  MAC64_REGEX: () => MAC64_REGEX,
  MAC_REGEX: () => MAC_REGEX,
  OCTAL_REGEX: () => OCTAL_REGEX,
  ULID_REGEX: () => ULID_REGEX,
  UUID_REGEX: () => UUID_REGEX,
  ValiError: () => ValiError,
  _addIssue: () => _addIssue,
  _isLuhnAlgo: () => _isLuhnAlgo,
  _isValidObjectKey: () => _isValidObjectKey,
  _stringify: () => _stringify,
  any: () => any,
  array: () => array,
  arrayAsync: () => arrayAsync,
  awaitAsync: () => awaitAsync,
  bic: () => bic,
  bigint: () => bigint,
  blob: () => blob,
  boolean: () => boolean,
  brand: () => brand,
  bytes: () => bytes,
  check: () => check,
  checkAsync: () => checkAsync,
  checkItems: () => checkItems,
  config: () => config,
  creditCard: () => creditCard,
  cuid2: () => cuid2,
  custom: () => custom,
  customAsync: () => customAsync,
  date: () => date,
  decimal: () => decimal,
  deleteGlobalConfig: () => deleteGlobalConfig,
  deleteGlobalMessage: () => deleteGlobalMessage,
  deleteSchemaMessage: () => deleteSchemaMessage,
  deleteSpecificMessage: () => deleteSpecificMessage,
  email: () => email,
  emoji: () => emoji,
  empty: () => empty,
  endsWith: () => endsWith,
  entriesFromList: () => entriesFromList,
  enum: () => enum_,
  enum_: () => enum_,
  everyItem: () => everyItem,
  excludes: () => excludes,
  fallback: () => fallback,
  fallbackAsync: () => fallbackAsync,
  file: () => file,
  filterItems: () => filterItems,
  findItem: () => findItem,
  finite: () => finite,
  flatten: () => flatten,
  forward: () => forward,
  forwardAsync: () => forwardAsync,
  function: () => function_,
  function_: () => function_,
  getDefault: () => getDefault,
  getDefaults: () => getDefaults,
  getDefaultsAsync: () => getDefaultsAsync,
  getDotPath: () => getDotPath,
  getFallback: () => getFallback,
  getFallbacks: () => getFallbacks,
  getFallbacksAsync: () => getFallbacksAsync,
  getGlobalConfig: () => getGlobalConfig,
  getGlobalMessage: () => getGlobalMessage,
  getSchemaMessage: () => getSchemaMessage,
  getSpecificMessage: () => getSpecificMessage,
  hash: () => hash,
  hexColor: () => hexColor,
  hexadecimal: () => hexadecimal,
  imei: () => imei,
  includes: () => includes,
  instance: () => instance,
  integer: () => integer,
  intersect: () => intersect,
  intersectAsync: () => intersectAsync,
  ip: () => ip,
  ipv4: () => ipv4,
  ipv6: () => ipv6,
  is: () => is,
  isOfKind: () => isOfKind,
  isOfType: () => isOfType,
  isValiError: () => isValiError,
  isoDate: () => isoDate,
  isoDateTime: () => isoDateTime,
  isoTime: () => isoTime,
  isoTimeSecond: () => isoTimeSecond,
  isoTimestamp: () => isoTimestamp,
  isoWeek: () => isoWeek,
  keyof: () => keyof,
  lazy: () => lazy,
  lazyAsync: () => lazyAsync,
  length: () => length,
  literal: () => literal,
  looseObject: () => looseObject,
  looseObjectAsync: () => looseObjectAsync,
  looseTuple: () => looseTuple,
  looseTupleAsync: () => looseTupleAsync,
  mac: () => mac,
  mac48: () => mac48,
  mac64: () => mac64,
  map: () => map,
  mapAsync: () => mapAsync,
  mapItems: () => mapItems,
  maxBytes: () => maxBytes,
  maxLength: () => maxLength,
  maxSize: () => maxSize,
  maxValue: () => maxValue,
  mimeType: () => mimeType,
  minBytes: () => minBytes,
  minLength: () => minLength,
  minSize: () => minSize,
  minValue: () => minValue,
  multipleOf: () => multipleOf,
  nan: () => nan,
  never: () => never,
  nonEmpty: () => nonEmpty,
  nonNullable: () => nonNullable,
  nonNullableAsync: () => nonNullableAsync,
  nonNullish: () => nonNullish,
  nonNullishAsync: () => nonNullishAsync,
  nonOptional: () => nonOptional,
  nonOptionalAsync: () => nonOptionalAsync,
  normalize: () => normalize,
  notBytes: () => notBytes,
  notLength: () => notLength,
  notSize: () => notSize,
  notValue: () => notValue,
  null: () => null_,
  null_: () => null_,
  nullable: () => nullable,
  nullableAsync: () => nullableAsync,
  nullish: () => nullish,
  nullishAsync: () => nullishAsync,
  number: () => number,
  object: () => object,
  objectAsync: () => objectAsync,
  objectWithRest: () => objectWithRest,
  objectWithRestAsync: () => objectWithRestAsync,
  octal: () => octal,
  omit: () => omit,
  optional: () => optional,
  optionalAsync: () => optionalAsync,
  parse: () => parse,
  parseAsync: () => parseAsync,
  parser: () => parser,
  parserAsync: () => parserAsync,
  partial: () => partial,
  partialAsync: () => partialAsync,
  partialCheck: () => partialCheck,
  partialCheckAsync: () => partialCheckAsync,
  pick: () => pick,
  picklist: () => picklist,
  pipe: () => pipe,
  pipeAsync: () => pipeAsync,
  promise: () => promise,
  rawCheck: () => rawCheck,
  rawCheckAsync: () => rawCheckAsync,
  rawTransform: () => rawTransform,
  rawTransformAsync: () => rawTransformAsync,
  readonly: () => readonly,
  record: () => record,
  recordAsync: () => recordAsync,
  reduceItems: () => reduceItems,
  regex: () => regex,
  required: () => required,
  requiredAsync: () => requiredAsync,
  safeInteger: () => safeInteger,
  safeParse: () => safeParse,
  safeParseAsync: () => safeParseAsync,
  safeParser: () => safeParser,
  safeParserAsync: () => safeParserAsync,
  set: () => set,
  setAsync: () => setAsync,
  setGlobalConfig: () => setGlobalConfig,
  setGlobalMessage: () => setGlobalMessage,
  setSchemaMessage: () => setSchemaMessage,
  setSpecificMessage: () => setSpecificMessage,
  size: () => size,
  someItem: () => someItem,
  sortItems: () => sortItems,
  startsWith: () => startsWith,
  strictObject: () => strictObject,
  strictObjectAsync: () => strictObjectAsync,
  strictTuple: () => strictTuple,
  strictTupleAsync: () => strictTupleAsync,
  string: () => string,
  symbol: () => symbol,
  toLowerCase: () => toLowerCase,
  toMaxValue: () => toMaxValue,
  toMinValue: () => toMinValue,
  toUpperCase: () => toUpperCase,
  transform: () => transform,
  transformAsync: () => transformAsync,
  trim: () => trim,
  trimEnd: () => trimEnd,
  trimStart: () => trimStart,
  tuple: () => tuple,
  tupleAsync: () => tupleAsync,
  tupleWithRest: () => tupleWithRest,
  tupleWithRestAsync: () => tupleWithRestAsync,
  ulid: () => ulid,
  undefined: () => undefined_,
  undefined_: () => undefined_,
  union: () => union,
  unionAsync: () => unionAsync,
  unknown: () => unknown,
  unwrap: () => unwrap,
  url: () => url,
  uuid: () => uuid,
  value: () => value,
  variant: () => variant,
  variantAsync: () => variantAsync,
  void: () => void_,
  void_: () => void_
});
module.exports = __toCommonJS(src_exports);

// src/actions/await/awaitAsync.ts
function awaitAsync() {
  return {
    kind: "transformation",
    type: "await",
    reference: awaitAsync,
    async: true,
    async _run(dataset) {
      dataset.value = await dataset.value;
      return dataset;
    }
  };
}

// src/regex.ts
var BIC_REGEX = /^[A-Z]{6}(?!00)[A-Z\d]{2}(?:[A-Z\d]{3})?$/u;
var CUID2_REGEX = /^[a-z][\da-z]*$/u;
var DECIMAL_REGEX = /^\d+$/u;
var EMAIL_REGEX = /^[\w+-]+(?:\.[\w+-]+)*@[\da-z]+(?:[.-][\da-z]+)*\.[a-z]{2,}$/iu;
var EMOJI_REGEX = /^[\p{Extended_Pictographic}\p{Emoji_Component}]+$/u;
var HEXADECIMAL_REGEX = /^(?:0h|0x)?[\da-f]+$/iu;
var HEX_COLOR_REGEX = /^#(?:[\da-f]{3,4}|[\da-f]{6}|[\da-f]{8})$/iu;
var IMEI_REGEX = /^\d{15}$|^\d{2}-\d{6}-\d{6}-\d$/u;
var IPV4_REGEX = (
  // eslint-disable-next-line redos-detector/no-unsafe-regex -- false positive
  /^(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])(?:\.(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])){3}$/u
);
var IPV6_REGEX = /^(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,7}:|(?:[\da-f]{1,4}:){1,6}:[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,5}(?::[\da-f]{1,4}){1,2}|(?:[\da-f]{1,4}:){1,4}(?::[\da-f]{1,4}){1,3}|(?:[\da-f]{1,4}:){1,3}(?::[\da-f]{1,4}){1,4}|(?:[\da-f]{1,4}:){1,2}(?::[\da-f]{1,4}){1,5}|[\da-f]{1,4}:(?::[\da-f]{1,4}){1,6}|:(?:(?::[\da-f]{1,4}){1,7}|:)|fe80:(?::[\da-f]{0,4}){0,4}%[\da-z]+|::(?:f{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[\da-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d))$/iu;
var IP_REGEX = /^(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])(?:\.(?:(?:[1-9]|1\d|2[0-4])?\d|25[0-5])){3}$|^(?:(?:[\da-f]{1,4}:){7}[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,7}:|(?:[\da-f]{1,4}:){1,6}:[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,5}(?::[\da-f]{1,4}){1,2}|(?:[\da-f]{1,4}:){1,4}(?::[\da-f]{1,4}){1,3}|(?:[\da-f]{1,4}:){1,3}(?::[\da-f]{1,4}){1,4}|(?:[\da-f]{1,4}:){1,2}(?::[\da-f]{1,4}){1,5}|[\da-f]{1,4}:(?::[\da-f]{1,4}){1,6}|:(?:(?::[\da-f]{1,4}){1,7}|:)|fe80:(?::[\da-f]{0,4}){0,4}%[\da-z]+|::(?:f{4}(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)|(?:[\da-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d))$/iu;
var ISO_DATE_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[12]\d|0[1-9]|3[01])$/u;
var ISO_DATE_TIME_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[12]\d|0[1-9]|3[01])T(?:0\d|1\d|2[0-3]):[0-5]\d$/u;
var ISO_TIME_REGEX = /^(?:0\d|1\d|2[0-3]):[0-5]\d$/u;
var ISO_TIME_SECOND_REGEX = /^(?:0\d|1\d|2[0-3])(?::[0-5]\d){2}$/u;
var ISO_TIMESTAMP_REGEX = /^\d{4}-(?:0[1-9]|1[0-2])-(?:[12]\d|0[1-9]|3[01])T(?:0\d|1\d|2[0-3])(?::[0-5]\d){2}(?:\.\d{1,9})?(?:Z|[+-](?:0\d|1\d|2[0-3])(?::?[0-5]\d)?)$/u;
var ISO_WEEK_REGEX = /^\d{4}-W(?:0[1-9]|[1-4]\d|5[0-3])$/u;
var MAC48_REGEX = /^(?:[\da-f]{2}:){5}[\da-f]{2}$|^(?:[\da-f]{2}-){5}[\da-f]{2}$|^(?:[\da-f]{4}\.){2}[\da-f]{4}$/iu;
var MAC64_REGEX = /^(?:[\da-f]{2}:){7}[\da-f]{2}$|^(?:[\da-f]{2}-){7}[\da-f]{2}$|^(?:[\da-f]{4}\.){3}[\da-f]{4}$|^(?:[\da-f]{4}:){3}[\da-f]{4}$/iu;
var MAC_REGEX = /^(?:[\da-f]{2}:){5}[\da-f]{2}$|^(?:[\da-f]{2}-){5}[\da-f]{2}$|^(?:[\da-f]{4}\.){2}[\da-f]{4}$|^(?:[\da-f]{2}:){7}[\da-f]{2}$|^(?:[\da-f]{2}-){7}[\da-f]{2}$|^(?:[\da-f]{4}\.){3}[\da-f]{4}$|^(?:[\da-f]{4}:){3}[\da-f]{4}$/iu;
var OCTAL_REGEX = /^(?:0o)?[0-7]+$/iu;
var ULID_REGEX = /^[\da-hjkmnp-tv-z]{26}$/iu;
var UUID_REGEX = /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/iu;

// src/storages/globalConfig/globalConfig.ts
var store;
function setGlobalConfig(config2) {
  store = { ...store, ...config2 };
}
function getGlobalConfig(config2) {
  return {
    lang: config2?.lang ?? store?.lang,
    message: config2?.message,
    abortEarly: config2?.abortEarly ?? store?.abortEarly,
    abortPipeEarly: config2?.abortPipeEarly ?? store?.abortPipeEarly
  };
}
function deleteGlobalConfig() {
  store = void 0;
}

// src/storages/globalMessage/globalMessage.ts
var store2;
function setGlobalMessage(message, lang) {
  if (!store2) store2 = /* @__PURE__ */ new Map();
  store2.set(lang, message);
}
function getGlobalMessage(lang) {
  return store2?.get(lang);
}
function deleteGlobalMessage(lang) {
  store2?.delete(lang);
}

// src/storages/schemaMessage/schemaMessage.ts
var store3;
function setSchemaMessage(message, lang) {
  if (!store3) store3 = /* @__PURE__ */ new Map();
  store3.set(lang, message);
}
function getSchemaMessage(lang) {
  return store3?.get(lang);
}
function deleteSchemaMessage(lang) {
  store3?.delete(lang);
}

// src/storages/specificMessage/specificMessage.ts
var store4;
function setSpecificMessage(reference, message, lang) {
  if (!store4) store4 = /* @__PURE__ */ new Map();
  if (!store4.get(reference)) store4.set(reference, /* @__PURE__ */ new Map());
  store4.get(reference).set(lang, message);
}
function getSpecificMessage(reference, lang) {
  return store4?.get(reference)?.get(lang);
}
function deleteSpecificMessage(reference, lang) {
  store4?.get(reference)?.delete(lang);
}

// src/utils/_stringify/_stringify.ts
function _stringify(input) {
  const type = typeof input;
  if (type === "string") {
    return `"${input}"`;
  }
  if (type === "number" || type === "bigint" || type === "boolean") {
    return `${input}`;
  }
  if (type === "object" || type === "function") {
    return (input && Object.getPrototypeOf(input)?.constructor?.name) ?? "null";
  }
  return type;
}

// src/utils/_addIssue/_addIssue.ts
function _addIssue(context, label, dataset, config2, other) {
  const input = other && "input" in other ? other.input : dataset.value;
  const expected = other?.expected ?? context.expects ?? null;
  const received = other?.received ?? _stringify(input);
  const issue = {
    kind: context.kind,
    type: context.type,
    input,
    expected,
    received,
    message: `Invalid ${label}: ${expected ? `Expected ${expected} but r` : "R"}eceived ${received}`,
    // @ts-expect-error
    requirement: context.requirement,
    path: other?.path,
    issues: other?.issues,
    lang: config2.lang,
    abortEarly: config2.abortEarly,
    abortPipeEarly: config2.abortPipeEarly
  };
  const isSchema = context.kind === "schema";
  const message = other?.message ?? // @ts-expect-error
  context.message ?? getSpecificMessage(context.reference, issue.lang) ?? (isSchema ? getSchemaMessage(issue.lang) : null) ?? config2.message ?? getGlobalMessage(issue.lang);
  if (message) {
    issue.message = typeof message === "function" ? message(issue) : message;
  }
  if (isSchema) {
    dataset.typed = false;
  }
  if (dataset.issues) {
    dataset.issues.push(issue);
  } else {
    dataset.issues = [issue];
  }
}

// src/utils/_isLuhnAlgo/_isLuhnAlgo.ts
var NON_DIGIT_REGEX = /\D/gu;
function _isLuhnAlgo(input) {
  const number2 = input.replace(NON_DIGIT_REGEX, "");
  let length2 = number2.length;
  let bit = 1;
  let sum = 0;
  while (length2) {
    const value2 = +number2[--length2];
    bit ^= 1;
    sum += bit ? [0, 2, 4, 6, 8, 1, 3, 5, 7, 9][value2] : value2;
  }
  return sum % 10 === 0;
}

// src/utils/_isValidObjectKey/_isValidObjectKey.ts
function _isValidObjectKey(object2, key) {
  return Object.hasOwn(object2, key) && key !== "__proto__" && key !== "prototype" && key !== "constructor";
}

// src/utils/entriesFromList/entriesFromList.ts
function entriesFromList(list, schema) {
  const entries = {};
  for (const key of list) {
    entries[key] = schema;
  }
  return entries;
}

// src/utils/getDotPath/getDotPath.ts
function getDotPath(issue) {
  if (issue.path) {
    let key = "";
    for (const item of issue.path) {
      if (typeof item.key === "string" || typeof item.key === "number") {
        if (key) {
          key += `.${item.key}`;
        } else {
          key += item.key;
        }
      } else {
        return null;
      }
    }
    return key;
  }
  return null;
}

// src/utils/isOfKind/isOfKind.ts
function isOfKind(kind, object2) {
  return object2.kind === kind;
}

// src/utils/isOfType/isOfType.ts
function isOfType(type, object2) {
  return object2.type === type;
}

// src/utils/isValiError/isValiError.ts
function isValiError(error) {
  return error instanceof ValiError;
}

// src/utils/ValiError/ValiError.ts
var ValiError = class extends Error {
  /**
   * The error issues.
   */
  issues;
  /**
   * Creates a Valibot error with useful information.
   *
   * @param issues The error issues.
   */
  constructor(issues) {
    super(issues[0].message);
    this.name = "ValiError";
    this.issues = issues;
  }
};

// src/actions/bic/bic.ts
function bic(message) {
  return {
    kind: "validation",
    type: "bic",
    reference: bic,
    async: false,
    expects: null,
    requirement: BIC_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "BIC", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/brand/brand.ts
function brand(name) {
  return {
    kind: "transformation",
    type: "brand",
    reference: brand,
    async: false,
    name,
    _run(dataset) {
      return dataset;
    }
  };
}

// src/actions/bytes/bytes.ts
function bytes(requirement, message) {
  return {
    kind: "validation",
    type: "bytes",
    reference: bytes,
    async: false,
    expects: `${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed) {
        const length2 = new TextEncoder().encode(dataset.value).length;
        if (length2 !== this.requirement) {
          _addIssue(this, "bytes", dataset, config2, {
            received: `${length2}`
          });
        }
      }
      return dataset;
    }
  };
}

// src/actions/check/check.ts
function check(requirement, message) {
  return {
    kind: "validation",
    type: "check",
    reference: check,
    async: false,
    expects: null,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "input", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/check/checkAsync.ts
function checkAsync(requirement, message) {
  return {
    kind: "validation",
    type: "check",
    reference: checkAsync,
    async: true,
    expects: null,
    requirement,
    message,
    async _run(dataset, config2) {
      if (dataset.typed && !await this.requirement(dataset.value)) {
        _addIssue(this, "input", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/checkItems/checkItems.ts
function checkItems(requirement, message) {
  return {
    kind: "validation",
    type: "check_items",
    reference: checkItems,
    async: false,
    expects: null,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed) {
        for (let index = 0; index < dataset.value.length; index++) {
          const item = dataset.value[index];
          if (!this.requirement(item, index, dataset.value)) {
            _addIssue(this, "item", dataset, config2, {
              input: item,
              path: [
                {
                  type: "array",
                  origin: "value",
                  input: dataset.value,
                  key: index,
                  value: item
                }
              ]
            });
          }
        }
      }
      return dataset;
    }
  };
}

// src/actions/creditCard/creditCard.ts
var CREDIT_CARD_REGEX = /^(?:\d{14,19}|\d{4}(?: \d{3,6}){2,4}|\d{4}(?:-\d{3,6}){2,4})$/u;
var SANITIZE_REGEX = /[- ]/gu;
var PROVIDER_REGEX_LIST = [
  // American Express
  /^3[47]\d{13}$/u,
  // Diners Club
  /^3(?:0[0-5]|[68]\d)\d{11,13}$/u,
  // Discover
  /^6(?:011|5\d{2})\d{12,15}$/u,
  // JCB
  /^(?:2131|1800|35\d{3})\d{11}$/u,
  // Mastercard
  /^5[1-5]\d{2}|(?:222\d|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720)\d{12}$/u,
  // UnionPay
  /^(?:6[27]\d{14,17}|81\d{14,17})$/u,
  // Visa
  /^4\d{12}(?:\d{3,6})?$/u
];
function creditCard(message) {
  return {
    kind: "validation",
    type: "credit_card",
    reference: creditCard,
    async: false,
    expects: null,
    requirement(input) {
      let sanitized;
      return CREDIT_CARD_REGEX.test(input) && // Remove any hyphens and blanks
      (sanitized = input.replace(SANITIZE_REGEX, "")) && // Check if it matches a provider
      PROVIDER_REGEX_LIST.some((regex2) => regex2.test(sanitized)) && // Check if passes luhn algorithm
      _isLuhnAlgo(sanitized);
    },
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "credit card", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/cuid2/cuid2.ts
function cuid2(message) {
  return {
    kind: "validation",
    type: "cuid2",
    reference: cuid2,
    async: false,
    expects: null,
    requirement: CUID2_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "Cuid2", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/decimal/decimal.ts
function decimal(message) {
  return {
    kind: "validation",
    type: "decimal",
    reference: decimal,
    async: false,
    expects: null,
    requirement: DECIMAL_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "decimal", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/email/email.ts
function email(message) {
  return {
    kind: "validation",
    type: "email",
    reference: email,
    expects: null,
    async: false,
    requirement: EMAIL_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "email", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/emoji/emoji.ts
function emoji(message) {
  return {
    kind: "validation",
    type: "emoji",
    reference: emoji,
    async: false,
    expects: null,
    requirement: EMOJI_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "emoji", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/empty/empty.ts
function empty(message) {
  return {
    kind: "validation",
    type: "empty",
    reference: empty,
    async: false,
    expects: "0",
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.length > 0) {
        _addIssue(this, "length", dataset, config2, {
          received: `${dataset.value.length}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/endsWith/endsWith.ts
function endsWith(requirement, message) {
  return {
    kind: "validation",
    type: "ends_with",
    reference: endsWith,
    async: false,
    expects: `"${requirement}"`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !dataset.value.endsWith(this.requirement)) {
        _addIssue(this, "end", dataset, config2, {
          received: `"${dataset.value.slice(-this.requirement.length)}"`
        });
      }
      return dataset;
    }
  };
}

// src/actions/everyItem/everyItem.ts
function everyItem(requirement, message) {
  return {
    kind: "validation",
    type: "every_item",
    reference: everyItem,
    async: false,
    expects: null,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !dataset.value.every(this.requirement)) {
        _addIssue(this, "item", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/excludes/excludes.ts
function excludes(requirement, message) {
  const received = _stringify(requirement);
  return {
    kind: "validation",
    type: "excludes",
    reference: excludes,
    async: false,
    expects: `!${received}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.includes(this.requirement)) {
        _addIssue(this, "content", dataset, config2, { received });
      }
      return dataset;
    }
  };
}

// src/actions/filterItems/filterItems.ts
function filterItems(operation) {
  return {
    kind: "transformation",
    type: "filter_items",
    reference: filterItems,
    async: false,
    operation,
    _run(dataset) {
      dataset.value = dataset.value.filter(this.operation);
      return dataset;
    }
  };
}

// src/actions/findItem/findItem.ts
function findItem(operation) {
  return {
    kind: "transformation",
    type: "find_item",
    reference: findItem,
    async: false,
    operation,
    _run(dataset) {
      dataset.value = dataset.value.find(this.operation);
      return dataset;
    }
  };
}

// src/actions/finite/finite.ts
function finite(message) {
  return {
    kind: "validation",
    type: "finite",
    reference: finite,
    async: false,
    expects: null,
    requirement: Number.isFinite,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "finite", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/hash/hash.ts
var HASH_LENGTHS = {
  md4: 32,
  md5: 32,
  sha1: 40,
  sha256: 64,
  sha384: 96,
  sha512: 128,
  ripemd128: 32,
  ripemd160: 40,
  tiger128: 32,
  tiger160: 40,
  tiger192: 48,
  crc32: 8,
  crc32b: 8,
  adler32: 8
};
function hash(types, message) {
  return {
    kind: "validation",
    type: "hash",
    reference: hash,
    expects: null,
    async: false,
    requirement: RegExp(
      types.map((type) => `^[a-f0-9]{${HASH_LENGTHS[type]}}$`).join("|"),
      "iu"
    ),
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "hash", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/hexadecimal/hexadecimal.ts
function hexadecimal(message) {
  return {
    kind: "validation",
    type: "hexadecimal",
    reference: hexadecimal,
    async: false,
    expects: null,
    requirement: HEXADECIMAL_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "hexadecimal", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/hexColor/hexColor.ts
function hexColor(message) {
  return {
    kind: "validation",
    type: "hex_color",
    reference: hexColor,
    async: false,
    expects: null,
    requirement: HEX_COLOR_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "hex color", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/imei/imei.ts
function imei(message) {
  return {
    kind: "validation",
    type: "imei",
    reference: imei,
    async: false,
    expects: null,
    requirement(input) {
      return IMEI_REGEX.test(input) && _isLuhnAlgo(input);
    },
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "IMEI", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/includes/includes.ts
function includes(requirement, message) {
  const expects = _stringify(requirement);
  return {
    kind: "validation",
    type: "includes",
    reference: includes,
    async: false,
    expects,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !dataset.value.includes(this.requirement)) {
        _addIssue(this, "content", dataset, config2, {
          received: `!${expects}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/integer/integer.ts
function integer(message) {
  return {
    kind: "validation",
    type: "integer",
    reference: integer,
    async: false,
    expects: null,
    requirement: Number.isInteger,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "integer", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/ip/ip.ts
function ip(message) {
  return {
    kind: "validation",
    type: "ip",
    reference: ip,
    async: false,
    expects: null,
    requirement: IP_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "IP", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/ipv4/ipv4.ts
function ipv4(message) {
  return {
    kind: "validation",
    type: "ipv4",
    reference: ipv4,
    async: false,
    expects: null,
    requirement: IPV4_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "IPv4", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/ipv6/ipv6.ts
function ipv6(message) {
  return {
    kind: "validation",
    type: "ipv6",
    reference: ipv6,
    async: false,
    expects: null,
    requirement: IPV6_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "IPv6", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/isoDate/isoDate.ts
function isoDate(message) {
  return {
    kind: "validation",
    type: "iso_date",
    reference: isoDate,
    async: false,
    expects: null,
    requirement: ISO_DATE_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "date", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/isoDateTime/isoDateTime.ts
function isoDateTime(message) {
  return {
    kind: "validation",
    type: "iso_date_time",
    reference: isoDateTime,
    async: false,
    expects: null,
    requirement: ISO_DATE_TIME_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "date-time", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/isoTime/isoTime.ts
function isoTime(message) {
  return {
    kind: "validation",
    type: "iso_time",
    reference: isoTime,
    async: false,
    expects: null,
    requirement: ISO_TIME_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "time", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/isoTimeSecond/isoTimeSecond.ts
function isoTimeSecond(message) {
  return {
    kind: "validation",
    type: "iso_time_second",
    reference: isoTimeSecond,
    async: false,
    expects: null,
    requirement: ISO_TIME_SECOND_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "time-second", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/isoTimestamp/isoTimestamp.ts
function isoTimestamp(message) {
  return {
    kind: "validation",
    type: "iso_timestamp",
    reference: isoTimestamp,
    async: false,
    expects: null,
    requirement: ISO_TIMESTAMP_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "timestamp", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/isoWeek/isoWeek.ts
function isoWeek(message) {
  return {
    kind: "validation",
    type: "iso_week",
    reference: isoWeek,
    async: false,
    expects: null,
    requirement: ISO_WEEK_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "week", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/length/length.ts
function length(requirement, message) {
  return {
    kind: "validation",
    type: "length",
    reference: length,
    async: false,
    expects: `${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.length !== this.requirement) {
        _addIssue(this, "length", dataset, config2, {
          received: `${dataset.value.length}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/mac/mac.ts
function mac(message) {
  return {
    kind: "validation",
    type: "mac",
    reference: mac,
    async: false,
    expects: null,
    requirement: MAC_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "MAC", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/mac48/mac48.ts
function mac48(message) {
  return {
    kind: "validation",
    type: "mac48",
    reference: mac48,
    async: false,
    expects: null,
    requirement: MAC48_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "48-bit MAC", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/mac64/mac64.ts
function mac64(message) {
  return {
    kind: "validation",
    type: "mac64",
    reference: mac64,
    async: false,
    expects: null,
    requirement: MAC64_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "64-bit MAC", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/mapItems/mapItems.ts
function mapItems(operation) {
  return {
    kind: "transformation",
    type: "map_items",
    reference: mapItems,
    async: false,
    operation,
    _run(dataset) {
      dataset.value = dataset.value.map(this.operation);
      return dataset;
    }
  };
}

// src/actions/maxBytes/maxBytes.ts
function maxBytes(requirement, message) {
  return {
    kind: "validation",
    type: "max_bytes",
    reference: maxBytes,
    async: false,
    expects: `<=${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed) {
        const length2 = new TextEncoder().encode(dataset.value).length;
        if (length2 > this.requirement) {
          _addIssue(this, "bytes", dataset, config2, {
            received: `${length2}`
          });
        }
      }
      return dataset;
    }
  };
}

// src/actions/maxLength/maxLength.ts
function maxLength(requirement, message) {
  return {
    kind: "validation",
    type: "max_length",
    reference: maxLength,
    async: false,
    expects: `<=${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.length > this.requirement) {
        _addIssue(this, "length", dataset, config2, {
          received: `${dataset.value.length}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/maxSize/maxSize.ts
function maxSize(requirement, message) {
  return {
    kind: "validation",
    type: "max_size",
    reference: maxSize,
    async: false,
    expects: `<=${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.size > this.requirement) {
        _addIssue(this, "size", dataset, config2, {
          received: `${dataset.value.size}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/maxValue/maxValue.ts
function maxValue(requirement, message) {
  return {
    kind: "validation",
    type: "max_value",
    reference: maxValue,
    async: false,
    expects: `<=${requirement instanceof Date ? requirement.toJSON() : _stringify(requirement)}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value > this.requirement) {
        _addIssue(this, "value", dataset, config2, {
          received: dataset.value instanceof Date ? dataset.value.toJSON() : _stringify(dataset.value)
        });
      }
      return dataset;
    }
  };
}

// src/actions/mimeType/mimeType.ts
function mimeType(requirement, message) {
  return {
    kind: "validation",
    type: "mime_type",
    reference: mimeType,
    async: false,
    expects: requirement.map((option) => `"${option}"`).join(" | ") || "never",
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.includes(dataset.value.type)) {
        _addIssue(this, "MIME type", dataset, config2, {
          received: `"${dataset.value.type}"`
        });
      }
      return dataset;
    }
  };
}

// src/actions/minBytes/minBytes.ts
function minBytes(requirement, message) {
  return {
    kind: "validation",
    type: "min_bytes",
    reference: minBytes,
    async: false,
    expects: `>=${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed) {
        const length2 = new TextEncoder().encode(dataset.value).length;
        if (length2 < this.requirement) {
          _addIssue(this, "bytes", dataset, config2, {
            received: `${length2}`
          });
        }
      }
      return dataset;
    }
  };
}

// src/actions/minLength/minLength.ts
function minLength(requirement, message) {
  return {
    kind: "validation",
    type: "min_length",
    reference: minLength,
    async: false,
    expects: `>=${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.length < this.requirement) {
        _addIssue(this, "length", dataset, config2, {
          received: `${dataset.value.length}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/minSize/minSize.ts
function minSize(requirement, message) {
  return {
    kind: "validation",
    type: "min_size",
    reference: minSize,
    async: false,
    expects: `>=${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.size < this.requirement) {
        _addIssue(this, "size", dataset, config2, {
          received: `${dataset.value.size}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/minValue/minValue.ts
function minValue(requirement, message) {
  return {
    kind: "validation",
    type: "min_value",
    reference: minValue,
    async: false,
    expects: `>=${requirement instanceof Date ? requirement.toJSON() : _stringify(requirement)}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value < this.requirement) {
        _addIssue(this, "value", dataset, config2, {
          received: dataset.value instanceof Date ? dataset.value.toJSON() : _stringify(dataset.value)
        });
      }
      return dataset;
    }
  };
}

// src/actions/multipleOf/multipleOf.ts
function multipleOf(requirement, message) {
  return {
    kind: "validation",
    type: "multiple_of",
    reference: multipleOf,
    async: false,
    expects: `%${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value % this.requirement !== 0) {
        _addIssue(this, "multiple", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/nonEmpty/nonEmpty.ts
function nonEmpty(message) {
  return {
    kind: "validation",
    type: "non_empty",
    reference: nonEmpty,
    async: false,
    expects: "!0",
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.length === 0) {
        _addIssue(this, "length", dataset, config2, {
          received: "0"
        });
      }
      return dataset;
    }
  };
}

// src/actions/normalize/normalize.ts
function normalize(form) {
  return {
    kind: "transformation",
    type: "normalize",
    reference: normalize,
    async: false,
    form,
    _run(dataset) {
      dataset.value = dataset.value.normalize(this.form);
      return dataset;
    }
  };
}

// src/actions/notBytes/notBytes.ts
function notBytes(requirement, message) {
  return {
    kind: "validation",
    type: "not_bytes",
    reference: notBytes,
    async: false,
    expects: `!${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed) {
        const length2 = new TextEncoder().encode(dataset.value).length;
        if (length2 === this.requirement) {
          _addIssue(this, "bytes", dataset, config2, {
            received: `${length2}`
          });
        }
      }
      return dataset;
    }
  };
}

// src/actions/notLength/notLength.ts
function notLength(requirement, message) {
  return {
    kind: "validation",
    type: "not_length",
    reference: notLength,
    async: false,
    expects: `!${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.length === this.requirement) {
        _addIssue(this, "length", dataset, config2, {
          received: `${dataset.value.length}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/notSize/notSize.ts
function notSize(requirement, message) {
  return {
    kind: "validation",
    type: "not_size",
    reference: notSize,
    async: false,
    expects: `!${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.size === this.requirement) {
        _addIssue(this, "size", dataset, config2, {
          received: `${dataset.value.size}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/notValue/notValue.ts
function notValue(requirement, message) {
  return {
    kind: "validation",
    type: "not_value",
    reference: notValue,
    async: false,
    expects: requirement instanceof Date ? `!${requirement.toJSON()}` : `!${_stringify(requirement)}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && this.requirement <= dataset.value && this.requirement >= dataset.value) {
        _addIssue(this, "value", dataset, config2, {
          received: dataset.value instanceof Date ? dataset.value.toJSON() : _stringify(dataset.value)
        });
      }
      return dataset;
    }
  };
}

// src/actions/octal/octal.ts
function octal(message) {
  return {
    kind: "validation",
    type: "octal",
    reference: octal,
    async: false,
    expects: null,
    requirement: OCTAL_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "octal", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/partialCheck/utils/_isPartiallyTyped/_isPartiallyTyped.ts
function _isPartiallyTyped(dataset, pathList) {
  if (dataset.issues) {
    for (const path of pathList) {
      for (const issue of dataset.issues) {
        let typed = false;
        const bound = Math.min(path.length, issue.path?.length ?? 0);
        for (let index = 0; index < bound; index++) {
          if (path[index] !== issue.path[index].key) {
            typed = true;
            break;
          }
        }
        if (!typed) {
          return false;
        }
      }
    }
  }
  return true;
}

// src/actions/partialCheck/partialCheck.ts
function partialCheck(pathList, requirement, message) {
  return {
    kind: "validation",
    type: "partial_check",
    reference: partialCheck,
    async: false,
    expects: null,
    requirement,
    message,
    _run(dataset, config2) {
      if (_isPartiallyTyped(dataset, pathList) && // @ts-expect-error
      !this.requirement(dataset.value)) {
        _addIssue(this, "input", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/partialCheck/partialCheckAsync.ts
function partialCheckAsync(pathList, requirement, message) {
  return {
    kind: "validation",
    type: "partial_check",
    reference: partialCheckAsync,
    async: true,
    expects: null,
    requirement,
    message,
    async _run(dataset, config2) {
      if (_isPartiallyTyped(dataset, pathList) && // @ts-expect-error
      !await this.requirement(dataset.value)) {
        _addIssue(this, "input", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/rawCheck/rawCheck.ts
function rawCheck(action) {
  return {
    kind: "validation",
    type: "raw_check",
    reference: rawCheck,
    async: false,
    expects: null,
    _run(dataset, config2) {
      action({
        dataset,
        config: config2,
        addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config2, info)
      });
      return dataset;
    }
  };
}

// src/actions/rawCheck/rawCheckAsync.ts
function rawCheckAsync(action) {
  return {
    kind: "validation",
    type: "raw_check",
    reference: rawCheckAsync,
    async: true,
    expects: null,
    async _run(dataset, config2) {
      await action({
        dataset,
        config: config2,
        addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config2, info)
      });
      return dataset;
    }
  };
}

// src/actions/rawTransform/rawTransform.ts
function rawTransform(action) {
  return {
    kind: "transformation",
    type: "raw_transform",
    reference: rawTransform,
    async: false,
    _run(dataset, config2) {
      const output = action({
        dataset,
        config: config2,
        addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config2, info),
        NEVER: null
      });
      if (dataset.issues) {
        dataset.typed = false;
      } else {
        dataset.value = output;
      }
      return dataset;
    }
  };
}

// src/actions/rawTransform/rawTransformAsync.ts
function rawTransformAsync(action) {
  return {
    kind: "transformation",
    type: "raw_transform",
    reference: rawTransformAsync,
    async: true,
    async _run(dataset, config2) {
      const output = await action({
        dataset,
        config: config2,
        addIssue: (info) => _addIssue(this, info?.label ?? "input", dataset, config2, info),
        NEVER: null
      });
      if (dataset.issues) {
        dataset.typed = false;
      } else {
        dataset.value = output;
      }
      return dataset;
    }
  };
}

// src/actions/readonly/readonly.ts
function readonly() {
  return {
    kind: "transformation",
    type: "readonly",
    reference: readonly,
    async: false,
    _run(dataset) {
      return dataset;
    }
  };
}

// src/actions/reduceItems/reduceItems.ts
function reduceItems(operation, initial) {
  return {
    kind: "transformation",
    type: "reduce_items",
    reference: reduceItems,
    async: false,
    operation,
    initial,
    _run(dataset) {
      dataset.value = dataset.value.reduce(this.operation, this.initial);
      return dataset;
    }
  };
}

// src/actions/regex/regex.ts
function regex(requirement, message) {
  return {
    kind: "validation",
    type: "regex",
    reference: regex,
    async: false,
    expects: `${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "format", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/safeInteger/safeInteger.ts
function safeInteger(message) {
  return {
    kind: "validation",
    type: "safe_integer",
    reference: safeInteger,
    async: false,
    expects: null,
    requirement: Number.isSafeInteger,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "safe integer", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/size/size.ts
function size(requirement, message) {
  return {
    kind: "validation",
    type: "size",
    reference: size,
    async: false,
    expects: `${requirement}`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && dataset.value.size !== this.requirement) {
        _addIssue(this, "size", dataset, config2, {
          received: `${dataset.value.size}`
        });
      }
      return dataset;
    }
  };
}

// src/actions/someItem/someItem.ts
function someItem(requirement, message) {
  return {
    kind: "validation",
    type: "some_item",
    reference: someItem,
    async: false,
    expects: null,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !dataset.value.some(this.requirement)) {
        _addIssue(this, "item", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/sortItems/sortItems.ts
function sortItems(operation) {
  return {
    kind: "transformation",
    type: "sort_items",
    reference: sortItems,
    async: false,
    operation,
    _run(dataset) {
      dataset.value = dataset.value.sort(this.operation);
      return dataset;
    }
  };
}

// src/actions/startsWith/startsWith.ts
function startsWith(requirement, message) {
  return {
    kind: "validation",
    type: "starts_with",
    reference: startsWith,
    async: false,
    expects: `"${requirement}"`,
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !dataset.value.startsWith(this.requirement)) {
        _addIssue(this, "start", dataset, config2, {
          received: `"${dataset.value.slice(0, this.requirement.length)}"`
        });
      }
      return dataset;
    }
  };
}

// src/actions/toLowerCase/toLowerCase.ts
function toLowerCase() {
  return {
    kind: "transformation",
    type: "to_lower_case",
    reference: toLowerCase,
    async: false,
    _run(dataset) {
      dataset.value = dataset.value.toLowerCase();
      return dataset;
    }
  };
}

// src/actions/toMaxValue/toMaxValue.ts
function toMaxValue(requirement) {
  return {
    kind: "transformation",
    type: "to_max_value",
    reference: toMaxValue,
    async: false,
    requirement,
    _run(dataset) {
      dataset.value = dataset.value > this.requirement ? this.requirement : dataset.value;
      return dataset;
    }
  };
}

// src/actions/toMinValue/toMinValue.ts
function toMinValue(requirement) {
  return {
    kind: "transformation",
    type: "to_min_value",
    reference: toMinValue,
    async: false,
    requirement,
    _run(dataset) {
      dataset.value = dataset.value < this.requirement ? this.requirement : dataset.value;
      return dataset;
    }
  };
}

// src/actions/toUpperCase/toUpperCase.ts
function toUpperCase() {
  return {
    kind: "transformation",
    type: "to_upper_case",
    reference: toUpperCase,
    async: false,
    _run(dataset) {
      dataset.value = dataset.value.toUpperCase();
      return dataset;
    }
  };
}

// src/actions/transform/transform.ts
function transform(operation) {
  return {
    kind: "transformation",
    type: "transform",
    reference: transform,
    async: false,
    operation,
    _run(dataset) {
      dataset.value = this.operation(dataset.value);
      return dataset;
    }
  };
}

// src/actions/transform/transformAsync.ts
function transformAsync(operation) {
  return {
    kind: "transformation",
    type: "transform",
    reference: transformAsync,
    async: true,
    operation,
    async _run(dataset) {
      dataset.value = await this.operation(dataset.value);
      return dataset;
    }
  };
}

// src/actions/trim/trim.ts
function trim() {
  return {
    kind: "transformation",
    type: "trim",
    reference: trim,
    async: false,
    _run(dataset) {
      dataset.value = dataset.value.trim();
      return dataset;
    }
  };
}

// src/actions/trimEnd/trimEnd.ts
function trimEnd() {
  return {
    kind: "transformation",
    type: "trim_end",
    reference: trimEnd,
    async: false,
    _run(dataset) {
      dataset.value = dataset.value.trimEnd();
      return dataset;
    }
  };
}

// src/actions/trimStart/trimStart.ts
function trimStart() {
  return {
    kind: "transformation",
    type: "trim_start",
    reference: trimStart,
    async: false,
    _run(dataset) {
      dataset.value = dataset.value.trimStart();
      return dataset;
    }
  };
}

// src/actions/ulid/ulid.ts
function ulid(message) {
  return {
    kind: "validation",
    type: "ulid",
    reference: ulid,
    async: false,
    expects: null,
    requirement: ULID_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "ULID", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/url/url.ts
function url(message) {
  return {
    kind: "validation",
    type: "url",
    reference: url,
    async: false,
    expects: null,
    requirement(input) {
      try {
        new URL(input);
        return true;
      } catch {
        return false;
      }
    },
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement(dataset.value)) {
        _addIssue(this, "URL", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/uuid/uuid.ts
function uuid(message) {
  return {
    kind: "validation",
    type: "uuid",
    reference: uuid,
    async: false,
    expects: null,
    requirement: UUID_REGEX,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !this.requirement.test(dataset.value)) {
        _addIssue(this, "UUID", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/actions/value/value.ts
function value(requirement, message) {
  return {
    kind: "validation",
    type: "value",
    reference: value,
    async: false,
    expects: requirement instanceof Date ? requirement.toJSON() : _stringify(requirement),
    requirement,
    message,
    _run(dataset, config2) {
      if (dataset.typed && !(this.requirement <= dataset.value && this.requirement >= dataset.value)) {
        _addIssue(this, "value", dataset, config2, {
          received: dataset.value instanceof Date ? dataset.value.toJSON() : _stringify(dataset.value)
        });
      }
      return dataset;
    }
  };
}

// src/methods/config/config.ts
function config(schema, config2) {
  return {
    ...schema,
    _run(dataset, config_) {
      return schema._run(dataset, { ...config_, ...config2 });
    }
  };
}

// src/methods/getFallback/getFallback.ts
function getFallback(schema, dataset, config2) {
  return typeof schema.fallback === "function" ? (
    // @ts-expect-error
    schema.fallback(dataset, config2)
  ) : (
    // @ts-expect-error
    schema.fallback
  );
}

// src/methods/fallback/fallback.ts
function fallback(schema, fallback2) {
  return {
    ...schema,
    fallback: fallback2,
    _run(dataset, config2) {
      schema._run(dataset, config2);
      return dataset.issues ? { typed: true, value: getFallback(this, dataset, config2) } : dataset;
    }
  };
}

// src/methods/fallback/fallbackAsync.ts
function fallbackAsync(schema, fallback2) {
  return {
    ...schema,
    fallback: fallback2,
    async: true,
    async _run(dataset, config2) {
      schema._run(dataset, config2);
      return dataset.issues ? (
        // @ts-expect-error
        { typed: true, value: await getFallback(this, dataset, config2) }
      ) : dataset;
    }
  };
}

// src/methods/flatten/flatten.ts
function flatten(issues) {
  const flatErrors = {};
  for (const issue of issues) {
    if (issue.path) {
      const dotPath = getDotPath(issue);
      if (dotPath) {
        if (!flatErrors.nested) {
          flatErrors.nested = {};
        }
        if (flatErrors.nested[dotPath]) {
          flatErrors.nested[dotPath].push(issue.message);
        } else {
          flatErrors.nested[dotPath] = [issue.message];
        }
      } else {
        if (flatErrors.other) {
          flatErrors.other.push(issue.message);
        } else {
          flatErrors.other = [issue.message];
        }
      }
    } else {
      if (flatErrors.root) {
        flatErrors.root.push(issue.message);
      } else {
        flatErrors.root = [issue.message];
      }
    }
  }
  return flatErrors;
}

// src/methods/forward/forward.ts
function forward(action, pathKeys) {
  return {
    ...action,
    _run(dataset, config2) {
      const prevIssues = dataset.issues && [...dataset.issues];
      action._run(dataset, config2);
      if (dataset.issues) {
        for (const issue of dataset.issues) {
          if (!prevIssues?.includes(issue)) {
            let pathInput = dataset.value;
            for (const key of pathKeys) {
              const pathValue = pathInput[key];
              const pathItem = {
                type: "unknown",
                origin: "value",
                input: pathInput,
                key,
                value: pathValue
              };
              if (issue.path) {
                issue.path.push(pathItem);
              } else {
                issue.path = [pathItem];
              }
              if (!pathValue) {
                break;
              }
              pathInput = pathValue;
            }
          }
        }
      }
      return dataset;
    }
  };
}

// src/methods/forward/forwardAsync.ts
function forwardAsync(action, pathKeys) {
  return {
    ...action,
    async: true,
    async _run(dataset, config2) {
      const prevIssues = dataset.issues && [...dataset.issues];
      await action._run(dataset, config2);
      if (dataset.issues) {
        for (const issue of dataset.issues) {
          if (!prevIssues?.includes(issue)) {
            let pathInput = dataset.value;
            for (const key of pathKeys) {
              const pathValue = pathInput[key];
              const pathItem = {
                type: "unknown",
                origin: "value",
                input: pathInput,
                key,
                value: pathValue
              };
              if (issue.path) {
                issue.path.push(pathItem);
              } else {
                issue.path = [pathItem];
              }
              if (!pathValue) {
                break;
              }
              pathInput = pathValue;
            }
          }
        }
      }
      return dataset;
    }
  };
}

// src/methods/getDefault/getDefault.ts
function getDefault(schema, dataset, config2) {
  return typeof schema.default === "function" ? (
    // @ts-expect-error
    schema.default(dataset, config2)
  ) : (
    // @ts-expect-error
    schema.default
  );
}

// src/methods/getDefaults/getDefaults.ts
function getDefaults(schema) {
  if ("entries" in schema) {
    const object2 = {};
    for (const key in schema.entries) {
      object2[key] = getDefaults(schema.entries[key]);
    }
    return object2;
  }
  if ("items" in schema) {
    return schema.items.map(getDefaults);
  }
  return getDefault(schema);
}

// src/methods/getDefaults/getDefaultsAsync.ts
async function getDefaultsAsync(schema) {
  if ("entries" in schema) {
    return Object.fromEntries(
      await Promise.all(
        Object.entries(schema.entries).map(async ([key, value2]) => [
          key,
          await getDefaultsAsync(value2)
        ])
      )
    );
  }
  if ("items" in schema) {
    return Promise.all(schema.items.map(getDefaultsAsync));
  }
  return getDefault(schema);
}

// src/methods/getFallbacks/getFallbacks.ts
function getFallbacks(schema) {
  if ("entries" in schema) {
    const object2 = {};
    for (const key in schema.entries) {
      object2[key] = getFallbacks(schema.entries[key]);
    }
    return object2;
  }
  if ("items" in schema) {
    return schema.items.map(getFallbacks);
  }
  return getFallback(schema);
}

// src/methods/getFallbacks/getFallbacksAsync.ts
async function getFallbacksAsync(schema) {
  if ("entries" in schema) {
    return Object.fromEntries(
      await Promise.all(
        Object.entries(schema.entries).map(async ([key, value2]) => [
          key,
          await getFallbacksAsync(value2)
        ])
      )
    );
  }
  if ("items" in schema) {
    return Promise.all(schema.items.map(getFallbacksAsync));
  }
  return getFallback(schema);
}

// src/methods/is/is.ts
function is(schema, input) {
  return !schema._run({ typed: false, value: input }, { abortEarly: true }).issues;
}

// src/schemas/any/any.ts
function any() {
  return {
    kind: "schema",
    type: "any",
    reference: any,
    expects: "any",
    async: false,
    _run(dataset) {
      dataset.typed = true;
      return dataset;
    }
  };
}

// src/schemas/array/array.ts
function array(item, message) {
  return {
    kind: "schema",
    type: "array",
    reference: array,
    expects: "Array",
    async: false,
    item,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        for (let key = 0; key < input.length; key++) {
          const value2 = input[key];
          const itemDataset = this.item._run({ typed: false, value: value2 }, config2);
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/array/arrayAsync.ts
function arrayAsync(item, message) {
  return {
    kind: "schema",
    type: "array",
    reference: arrayAsync,
    expects: "Array",
    async: true,
    item,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        const itemDatasets = await Promise.all(
          input.map((value2) => this.item._run({ typed: false, value: value2 }, config2))
        );
        for (let key = 0; key < itemDatasets.length; key++) {
          const itemDataset = itemDatasets[key];
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: input[key]
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/bigint/bigint.ts
function bigint(message) {
  return {
    kind: "schema",
    type: "bigint",
    reference: bigint,
    expects: "bigint",
    async: false,
    message,
    _run(dataset, config2) {
      if (typeof dataset.value === "bigint") {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/blob/blob.ts
function blob(message) {
  return {
    kind: "schema",
    type: "blob",
    reference: blob,
    expects: "Blob",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value instanceof Blob) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/boolean/boolean.ts
function boolean(message) {
  return {
    kind: "schema",
    type: "boolean",
    reference: boolean,
    expects: "boolean",
    async: false,
    message,
    _run(dataset, config2) {
      if (typeof dataset.value === "boolean") {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/custom/custom.ts
function custom(check2, message) {
  return {
    kind: "schema",
    type: "custom",
    reference: custom,
    expects: "unknown",
    async: false,
    check: check2,
    message,
    _run(dataset, config2) {
      if (this.check(dataset.value)) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/custom/customAsync.ts
function customAsync(check2, message) {
  return {
    kind: "schema",
    type: "custom",
    reference: customAsync,
    expects: "unknown",
    async: true,
    check: check2,
    message,
    async _run(dataset, config2) {
      if (await this.check(dataset.value)) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/date/date.ts
function date(message) {
  return {
    kind: "schema",
    type: "date",
    reference: date,
    expects: "Date",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value instanceof Date) {
        if (!isNaN(dataset.value)) {
          dataset.typed = true;
        } else {
          _addIssue(this, "type", dataset, config2, {
            received: '"Invalid Date"'
          });
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/enum/enum.ts
function enum_(enum__, message) {
  const options = Object.entries(enum__).filter(([key]) => isNaN(+key)).map(([, value2]) => value2);
  return {
    kind: "schema",
    type: "enum",
    reference: enum_,
    expects: options.map(_stringify).join(" | ") || "never",
    async: false,
    enum: enum__,
    options,
    message,
    _run(dataset, config2) {
      if (this.options.includes(dataset.value)) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/file/file.ts
function file(message) {
  return {
    kind: "schema",
    type: "file",
    reference: file,
    expects: "File",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value instanceof File) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/function/function.ts
function function_(message) {
  return {
    kind: "schema",
    type: "function",
    reference: function_,
    expects: "Function",
    async: false,
    message,
    _run(dataset, config2) {
      if (typeof dataset.value === "function") {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/instance/instance.ts
function instance(class_, message) {
  return {
    kind: "schema",
    type: "instance",
    reference: instance,
    expects: class_.name,
    async: false,
    class: class_,
    message,
    _run(dataset, config2) {
      if (dataset.value instanceof this.class) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/intersect/utils/_merge/_merge.ts
function _merge(value1, value2) {
  if (typeof value1 === typeof value2) {
    if (value1 === value2 || value1 instanceof Date && value2 instanceof Date && +value1 === +value2) {
      return { value: value1 };
    }
    if (value1 && value2 && value1.constructor === Object && value2.constructor === Object) {
      for (const key in value2) {
        if (key in value1) {
          const dataset = _merge(value1[key], value2[key]);
          if (dataset.issue) {
            return dataset;
          }
          value1[key] = dataset.value;
        } else {
          value1[key] = value2[key];
        }
      }
      return { value: value1 };
    }
    if (Array.isArray(value1) && Array.isArray(value2)) {
      if (value1.length === value2.length) {
        for (let index = 0; index < value1.length; index++) {
          const dataset = _merge(value1[index], value2[index]);
          if (dataset.issue) {
            return dataset;
          }
          value1[index] = dataset.value;
        }
        return { value: value1 };
      }
    }
  }
  return { issue: true };
}

// src/schemas/intersect/intersect.ts
function intersect(options, message) {
  return {
    kind: "schema",
    type: "intersect",
    reference: intersect,
    expects: [...new Set(options.map((option) => option.expects))].join(" & ") || "never",
    async: false,
    options,
    message,
    _run(dataset, config2) {
      if (this.options.length) {
        const input = dataset.value;
        let outputs;
        dataset.typed = true;
        for (const schema of this.options) {
          const optionDataset = schema._run(
            { typed: false, value: input },
            config2
          );
          if (optionDataset.issues) {
            if (dataset.issues) {
              dataset.issues.push(...optionDataset.issues);
            } else {
              dataset.issues = optionDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!optionDataset.typed) {
            dataset.typed = false;
          }
          if (dataset.typed) {
            if (outputs) {
              outputs.push(optionDataset.value);
            } else {
              outputs = [optionDataset.value];
            }
          }
        }
        if (dataset.typed) {
          dataset.value = outputs[0];
          for (let index = 1; index < outputs.length; index++) {
            const mergeDataset = _merge(dataset.value, outputs[index]);
            if (mergeDataset.issue) {
              _addIssue(this, "type", dataset, config2, {
                received: "unknown"
              });
              break;
            }
            dataset.value = mergeDataset.value;
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/intersect/intersectAsync.ts
function intersectAsync(options, message) {
  return {
    kind: "schema",
    type: "intersect",
    reference: intersectAsync,
    expects: [...new Set(options.map((option) => option.expects))].join(" & ") || "never",
    async: true,
    options,
    message,
    async _run(dataset, config2) {
      if (this.options.length) {
        const input = dataset.value;
        let outputs;
        dataset.typed = true;
        const optionDatasets = await Promise.all(
          this.options.map(
            (schema) => schema._run({ typed: false, value: input }, config2)
          )
        );
        for (const optionDataset of optionDatasets) {
          if (optionDataset.issues) {
            if (dataset.issues) {
              dataset.issues.push(...optionDataset.issues);
            } else {
              dataset.issues = optionDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!optionDataset.typed) {
            dataset.typed = false;
          }
          if (dataset.typed) {
            if (outputs) {
              outputs.push(optionDataset.value);
            } else {
              outputs = [optionDataset.value];
            }
          }
        }
        if (dataset.typed) {
          dataset.value = outputs[0];
          for (let index = 1; index < outputs.length; index++) {
            const mergeDataset = _merge(dataset.value, outputs[index]);
            if (mergeDataset.issue) {
              _addIssue(this, "type", dataset, config2, {
                received: "unknown"
              });
              break;
            }
            dataset.value = mergeDataset.value;
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/lazy/lazy.ts
function lazy(getter) {
  return {
    kind: "schema",
    type: "lazy",
    reference: lazy,
    expects: "unknown",
    async: false,
    getter,
    _run(dataset, config2) {
      return this.getter(dataset.value)._run(dataset, config2);
    }
  };
}

// src/schemas/lazy/lazyAsync.ts
function lazyAsync(getter) {
  return {
    kind: "schema",
    type: "lazy",
    reference: lazyAsync,
    expects: "unknown",
    async: true,
    getter,
    async _run(dataset, config2) {
      return (await this.getter(dataset.value))._run(dataset, config2);
    }
  };
}

// src/schemas/literal/literal.ts
function literal(literal_, message) {
  return {
    kind: "schema",
    type: "literal",
    reference: literal,
    expects: _stringify(literal_),
    async: false,
    literal: literal_,
    message,
    _run(dataset, config2) {
      if (dataset.value === this.literal) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/looseObject/looseObject.ts
function looseObject(entries, message) {
  return {
    kind: "schema",
    type: "loose_object",
    reference: looseObject,
    expects: "Object",
    async: false,
    entries,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        for (const key in this.entries) {
          const value2 = input[key];
          const valueDataset = this.entries[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const key in input) {
            if (_isValidObjectKey(input, key) && !(key in this.entries)) {
              dataset.value[key] = input[key];
            }
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/looseObject/looseObjectAsync.ts
function looseObjectAsync(entries, message) {
  return {
    kind: "schema",
    type: "loose_object",
    reference: looseObjectAsync,
    expects: "Object",
    async: true,
    entries,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        const valueDatasets = await Promise.all(
          Object.entries(this.entries).map(async ([key, schema]) => {
            const value2 = input[key];
            return [
              key,
              value2,
              await schema._run({ typed: false, value: value2 }, config2)
            ];
          })
        );
        for (const [key, value2, valueDataset] of valueDatasets) {
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const key in input) {
            if (_isValidObjectKey(input, key) && !(key in this.entries)) {
              dataset.value[key] = input[key];
            }
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/looseTuple/looseTuple.ts
function looseTuple(items, message) {
  return {
    kind: "schema",
    type: "loose_tuple",
    reference: looseTuple,
    expects: "Array",
    async: false,
    items,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        for (let key = 0; key < this.items.length; key++) {
          const value2 = input[key];
          const itemDataset = this.items[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (let key = this.items.length; key < input.length; key++) {
            dataset.value.push(input[key]);
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/looseTuple/looseTupleAsync.ts
function looseTupleAsync(items, message) {
  return {
    kind: "schema",
    type: "loose_tuple",
    reference: looseTupleAsync,
    expects: "Array",
    async: true,
    items,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        const itemDatasets = await Promise.all(
          this.items.map(async (item, key) => {
            const value2 = input[key];
            return [
              key,
              value2,
              await item._run({ typed: false, value: value2 }, config2)
            ];
          })
        );
        for (const [key, value2, itemDataset] of itemDatasets) {
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (let key = this.items.length; key < input.length; key++) {
            dataset.value.push(input[key]);
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/map/map.ts
function map(key, value2, message) {
  return {
    kind: "schema",
    type: "map",
    reference: map,
    expects: "Map",
    async: false,
    key,
    value: value2,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input instanceof Map) {
        dataset.typed = true;
        dataset.value = /* @__PURE__ */ new Map();
        for (const [inputKey, inputValue] of input) {
          const keyDataset = this.key._run(
            { typed: false, value: inputKey },
            config2
          );
          if (keyDataset.issues) {
            const pathItem = {
              type: "map",
              origin: "key",
              input,
              key: inputKey,
              value: inputValue
            };
            for (const issue of keyDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = keyDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          const valueDataset = this.value._run(
            { typed: false, value: inputValue },
            config2
          );
          if (valueDataset.issues) {
            const pathItem = {
              type: "map",
              origin: "value",
              input,
              key: inputKey,
              value: inputValue
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!keyDataset.typed || !valueDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.set(keyDataset.value, valueDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/map/mapAsync.ts
function mapAsync(key, value2, message) {
  return {
    kind: "schema",
    type: "map",
    reference: mapAsync,
    expects: "Map",
    async: true,
    key,
    value: value2,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input instanceof Map) {
        dataset.typed = true;
        dataset.value = /* @__PURE__ */ new Map();
        const datasets = await Promise.all(
          [...input].map(
            ([inputKey, inputValue]) => Promise.all([
              inputKey,
              inputValue,
              this.key._run({ typed: false, value: inputKey }, config2),
              this.value._run({ typed: false, value: inputValue }, config2)
            ])
          )
        );
        for (const [
          inputKey,
          inputValue,
          keyDataset,
          valueDataset
        ] of datasets) {
          if (keyDataset.issues) {
            const pathItem = {
              type: "map",
              origin: "key",
              input,
              key: inputKey,
              value: inputValue
            };
            for (const issue of keyDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = keyDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (valueDataset.issues) {
            const pathItem = {
              type: "map",
              origin: "value",
              input,
              key: inputKey,
              value: inputValue
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!keyDataset.typed || !valueDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.set(keyDataset.value, valueDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/nan/nan.ts
function nan(message) {
  return {
    kind: "schema",
    type: "nan",
    reference: nan,
    expects: "NaN",
    async: false,
    message,
    _run(dataset, config2) {
      if (Number.isNaN(dataset.value)) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/never/never.ts
function never(message) {
  return {
    kind: "schema",
    type: "never",
    reference: never,
    expects: "never",
    async: false,
    message,
    _run(dataset, config2) {
      _addIssue(this, "type", dataset, config2);
      return dataset;
    }
  };
}

// src/schemas/nonNullable/nonNullable.ts
function nonNullable(wrapped, message) {
  return {
    kind: "schema",
    type: "non_nullable",
    reference: nonNullable,
    expects: "!null",
    async: false,
    wrapped,
    message,
    _run(dataset, config2) {
      if (dataset.value === null) {
        _addIssue(this, "type", dataset, config2);
        return dataset;
      }
      return this.wrapped._run(dataset, config2);
    }
  };
}

// src/schemas/nonNullable/nonNullableAsync.ts
function nonNullableAsync(wrapped, message) {
  return {
    kind: "schema",
    type: "non_nullable",
    reference: nonNullableAsync,
    expects: "!null",
    async: true,
    wrapped,
    message,
    async _run(dataset, config2) {
      if (dataset.value === null) {
        _addIssue(this, "type", dataset, config2);
        return dataset;
      }
      return this.wrapped._run(dataset, config2);
    }
  };
}

// src/schemas/nonNullish/nonNullish.ts
function nonNullish(wrapped, message) {
  return {
    kind: "schema",
    type: "non_nullish",
    reference: nonNullish,
    expects: "!null & !undefined",
    async: false,
    wrapped,
    message,
    _run(dataset, config2) {
      if (dataset.value === null || dataset.value === void 0) {
        _addIssue(this, "type", dataset, config2);
        return dataset;
      }
      return this.wrapped._run(dataset, config2);
    }
  };
}

// src/schemas/nonNullish/nonNullishAsync.ts
function nonNullishAsync(wrapped, message) {
  return {
    kind: "schema",
    type: "non_nullish",
    reference: nonNullishAsync,
    expects: "!null & !undefined",
    async: true,
    wrapped,
    message,
    async _run(dataset, config2) {
      if (dataset.value === null || dataset.value === void 0) {
        _addIssue(this, "type", dataset, config2);
        return dataset;
      }
      return this.wrapped._run(dataset, config2);
    }
  };
}

// src/schemas/nonOptional/nonOptional.ts
function nonOptional(wrapped, message) {
  return {
    kind: "schema",
    type: "non_optional",
    reference: nonOptional,
    expects: "!undefined",
    async: false,
    wrapped,
    message,
    _run(dataset, config2) {
      if (dataset.value === void 0) {
        _addIssue(this, "type", dataset, config2);
        return dataset;
      }
      return this.wrapped._run(dataset, config2);
    }
  };
}

// src/schemas/nonOptional/nonOptionalAsync.ts
function nonOptionalAsync(wrapped, message) {
  return {
    kind: "schema",
    type: "non_optional",
    reference: nonOptionalAsync,
    expects: "!undefined",
    async: true,
    wrapped,
    message,
    async _run(dataset, config2) {
      if (dataset.value === void 0) {
        _addIssue(this, "type", dataset, config2);
        return dataset;
      }
      return this.wrapped._run(dataset, config2);
    }
  };
}

// src/schemas/null/null.ts
function null_(message) {
  return {
    kind: "schema",
    type: "null",
    reference: null_,
    expects: "null",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value === null) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/nullable/nullable.ts
function nullable(wrapped, ...args) {
  const schema = {
    kind: "schema",
    type: "nullable",
    reference: nullable,
    expects: `${wrapped.expects} | null`,
    async: false,
    wrapped,
    _run(dataset, config2) {
      if (dataset.value === null) {
        if ("default" in this) {
          dataset.value = getDefault(
            this,
            dataset,
            config2
          );
        }
        if (dataset.value === null) {
          dataset.typed = true;
          return dataset;
        }
      }
      return this.wrapped._run(dataset, config2);
    }
  };
  if (0 in args) {
    schema.default = args[0];
  }
  return schema;
}

// src/schemas/nullable/nullableAsync.ts
function nullableAsync(wrapped, ...args) {
  const schema = {
    kind: "schema",
    type: "nullable",
    reference: nullableAsync,
    expects: `${wrapped.expects} | null`,
    async: true,
    wrapped,
    async _run(dataset, config2) {
      if (dataset.value === null) {
        if ("default" in this) {
          dataset.value = await getDefault(
            this,
            dataset,
            config2
          );
        }
        if (dataset.value === null) {
          dataset.typed = true;
          return dataset;
        }
      }
      return this.wrapped._run(dataset, config2);
    }
  };
  if (0 in args) {
    schema.default = args[0];
  }
  return schema;
}

// src/schemas/nullish/nullish.ts
function nullish(wrapped, ...args) {
  const schema = {
    kind: "schema",
    type: "nullish",
    reference: nullish,
    expects: `${wrapped.expects} | null | undefined`,
    async: false,
    wrapped,
    _run(dataset, config2) {
      if (dataset.value === null || dataset.value === void 0) {
        if ("default" in this) {
          dataset.value = getDefault(
            this,
            dataset,
            config2
          );
        }
        if (dataset.value === null || dataset.value === void 0) {
          dataset.typed = true;
          return dataset;
        }
      }
      return this.wrapped._run(dataset, config2);
    }
  };
  if (0 in args) {
    schema.default = args[0];
  }
  return schema;
}

// src/schemas/nullish/nullishAsync.ts
function nullishAsync(wrapped, ...args) {
  const schema = {
    kind: "schema",
    type: "nullish",
    reference: nullishAsync,
    expects: `${wrapped.expects} | null | undefined`,
    async: true,
    wrapped,
    async _run(dataset, config2) {
      if (dataset.value === null || dataset.value === void 0) {
        if ("default" in this) {
          dataset.value = await getDefault(
            this,
            dataset,
            config2
          );
        }
        if (dataset.value === null || dataset.value === void 0) {
          dataset.typed = true;
          return dataset;
        }
      }
      return this.wrapped._run(dataset, config2);
    }
  };
  if (0 in args) {
    schema.default = args[0];
  }
  return schema;
}

// src/schemas/number/number.ts
function number(message) {
  return {
    kind: "schema",
    type: "number",
    reference: number,
    expects: "number",
    async: false,
    message,
    _run(dataset, config2) {
      if (typeof dataset.value === "number" && !isNaN(dataset.value)) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/object/object.ts
function object(entries, message) {
  return {
    kind: "schema",
    type: "object",
    reference: object,
    expects: "Object",
    async: false,
    entries,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        for (const key in this.entries) {
          const value2 = input[key];
          const valueDataset = this.entries[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/object/objectAsync.ts
function objectAsync(entries, message) {
  return {
    kind: "schema",
    type: "object",
    reference: objectAsync,
    expects: "Object",
    async: true,
    entries,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        const valueDatasets = await Promise.all(
          Object.entries(this.entries).map(async ([key, schema]) => {
            const value2 = input[key];
            return [
              key,
              value2,
              await schema._run({ typed: false, value: value2 }, config2)
            ];
          })
        );
        for (const [key, value2, valueDataset] of valueDatasets) {
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/objectWithRest/objectWithRest.ts
function objectWithRest(entries, rest, message) {
  return {
    kind: "schema",
    type: "object_with_rest",
    reference: objectWithRest,
    expects: "Object",
    async: false,
    entries,
    rest,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        for (const key in this.entries) {
          const value2 = input[key];
          const valueDataset = this.entries[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const key in input) {
            if (_isValidObjectKey(input, key) && !(key in this.entries)) {
              const value2 = input[key];
              const valueDataset = this.rest._run(
                { typed: false, value: value2 },
                config2
              );
              if (valueDataset.issues) {
                const pathItem = {
                  type: "object",
                  origin: "value",
                  input,
                  key,
                  value: value2
                };
                for (const issue of valueDataset.issues) {
                  if (issue.path) {
                    issue.path.unshift(pathItem);
                  } else {
                    issue.path = [pathItem];
                  }
                  dataset.issues?.push(issue);
                }
                if (!dataset.issues) {
                  dataset.issues = valueDataset.issues;
                }
                if (config2.abortEarly) {
                  dataset.typed = false;
                  break;
                }
              }
              if (!valueDataset.typed) {
                dataset.typed = false;
              }
              dataset.value[key] = valueDataset.value;
            }
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/objectWithRest/objectWithRestAsync.ts
function objectWithRestAsync(entries, rest, message) {
  return {
    kind: "schema",
    type: "object_with_rest",
    reference: objectWithRestAsync,
    expects: "Object",
    async: true,
    entries,
    rest,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        const [normalDatasets, restDatasets] = await Promise.all([
          // Parse schema of each normal entry
          Promise.all(
            Object.entries(this.entries).map(async ([key, schema]) => {
              const value2 = input[key];
              return [
                key,
                value2,
                await schema._run({ typed: false, value: value2 }, config2)
              ];
            })
          ),
          // Parse other entries with rest schema
          Promise.all(
            Object.entries(input).filter(
              ([key]) => _isValidObjectKey(input, key) && !(key in this.entries)
            ).map(
              async ([key, value2]) => [
                key,
                value2,
                await this.rest._run({ typed: false, value: value2 }, config2)
              ]
            )
          )
        ]);
        for (const [key, value2, valueDataset] of normalDatasets) {
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const [key, value2, valueDataset] of restDatasets) {
            if (valueDataset.issues) {
              const pathItem = {
                type: "object",
                origin: "value",
                input,
                key,
                value: value2
              };
              for (const issue of valueDataset.issues) {
                if (issue.path) {
                  issue.path.unshift(pathItem);
                } else {
                  issue.path = [pathItem];
                }
                dataset.issues?.push(issue);
              }
              if (!dataset.issues) {
                dataset.issues = valueDataset.issues;
              }
              if (config2.abortEarly) {
                dataset.typed = false;
                break;
              }
            }
            if (!valueDataset.typed) {
              dataset.typed = false;
            }
            dataset.value[key] = valueDataset.value;
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/optional/optional.ts
function optional(wrapped, ...args) {
  const schema = {
    kind: "schema",
    type: "optional",
    reference: optional,
    expects: `${wrapped.expects} | undefined`,
    async: false,
    wrapped,
    _run(dataset, config2) {
      if (dataset.value === void 0) {
        if ("default" in this) {
          dataset.value = getDefault(
            this,
            dataset,
            config2
          );
        }
        if (dataset.value === void 0) {
          dataset.typed = true;
          return dataset;
        }
      }
      return this.wrapped._run(dataset, config2);
    }
  };
  if (0 in args) {
    schema.default = args[0];
  }
  return schema;
}

// src/schemas/optional/optionalAsync.ts
function optionalAsync(wrapped, ...args) {
  const schema = {
    kind: "schema",
    type: "optional",
    reference: optionalAsync,
    expects: `${wrapped.expects} | undefined`,
    async: true,
    wrapped,
    async _run(dataset, config2) {
      if (dataset.value === void 0) {
        if ("default" in this) {
          dataset.value = await getDefault(
            this,
            dataset,
            config2
          );
        }
        if (dataset.value === void 0) {
          dataset.typed = true;
          return dataset;
        }
      }
      return this.wrapped._run(dataset, config2);
    }
  };
  if (0 in args) {
    schema.default = args[0];
  }
  return schema;
}

// src/schemas/picklist/picklist.ts
function picklist(options, message) {
  return {
    kind: "schema",
    type: "picklist",
    reference: picklist,
    expects: options.map(_stringify).join(" | ") || "never",
    async: false,
    options,
    message,
    _run(dataset, config2) {
      if (this.options.includes(dataset.value)) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/promise/promise.ts
function promise(message) {
  return {
    kind: "schema",
    type: "promise",
    reference: promise,
    expects: "Promise",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value instanceof Promise) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/record/record.ts
function record(key, value2, message) {
  return {
    kind: "schema",
    type: "record",
    reference: record,
    expects: "Object",
    async: false,
    key,
    value: value2,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        for (const entryKey in input) {
          if (_isValidObjectKey(input, entryKey)) {
            const entryValue = input[entryKey];
            const keyDataset = this.key._run(
              { typed: false, value: entryKey },
              config2
            );
            if (keyDataset.issues) {
              const pathItem = {
                type: "object",
                origin: "key",
                input,
                key: entryKey,
                value: entryValue
              };
              for (const issue of keyDataset.issues) {
                issue.path = [pathItem];
                dataset.issues?.push(issue);
              }
              if (!dataset.issues) {
                dataset.issues = keyDataset.issues;
              }
              if (config2.abortEarly) {
                dataset.typed = false;
                break;
              }
            }
            const valueDataset = this.value._run(
              { typed: false, value: entryValue },
              config2
            );
            if (valueDataset.issues) {
              const pathItem = {
                type: "object",
                origin: "value",
                input,
                key: entryKey,
                value: entryValue
              };
              for (const issue of valueDataset.issues) {
                if (issue.path) {
                  issue.path.unshift(pathItem);
                } else {
                  issue.path = [pathItem];
                }
                dataset.issues?.push(issue);
              }
              if (!dataset.issues) {
                dataset.issues = valueDataset.issues;
              }
              if (config2.abortEarly) {
                dataset.typed = false;
                break;
              }
            }
            if (!keyDataset.typed || !valueDataset.typed) {
              dataset.typed = false;
            }
            if (keyDataset.typed) {
              dataset.value[keyDataset.value] = valueDataset.value;
            }
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/record/recordAsync.ts
function recordAsync(key, value2, message) {
  return {
    kind: "schema",
    type: "record",
    reference: recordAsync,
    expects: "Object",
    async: true,
    key,
    value: value2,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        const datasets = await Promise.all(
          Object.entries(input).filter(([key2]) => _isValidObjectKey(input, key2)).map(
            ([entryKey, entryValue]) => Promise.all([
              entryKey,
              entryValue,
              this.key._run({ typed: false, value: entryKey }, config2),
              this.value._run({ typed: false, value: entryValue }, config2)
            ])
          )
        );
        for (const [
          entryKey,
          entryValue,
          keyDataset,
          valueDataset
        ] of datasets) {
          if (keyDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "key",
              input,
              key: entryKey,
              value: entryValue
            };
            for (const issue of keyDataset.issues) {
              issue.path = [pathItem];
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = keyDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key: entryKey,
              value: entryValue
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!keyDataset.typed || !valueDataset.typed) {
            dataset.typed = false;
          }
          if (keyDataset.typed) {
            dataset.value[keyDataset.value] = valueDataset.value;
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/set/set.ts
function set(value2, message) {
  return {
    kind: "schema",
    type: "set",
    reference: set,
    expects: "Set",
    async: false,
    value: value2,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input instanceof Set) {
        dataset.typed = true;
        dataset.value = /* @__PURE__ */ new Set();
        for (const inputValue of input) {
          const valueDataset = this.value._run(
            { typed: false, value: inputValue },
            config2
          );
          if (valueDataset.issues) {
            const pathItem = {
              type: "set",
              origin: "value",
              input,
              key: null,
              value: inputValue
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.add(valueDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/set/setAsync.ts
function setAsync(value2, message) {
  return {
    kind: "schema",
    type: "set",
    reference: setAsync,
    expects: "Set",
    async: true,
    value: value2,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input instanceof Set) {
        dataset.typed = true;
        dataset.value = /* @__PURE__ */ new Set();
        const valueDatasets = await Promise.all(
          [...input].map(
            async (inputValue) => [
              inputValue,
              await this.value._run(
                { typed: false, value: inputValue },
                config2
              )
            ]
          )
        );
        for (const [inputValue, valueDataset] of valueDatasets) {
          if (valueDataset.issues) {
            const pathItem = {
              type: "set",
              origin: "value",
              input,
              key: null,
              value: inputValue
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.add(valueDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/strictObject/strictObject.ts
function strictObject(entries, message) {
  return {
    kind: "schema",
    type: "strict_object",
    reference: strictObject,
    expects: "Object",
    async: false,
    entries,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        for (const key in this.entries) {
          const value2 = input[key];
          const valueDataset = this.entries[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const key in input) {
            if (!(key in this.entries)) {
              const value2 = input[key];
              _addIssue(this, "type", dataset, config2, {
                input: value2,
                expected: "never",
                path: [
                  {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: value2
                  }
                ]
              });
              break;
            }
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/strictObject/strictObjectAsync.ts
function strictObjectAsync(entries, message) {
  return {
    kind: "schema",
    type: "strict_object",
    reference: strictObjectAsync,
    expects: "Object",
    async: true,
    entries,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        dataset.typed = true;
        dataset.value = {};
        const valueDatasets = await Promise.all(
          Object.entries(this.entries).map(async ([key, schema]) => {
            const value2 = input[key];
            return [
              key,
              value2,
              await schema._run({ typed: false, value: value2 }, config2)
            ];
          })
        );
        for (const [key, value2, valueDataset] of valueDatasets) {
          if (valueDataset.issues) {
            const pathItem = {
              type: "object",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of valueDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = valueDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!valueDataset.typed) {
            dataset.typed = false;
          }
          if (valueDataset.value !== void 0 || key in input) {
            dataset.value[key] = valueDataset.value;
          }
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const key in input) {
            if (!(key in this.entries)) {
              const value2 = input[key];
              _addIssue(this, "type", dataset, config2, {
                input: value2,
                expected: "never",
                path: [
                  {
                    type: "object",
                    origin: "value",
                    input,
                    key,
                    value: value2
                  }
                ]
              });
              break;
            }
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/strictTuple/strictTuple.ts
function strictTuple(items, message) {
  return {
    kind: "schema",
    type: "strict_tuple",
    reference: strictTuple,
    expects: "Array",
    async: false,
    items,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        for (let key = 0; key < this.items.length; key++) {
          const value2 = input[key];
          const itemDataset = this.items[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
        if (!(dataset.issues && config2.abortEarly) && this.items.length < input.length) {
          const value2 = input[items.length];
          _addIssue(this, "type", dataset, config2, {
            input: value2,
            expected: "never",
            path: [
              {
                type: "array",
                origin: "value",
                input,
                key: this.items.length,
                value: value2
              }
            ]
          });
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/strictTuple/strictTupleAsync.ts
function strictTupleAsync(items, message) {
  return {
    kind: "schema",
    type: "strict_tuple",
    reference: strictTupleAsync,
    expects: "Array",
    async: true,
    items,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        const itemDatasets = await Promise.all(
          this.items.map(async (item, key) => {
            const value2 = input[key];
            return [
              key,
              value2,
              await item._run({ typed: false, value: value2 }, config2)
            ];
          })
        );
        for (const [key, value2, itemDataset] of itemDatasets) {
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
        if (!(dataset.issues && config2.abortEarly) && this.items.length < input.length) {
          const value2 = input[items.length];
          _addIssue(this, "type", dataset, config2, {
            input: value2,
            expected: "never",
            path: [
              {
                type: "array",
                origin: "value",
                input,
                key: this.items.length,
                value: value2
              }
            ]
          });
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/string/string.ts
function string(message) {
  return {
    kind: "schema",
    type: "string",
    reference: string,
    expects: "string",
    async: false,
    message,
    _run(dataset, config2) {
      if (typeof dataset.value === "string") {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/symbol/symbol.ts
function symbol(message) {
  return {
    kind: "schema",
    type: "symbol",
    reference: symbol,
    expects: "symbol",
    async: false,
    message,
    _run(dataset, config2) {
      if (typeof dataset.value === "symbol") {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/tuple/tuple.ts
function tuple(items, message) {
  return {
    kind: "schema",
    type: "tuple",
    reference: tuple,
    expects: "Array",
    async: false,
    items,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        for (let key = 0; key < this.items.length; key++) {
          const value2 = input[key];
          const itemDataset = this.items[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/tuple/tupleAsync.ts
function tupleAsync(items, message) {
  return {
    kind: "schema",
    type: "tuple",
    reference: tupleAsync,
    expects: "Array",
    async: true,
    items,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        const itemDatasets = await Promise.all(
          this.items.map(async (item, key) => {
            const value2 = input[key];
            return [
              key,
              value2,
              await item._run({ typed: false, value: value2 }, config2)
            ];
          })
        );
        for (const [key, value2, itemDataset] of itemDatasets) {
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/tupleWithRest/tupleWithRest.ts
function tupleWithRest(items, rest, message) {
  return {
    kind: "schema",
    type: "tuple_with_rest",
    reference: tupleWithRest,
    expects: "Array",
    async: false,
    items,
    rest,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        for (let key = 0; key < this.items.length; key++) {
          const value2 = input[key];
          const itemDataset = this.items[key]._run(
            { typed: false, value: value2 },
            config2
          );
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (let key = this.items.length; key < input.length; key++) {
            const value2 = input[key];
            const itemDataset = this.rest._run({ typed: false, value: value2 }, config2);
            if (itemDataset.issues) {
              const pathItem = {
                type: "array",
                origin: "value",
                input,
                key,
                value: value2
              };
              for (const issue of itemDataset.issues) {
                if (issue.path) {
                  issue.path.unshift(pathItem);
                } else {
                  issue.path = [pathItem];
                }
                dataset.issues?.push(issue);
              }
              if (!dataset.issues) {
                dataset.issues = itemDataset.issues;
              }
              if (config2.abortEarly) {
                dataset.typed = false;
                break;
              }
            }
            if (!itemDataset.typed) {
              dataset.typed = false;
            }
            dataset.value.push(itemDataset.value);
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/tupleWithRest/tupleWithRestAsync.ts
function tupleWithRestAsync(items, rest, message) {
  return {
    kind: "schema",
    type: "tuple_with_rest",
    reference: tupleWithRestAsync,
    expects: "Array",
    async: true,
    items,
    rest,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (Array.isArray(input)) {
        dataset.typed = true;
        dataset.value = [];
        const [normalDatasets, restDatasets] = await Promise.all([
          // Parse schema of each normal item
          Promise.all(
            this.items.map(async (item, key) => {
              const value2 = input[key];
              return [
                key,
                value2,
                await item._run({ typed: false, value: value2 }, config2)
              ];
            })
          ),
          // Parse other items with rest schema
          Promise.all(
            input.slice(this.items.length).map(async (value2, key) => {
              return [
                key + this.items.length,
                value2,
                await this.rest._run({ typed: false, value: value2 }, config2)
              ];
            })
          )
        ]);
        for (const [key, value2, itemDataset] of normalDatasets) {
          if (itemDataset.issues) {
            const pathItem = {
              type: "array",
              origin: "value",
              input,
              key,
              value: value2
            };
            for (const issue of itemDataset.issues) {
              if (issue.path) {
                issue.path.unshift(pathItem);
              } else {
                issue.path = [pathItem];
              }
              dataset.issues?.push(issue);
            }
            if (!dataset.issues) {
              dataset.issues = itemDataset.issues;
            }
            if (config2.abortEarly) {
              dataset.typed = false;
              break;
            }
          }
          if (!itemDataset.typed) {
            dataset.typed = false;
          }
          dataset.value.push(itemDataset.value);
        }
        if (!dataset.issues || !config2.abortEarly) {
          for (const [key, value2, itemDataset] of restDatasets) {
            if (itemDataset.issues) {
              const pathItem = {
                type: "array",
                origin: "value",
                input,
                key,
                value: value2
              };
              for (const issue of itemDataset.issues) {
                if (issue.path) {
                  issue.path.unshift(pathItem);
                } else {
                  issue.path = [pathItem];
                }
                dataset.issues?.push(issue);
              }
              if (!dataset.issues) {
                dataset.issues = itemDataset.issues;
              }
              if (config2.abortEarly) {
                dataset.typed = false;
                break;
              }
            }
            if (!itemDataset.typed) {
              dataset.typed = false;
            }
            dataset.value.push(itemDataset.value);
          }
        }
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/undefined/undefined.ts
function undefined_(message) {
  return {
    kind: "schema",
    type: "undefined",
    reference: undefined_,
    expects: "undefined",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value === void 0) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/union/utils/_subIssues/_subIssues.ts
function _subIssues(datasets) {
  let issues;
  if (datasets) {
    for (const dataset of datasets) {
      if (issues) {
        issues.push(...dataset.issues);
      } else {
        issues = dataset.issues;
      }
    }
  }
  return issues;
}

// src/schemas/union/union.ts
function union(options, message) {
  return {
    kind: "schema",
    type: "union",
    reference: union,
    expects: [...new Set(options.map((option) => option.expects))].join(" | ") || "never",
    async: false,
    options,
    message,
    _run(dataset, config2) {
      let validDataset;
      let typedDatasets;
      let untypedDatasets;
      for (const schema of this.options) {
        const optionDataset = schema._run(
          { typed: false, value: dataset.value },
          config2
        );
        if (optionDataset.typed) {
          if (optionDataset.issues) {
            if (typedDatasets) {
              typedDatasets.push(optionDataset);
            } else {
              typedDatasets = [optionDataset];
            }
          } else {
            validDataset = optionDataset;
            break;
          }
        } else {
          if (untypedDatasets) {
            untypedDatasets.push(optionDataset);
          } else {
            untypedDatasets = [optionDataset];
          }
        }
      }
      if (validDataset) {
        return validDataset;
      }
      if (typedDatasets) {
        if (typedDatasets.length === 1) {
          return typedDatasets[0];
        }
        _addIssue(this, "type", dataset, config2, {
          issues: _subIssues(typedDatasets)
        });
        dataset.typed = true;
      } else if (untypedDatasets?.length === 1) {
        return untypedDatasets[0];
      } else {
        _addIssue(this, "type", dataset, config2, {
          issues: _subIssues(untypedDatasets)
        });
      }
      return dataset;
    }
  };
}

// src/schemas/union/unionAsync.ts
function unionAsync(options, message) {
  return {
    kind: "schema",
    type: "union",
    reference: unionAsync,
    expects: [...new Set(options.map((option) => option.expects))].join(" | ") || "never",
    async: true,
    options,
    message,
    async _run(dataset, config2) {
      let validDataset;
      let typedDatasets;
      let untypedDatasets;
      for (const schema of this.options) {
        const optionDataset = await schema._run(
          { typed: false, value: dataset.value },
          config2
        );
        if (optionDataset.typed) {
          if (optionDataset.issues) {
            if (typedDatasets) {
              typedDatasets.push(optionDataset);
            } else {
              typedDatasets = [optionDataset];
            }
          } else {
            validDataset = optionDataset;
            break;
          }
        } else {
          if (untypedDatasets) {
            untypedDatasets.push(optionDataset);
          } else {
            untypedDatasets = [optionDataset];
          }
        }
      }
      if (validDataset) {
        return validDataset;
      }
      if (typedDatasets) {
        if (typedDatasets.length === 1) {
          return typedDatasets[0];
        }
        _addIssue(this, "type", dataset, config2, {
          issues: _subIssues(typedDatasets)
        });
        dataset.typed = true;
      } else if (untypedDatasets?.length === 1) {
        return untypedDatasets[0];
      } else {
        _addIssue(this, "type", dataset, config2, {
          issues: _subIssues(untypedDatasets)
        });
      }
      return dataset;
    }
  };
}

// src/schemas/unknown/unknown.ts
function unknown() {
  return {
    kind: "schema",
    type: "unknown",
    reference: unknown,
    expects: "unknown",
    async: false,
    _run(dataset) {
      dataset.typed = true;
      return dataset;
    }
  };
}

// src/schemas/variant/utils/_discriminators/_discriminators.ts
function _discriminators(key, options, set2 = /* @__PURE__ */ new Set()) {
  for (const schema of options) {
    if (schema.type === "variant") {
      _discriminators(key, schema.options, set2);
    } else {
      set2.add(schema.entries[key].expects);
    }
  }
  return set2;
}

// src/schemas/variant/variant.ts
function variant(key, options, message) {
  let expectedDiscriminators;
  return {
    kind: "schema",
    type: "variant",
    reference: variant,
    expects: "Object",
    async: false,
    key,
    options,
    message,
    _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        const discriminator = input[this.key];
        if (this.key in input) {
          let outputDataset;
          for (const schema of this.options) {
            if (schema.type === "variant" || !schema.entries[this.key]._run(
              { typed: false, value: discriminator },
              config2
            ).issues) {
              const optionDataset = schema._run(
                { typed: false, value: input },
                config2
              );
              if (!optionDataset.issues) {
                return optionDataset;
              }
              if (!outputDataset || !outputDataset.typed && optionDataset.typed) {
                outputDataset = optionDataset;
              }
            }
          }
          if (outputDataset) {
            return outputDataset;
          }
        }
        if (!expectedDiscriminators) {
          expectedDiscriminators = [..._discriminators(this.key, this.options)].join(" | ") || "never";
        }
        _addIssue(this, "type", dataset, config2, {
          input: discriminator,
          expected: expectedDiscriminators,
          path: [
            {
              type: "object",
              origin: "value",
              input,
              key: this.key,
              value: discriminator
            }
          ]
        });
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/variant/variantAsync.ts
function variantAsync(key, options, message) {
  let expectedDiscriminators;
  return {
    kind: "schema",
    type: "variant",
    reference: variantAsync,
    expects: "Object",
    async: true,
    key,
    options,
    message,
    async _run(dataset, config2) {
      const input = dataset.value;
      if (input && typeof input === "object") {
        const discriminator = input[this.key];
        if (this.key in input) {
          let outputDataset;
          for (const schema of this.options) {
            if (schema.type === "variant" || !(await schema.entries[this.key]._run(
              { typed: false, value: discriminator },
              config2
            )).issues) {
              const optionDataset = await schema._run(
                { typed: false, value: input },
                config2
              );
              if (!optionDataset.issues) {
                return optionDataset;
              }
              if (!outputDataset || !outputDataset.typed && optionDataset.typed) {
                outputDataset = optionDataset;
              }
            }
          }
          if (outputDataset) {
            return outputDataset;
          }
        }
        if (!expectedDiscriminators) {
          expectedDiscriminators = [..._discriminators(this.key, this.options)].join(" | ") || "never";
        }
        _addIssue(this, "type", dataset, config2, {
          input: discriminator,
          expected: expectedDiscriminators,
          path: [
            {
              type: "object",
              origin: "value",
              input,
              key: this.key,
              value: discriminator
            }
          ]
        });
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/schemas/void/void.ts
function void_(message) {
  return {
    kind: "schema",
    type: "void",
    reference: void_,
    expects: "void",
    async: false,
    message,
    _run(dataset, config2) {
      if (dataset.value === void 0) {
        dataset.typed = true;
      } else {
        _addIssue(this, "type", dataset, config2);
      }
      return dataset;
    }
  };
}

// src/methods/keyof/keyof.ts
function keyof(schema, message) {
  return picklist(Object.keys(schema.entries), message);
}

// src/methods/omit/omit.ts
function omit(schema, keys) {
  const entries = {
    ...schema.entries
  };
  for (const key of keys) {
    delete entries[key];
  }
  return { ...schema, entries };
}

// src/methods/parse/parse.ts
function parse(schema, input, config2) {
  const dataset = schema._run(
    { typed: false, value: input },
    getGlobalConfig(config2)
  );
  if (dataset.issues) {
    throw new ValiError(dataset.issues);
  }
  return dataset.value;
}

// src/methods/parse/parseAsync.ts
async function parseAsync(schema, input, config2) {
  const dataset = await schema._run(
    { typed: false, value: input },
    getGlobalConfig(config2)
  );
  if (dataset.issues) {
    throw new ValiError(dataset.issues);
  }
  return dataset.value;
}

// src/methods/parser/parser.ts
function parser(schema, config2) {
  const func = (input) => parse(schema, input, config2);
  func.schema = schema;
  func.config = config2;
  return func;
}

// src/methods/parser/parserAsync.ts
function parserAsync(schema, config2) {
  const func = (input) => parseAsync(schema, input, config2);
  func.schema = schema;
  func.config = config2;
  return func;
}

// src/methods/partial/partial.ts
function partial(schema, keys) {
  const entries = {};
  for (const key in schema.entries) {
    entries[key] = !keys || keys.includes(key) ? optional(schema.entries[key]) : schema.entries[key];
  }
  return { ...schema, entries };
}

// src/methods/partial/partialAsync.ts
function partialAsync(schema, keys) {
  const entries = {};
  for (const key in schema.entries) {
    entries[key] = !keys || keys.includes(key) ? optionalAsync(schema.entries[key]) : schema.entries[key];
  }
  return { ...schema, entries };
}

// src/methods/pick/pick.ts
function pick(schema, keys) {
  const entries = {};
  for (const key of keys) {
    entries[key] = schema.entries[key];
  }
  return { ...schema, entries };
}

// src/methods/pipe/pipe.ts
function pipe(...pipe2) {
  return {
    ...pipe2[0],
    pipe: pipe2,
    _run(dataset, config2) {
      for (let index = 0; index < pipe2.length; index++) {
        if (dataset.issues && (pipe2[index].kind === "schema" || pipe2[index].kind === "transformation")) {
          dataset.typed = false;
          break;
        }
        if (!dataset.issues || !config2.abortEarly && !config2.abortPipeEarly) {
          dataset = pipe2[index]._run(dataset, config2);
        }
      }
      return dataset;
    }
  };
}

// src/methods/pipe/pipeAsync.ts
function pipeAsync(...pipe2) {
  return {
    ...pipe2[0],
    pipe: pipe2,
    async: true,
    async _run(dataset, config2) {
      for (let index = 0; index < pipe2.length; index++) {
        if (dataset.issues && (pipe2[index].kind === "schema" || pipe2[index].kind === "transformation")) {
          dataset.typed = false;
          break;
        }
        if (!dataset.issues || !config2.abortEarly && !config2.abortPipeEarly) {
          dataset = await pipe2[index]._run(dataset, config2);
        }
      }
      return dataset;
    }
  };
}

// src/methods/required/required.ts
function required(schema, arg2, arg3) {
  const keys = Array.isArray(arg2) ? arg2 : void 0;
  const message = Array.isArray(arg2) ? arg3 : arg2;
  const entries = {};
  for (const key in schema.entries) {
    entries[key] = !keys || keys.includes(key) ? nonOptional(schema.entries[key], message) : schema.entries[key];
  }
  return { ...schema, entries };
}

// src/methods/required/requiredAsync.ts
function requiredAsync(schema, arg2, arg3) {
  const keys = Array.isArray(arg2) ? arg2 : void 0;
  const message = Array.isArray(arg2) ? arg3 : arg2;
  const entries = {};
  for (const key in schema.entries) {
    entries[key] = !keys || keys.includes(key) ? nonOptionalAsync(schema.entries[key], message) : schema.entries[key];
  }
  return { ...schema, entries };
}

// src/methods/safeParse/safeParse.ts
function safeParse(schema, input, config2) {
  const dataset = schema._run(
    { typed: false, value: input },
    getGlobalConfig(config2)
  );
  return {
    typed: dataset.typed,
    success: !dataset.issues,
    output: dataset.value,
    issues: dataset.issues
  };
}

// src/methods/safeParse/safeParseAsync.ts
async function safeParseAsync(schema, input, config2) {
  const dataset = await schema._run(
    { typed: false, value: input },
    getGlobalConfig(config2)
  );
  return {
    typed: dataset.typed,
    success: !dataset.issues,
    output: dataset.value,
    issues: dataset.issues
  };
}

// src/methods/safeParser/safeParser.ts
function safeParser(schema, config2) {
  const func = (input) => safeParse(schema, input, config2);
  func.schema = schema;
  func.config = config2;
  return func;
}

// src/methods/safeParser/safeParserAsync.ts
function safeParserAsync(schema, config2) {
  const func = (input) => safeParseAsync(schema, input, config2);
  func.schema = schema;
  func.config = config2;
  return func;
}

// src/methods/unwrap/unwrap.ts
function unwrap(schema) {
  return schema.wrapped;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (0);


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it uses a non-standard name for the exports (exports).
(() => {
var exports = __webpack_exports__;

Object.defineProperty(exports, "__esModule", ({ value: true }));
const client_1 = __nccwpck_require__(827);
const main = async () => {
    console.log('contract deploy');
    const suiClient = new client_1.SuiClient({ url: (0, client_1.getFullnodeUrl)('testnet') });
};
main();

})();

module.exports = __webpack_exports__;
/******/ })()
;