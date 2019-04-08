// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// CityHash, by Geoff Pike and Jyrki Alakuijala
//
// This file provides cityhash64() and related functions.
//
// It's probably possible to create even faster hash functions by
// writing a program that systematically explores some of the space of
// possible hash functions, by using SIMD instructions, or by
// compromising on hash quality.

#include <assert.h>
#include <string.h>

#include "cityhash.h"

#define likely(x) (__builtin_expect(!!(x), 1))

#ifdef LITTLE_ENDIAN
#define uint32_t_in_expected_order(x) (x)
#define uint64_t_in_expected_order(x) (x)
#else
#define uint32_t_in_expected_order(x) (bswap32(x))
#define uint64_t_in_expected_order(x) (bswap64(x))
#endif

#define PERMUTE3_64(a, b, c)                                                   \
  do {                                                                         \
    swap64(a, b);                                                              \
    swap64(a, c);                                                              \
  } while (0)

// some primes between 2^63 and 2^64 for various uses
const uint64_t k0 = 0xc3a5c85c97cb3127;
const uint64_t k1 = 0xb492b66fbe98f273;
const uint64_t k2 = 0x9ae16a3b2f90404f;
const uint64_t k3 = 0xc949d7c7509e6557;

static uint64_t uload64(const uint8_t* p) {
  uint64_t result;

  memcpy(&result, p, sizeof(result));

  return result;
}

static uint32_t uload32(const uint8_t* p) {
  uint32_t result;

  memcpy(&result, p, sizeof(result));

  return result;
}

static uint64_t fetch64(const uint8_t* p) {
  return uint64_t_in_expected_order(uload64(p));
}

static uint32_t fetch32(const uint8_t* p) {
  return uint32_t_in_expected_order(uload32(p));
}

static void swap64(uint64_t* a, uint64_t* b) {
  uint64_t t;

  t = *a;
  *a = *b;
  *b = t;
}

// bitwise right rotate, normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
static uint64_t rotate64(uint64_t val, size_t shift) {

  assert(shift < 64);
  return (val >> shift) | (val << (64 - shift));
}

static uint64_t smix(uint64_t val) { return val ^ (val >> 47); }

static uint64_t hash_16(uint64_t u, uint64_t v) {

  uint128_t result = {u, v};
  return hash_128_to_64(result);
}

static uint64_t hash_0_to_16(const uint8_t* s, size_t len) {

  if (len > 8) {

    uint64_t a = fetch64(s);
    uint64_t b = fetch64(s + len - 8);

    return hash_16(a, rotate64(b + len, len)) ^ b;
  }

  if (len >= 4) {

    uint64_t a = fetch32(s);

    return hash_16(len + (a << 3), fetch32(s + len - 4));
  }

  if (len > 0) {

    uint8_t a = s[0];
    uint8_t b = s[len >> 1];
    uint8_t c = s[len - 1];
    uint32_t y = ((uint32_t)a) + (((uint32_t)b) << 8);
    uint32_t z = len + (((uint32_t)c) << 2);

    return smix(y * k2 ^ z * k3) * k2;
  }

  return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
static uint64_t hash_17_to_32(const uint8_t* s, size_t len) {

  uint64_t a = fetch64(s) * k1;
  uint64_t b = fetch64(s + 8);
  uint64_t c = fetch64(s + len - 8) * k2;
  uint64_t d = fetch64(s + len - 16) * k0;

  return hash_16(rotate64(a - b, 43) + rotate64(c, 30) + d,
                   a + rotate64(b ^ k3, 20) - c + len);
}

// return a 16-byte hash for 48 bytes, quick and dirty
// callers do best to use "random-looking" values for a and b
static uint128_t weak_hash_32_with_seeds(uint64_t w, uint64_t x, uint64_t y,
                                         uint64_t z, uint64_t a, uint64_t b) {

  a += w;
  b = rotate64(b + a + z, 21);
  uint64_t c = a;
  a += x;
  a += y;
  b += rotate64(a, 44);

  uint128_t result = {a + z, b + c};

  return result;
}

// return a 16-byte hash for s[0] ... s[31], a, and b, quick and dirty
static uint128_t weak_hash_32_with_seeds_raw(const uint8_t* s, uint64_t a,
                                             uint64_t b) {

  return weak_hash_32_with_seeds(fetch64(s), fetch64(s + 8), fetch64(s + 16),
                                 fetch64(s + 24), a, b);
}

// return an 8-byte hash for 33 to 64 bytes
static uint64_t hash_33_to_64(const uint8_t* s, size_t len) {

  uint64_t z = fetch64(s + 24);
  uint64_t a = fetch64(s) + (len + fetch64(s + len - 16)) * k0;
  uint64_t b = rotate64(a + z, 52);
  uint64_t c = rotate64(a, 37);
  a += fetch64(s + 8);
  c += rotate64(a, 7);
  a += fetch64(s + 16);
  uint64_t vf = a + z;
  uint64_t vs = b + rotate64(a, 31) + c;
  a = fetch64(s + 16) + fetch64(s + len - 32);
  z = fetch64(s + len - 8);
  b = rotate64(a + z, 52);
  c = rotate64(a, 37);
  a += fetch64(s + len - 24);
  c += rotate64(a, 7);
  a += fetch64(s + len - 16);
  uint64_t wf = a + z;
  uint64_t ws = b + rotate64(a, 31) + c;
  uint64_t r = smix((vf + ws) * k2 + (wf + vs) * k0);
  return smix(r * k0 + vs) * k2;
}

uint64_t cityhash64(const uint8_t* s, size_t len) {

  if (len <= 32) {

    if (len <= 16) {

      return hash_0_to_16(s, len);
    } else {

      return hash_17_to_32(s, len);
    }
  } else if (len <= 64) {

    return hash_33_to_64(s, len);
  }

  // for strings over 64 bytes we hash the end first, and then as we
  // loop we keep 56 bytes of state: v, w, x, y, and z
  uint64_t x = fetch64(s);
  uint64_t y = fetch64(s + len - 16) ^ k1;
  uint64_t z = fetch64(s + len - 56) ^ k0;
  uint128_t v = weak_hash_32_with_seeds_raw(s + len - 64, len, y);
  uint128_t w = weak_hash_32_with_seeds_raw(s + len - 32, len * k1, k0);
  z += smix(v.b) * k1;
  x = rotate64(z + x, 39) * k1;
  y = rotate64(y, 33) * k1;

  // decrease len to the nearest multiple of 64, and operate on 64-byte chunks
  len = (len - 1) & ~((size_t)63);

  do {

    x = rotate64(x + y + v.a + fetch64(s + 16), 37) * k1;
    y = rotate64(y + v.b + fetch64(s + 48), 42) * k1;
    x ^= w.b;
    y ^= v.a;
    z = rotate64(z ^ w.a, 33);
    v = weak_hash_32_with_seeds_raw(s, v.b * k1, x + w.a);
    w = weak_hash_32_with_seeds_raw(s + 32, z + w.b, y);
    swap64(&z, &x);
    s += 64;
    len -= 64;
  } while (len != 0);

  return hash_16(hash_16(v.a, w.a) + smix(y) * k1 + z, hash_16(v.b, w.b) + x);
}

uint64_t cityhash64_with_seed(const uint8_t* s, size_t len, uint64_t seed) {
  return cityhash64_with_seeds(s, len, k2, seed);
}

uint64_t cityhash64_with_seeds(const uint8_t* s, size_t len, uint64_t seed0,
                               uint64_t seed1) {
  return hash_16(cityhash64(s, len) - seed0, seed1);
}

// a subroutine for cityhash128(), returns a decent 128-bit hash for strings
// of any length representable in signed long, based on city and murmur
static uint128_t city_murmur(const uint8_t* s, size_t len, uint128_t seed) {

  uint64_t a = seed.a;
  uint64_t b = seed.b;
  uint64_t c = 0;
  uint64_t d = 0;
  signed long l = len - 16;

  if (l <= 0) { // len <= 16

    a = smix(a * k1) * k1;
    c = b * k1 + hash_0_to_16(s, len);
    d = smix(a + (len >= 8 ? fetch64(s) : c));
  } else { // len > 16

    c = hash_16(fetch64(s + len - 8) + k1, a);
    d = hash_16(b + len, c + fetch64(s + len - 16));
    a += d;

    do {

      a ^= smix(fetch64(s) * k1) * k1;
      a *= k1;
      b ^= a;
      c ^= smix(fetch64(s + 8) * k1) * k1;
      c *= k1;
      d ^= c;
      s += 16;
      l -= 16;
    } while (l > 0);
  }

  a = hash_16(a, c);
  b = hash_16(d, b);

  uint128_t result = {a ^ b, hash_16(b, a)};

  return result;
}

uint128_t cityhash128_with_seed(const uint8_t* s, size_t len, uint128_t seed) {

  if (len < 128) {
    return city_murmur(s, len, seed);
  }

  // we expect len >= 128 to be the common case, keep 56 bytes of state:
  // v, w, x, y, and z
  uint128_t v, w;
  uint64_t x = seed.a;
  uint64_t y = seed.b;
  uint64_t z = len * k1;

  v.a = rotate64(y ^ k1, 49) * k1 + fetch64(s);
  v.b = rotate64(v.a, 42) * k1 + fetch64(s + 8);
  w.a = rotate64(y + z, 35) * k1 + x;
  w.b = rotate64(x + fetch64(s + 88), 53) * k1;

  // this is the same inner loop as cityhash64(), manually unrolled
  do {

    x = rotate64(x + y + v.a + fetch64(s + 16), 37) * k1;
    y = rotate64(y + v.b + fetch64(s + 48), 42) * k1;
    x ^= w.b;
    y ^= v.a;
    z = rotate64(z ^ w.a, 33);
    v = weak_hash_32_with_seeds_raw(s, v.b * k1, x + w.a);
    w = weak_hash_32_with_seeds_raw(s + 32, z + w.b, y);
    swap64(&z, &x);
    s += 64;
    x = rotate64(x + y + v.a + fetch64(s + 16), 37) * k1;
    y = rotate64(y + v.b + fetch64(s + 48), 42) * k1;
    x ^= w.b;
    y ^= v.a;
    z = rotate64(z ^ w.a, 33);
    v = weak_hash_32_with_seeds_raw(s, v.b * k1, x + w.a);
    w = weak_hash_32_with_seeds_raw(s + 32, z + w.b, y);
    swap64(&z, &x);
    s += 64;
    len -= 128;
  } while (likely(len >= 128));

  y += rotate64(w.a, 37) * k0 + z;
  x += rotate64(v.a + z, 49) * k0;

  // if 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of s
  for (size_t tail_done = 0; tail_done < len;) {

    tail_done += 32;
    y = rotate64(y - x, 42) * k0 + v.b;
    w.a += fetch64(s + len - tail_done + 16);
    x = rotate64(x, 49) * k0 + w.a;
    w.a += v.a;
    v = weak_hash_32_with_seeds_raw(s + len - tail_done, v.a, v.b);
  }

  // at this point our 48 bytes of state should contain more than
  // enough information for a strong 128-bit hash, we use two
  // different 48-byte-to-8-byte hashes to get a 16-byte final result
  x = hash_16(x, v.a);
  y = hash_16(y, w.a);

  uint128_t result = {hash_16(x + v.b, w.b) + y, hash_16(x + w.b, y + v.b)};

  return result;
}

uint128_t cityhash128(const uint8_t* s, size_t len) {

  if (len >= 16) {

    uint128_t seed = {fetch64(s) ^ k3, fetch64(s + 8)};
    return cityhash128_with_seed(s + 16, len - 16, seed);

  } else if (len >= 8) {

    uint128_t seed = {fetch64(s) ^ (len * k0), fetch64(s + len - 8) ^ k1};
    return cityhash128_with_seed(NULL, 0, seed);

  } else {

    uint128_t seed = {k0, k1};
    return cityhash128_with_seed(s, len, seed);
  }
}

// conditionally include declarations for versions of City that require SSE4.2
// instructions to be available
#if defined(__SSE4_2__) && defined(__x86_64)

#include <smmintrin.h>

// requires len >= 240
static uint256_t cityhash256_crc_long(const uint8_t* s, size_t len,
                                      uint32_t seed) {

  uint256_t result;

  uint64_t a = fetch64(s + 56) + k0;
  uint64_t b = fetch64(s + 96) + k0;
  uint64_t c = result.b = hash_16(b, len);
  uint64_t d = result.c = fetch64(s + 120) * k0 + len;
  uint64_t e = fetch64(s + 184) + seed;
  uint64_t f = seed;
  uint64_t g = 0;
  uint64_t h = 0;
  uint64_t i = 0;
  uint64_t j = 0;
  uint64_t t = c + d;

  // 240 bytes of input per iter
  size_t iters = len / 240;
  len -= iters * 240;

  do {
#define CHUNK(multiplier, z)                                  \
  {                                                           \
    uint64_t old_a = a;                                       \
    a = rotate64(b, 41 ^ z) * multiplier + fetch64(s);        \
    b = rotate64(c, 27 ^ z) * multiplier + fetch64(s + 8);    \
    c = rotate64(d, 41 ^ z) * multiplier + fetch64(s + 16);   \
    d = rotate64(e, 33 ^ z) * multiplier + fetch64(s + 24);   \
    e = rotate64(t, 25 ^ z) * multiplier + fetch64(s + 32);   \
    t = old_a;                                                \
  }                                                           \
    f = _mm_crc32_u64(f, a);                                  \
    g = _mm_crc32_u64(g, b);                                  \
    h = _mm_crc32_u64(h, c);                                  \
    i = _mm_crc32_u64(i, d);                                  \
    j = _mm_crc32_u64(j, e);                                  \
    s += 40

    CHUNK(1, 1); CHUNK(k0, 0);
    CHUNK(1, 1); CHUNK(k0, 0);
    CHUNK(1, 1); CHUNK(k0, 0);
  } while (--iters > 0);

  j += i << 32;
  a = hash_16(a, j);
  h += g << 32;
  b = b * k0 + h;
  c = hash_16(c, f) + i;
  d = hash_16(d, e);
  uint128_t v = {j + e, hash_16(h, t)};
  h = v.b + f;
  // If 0 < len < 240, hash chunks of 32 bytes each from the end of s.
  for (size_t tail_done = 0; tail_done < len; ) {
    tail_done += 32;
    c = Rotate(c - a, 42) * k0 + v.b;
    d += Fetch64(s + len - tail_done + 16);
    a = Rotate(a, 49) * k0 + d;
    d += v.a;
    v = weak_hash_32_with_seeds_raw(s + len - tail_done, v.a, v.b);
  }

  // Final mix.
  e = hash_16(a, d) + v.a;
  f = hash_16(b, c) + a;
  g = hash_16(v.a, v.b) + c;
  result.a = e + f + g + h;
  a = smix((a + g) * k0) * k0 + b;
  result.b += a + result.a;
  a = smix(a * k0) * k0 + c;
  result.c += a + result.b;
  a = smix((a + e) * k0) * k0;
  result.d = a + result.c;

  return result;
}

// requires len < 240
static uint256_t cityhash256_crc_short(const uint8_t* s, size_t len) {

  uint8_t buf[240];

  memcpy(buf, s, len);
  memset(buf + len, 0, 240 - len);

  return cityhash256_crc_long(buf, 240, ~((uint32_t)len));
}

uint256_t cityhash256_crc(const uint8_t* s, size_t len) {

  if (likely(len >= 240)) {
    return cityhash256_crc_long(s, len, 0);
  } else {
    return cityhash256_crc_short(s, len);
  }
}

uint128_t cityhash128_crc_with_seed(const uint8_t* s, size_t len,
                                    uint128_t seed) {

  if (len <= 900) {

    return cityhash128_with_seed(s, len, seed);

  } else {

    uint256_t hash = cityhash256_crc(s, len);

    uint64_t u = seed.b + hash.a;
    uint64_t v = seed.a + hash.b;

    uint128_t result = {hash_16(u, v + hash.c),
                        hash_16(rotate64(v, 32), u * k0 + hash.d)};
    return result;
  }
}

uint128_t cityhash128_crc(const uint8_t* s, size_t len) {

  if (len <= 900) {

    return cityhash128(s, len);
  } else {

    uint256_t hash = cityhash256_crc(s, len);
    uint128_t result = {hash.c, hash.d};

    return result;
  }
}

#endif
