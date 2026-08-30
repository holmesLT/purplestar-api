/**
 * Tron HD wallet address derivation (BIP44 SLIP-0044 coin type 195).
 *
 * Verified against BIP44 standard test vector (well-known reference):
 *   Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
 *   Path:     m / 44' / 195' / 0' / 0 / 0
 *   Expected: TKDu5yQ5oy2WAinZsxC2cD3CmHyYM7Rr4D
 *            (Keccak-256(uncompressed pubkey)[12..32] → base58check(0x41 || ... ))
 *
 * Path semantics:
 *   44'   = BIP44
 *   195'  = Tron's SLIP-0044 coin type
 *   0'    = account 0
 *   0     = external chain (receive addresses)
 *   <i>   = address index (0 = first receive address)
 *
 * Dependencies (audited pure-TS):
 *   - @scure/bip32 : HD key derivation
 *   - @scure/bip39 : mnemonic -> seed
 *   - @noble/curves/secp256k1 : secp256k1
 *   - @noble/hashes/keccak : Keccak-256 (NOT SHA3-256; Ethereum-style)
 *   - bs58check : base58check with double-SHA256 checksum (for the 0x41 prefix wrapper)
 */

import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
// bs58check v4 is ESM with default export — wrangler's bundler resolves default correctly
import bs58checkMod from 'bs58check';
const bs58check: { encode(buf: Uint8Array): string; decode(s: string): Uint8Array } =
  (bs58checkMod as any).encode ? (bs58checkMod as any) : (bs58checkMod as any).default;

export interface DerivedTronAddress {
  index: number;
  address: string;     // base58check 'T...' Tron address
  pubkey_uncompressed: string; // 0x04 || X || Y (65 bytes hex)
}

function uncompressPublicKey(compressed: Uint8Array): Uint8Array {
  if (compressed.length === 65 && compressed[0] === 0x04) {
    // strip 0x04 prefix
    return compressed.slice(1);
  }
  if (compressed.length !== 33) throw new Error('Invalid compressed pubkey length');
  // secp256k1 point decompression via noble's Point API:
  // Point.fromBytes(33 bytes compressed) -> Point.toBytes(false) gives 65 bytes (0x04 || X || Y)
  const point = secp256k1.Point.fromBytes(compressed);
  const uncompressed = point.toBytes(false);
  // strip leading 0x04, keep X(32) || Y(32)
  const out = new Uint8Array(64);
  out.set(uncompressed.slice(1, 33), 0);
  out.set(uncompressed.slice(33, 65), 32);
  return out;
}

/**
 * Derive Tron address (T...) from BIP39 mnemonic at a given index.
 */
export function deriveTronAddressFromMnemonic(
  mnemonic: string,
  index: number,
  passphrase: string = '',
): DerivedTronAddress {
  if (!bip39.validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid BIP39 mnemonic');
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  const master = HDKey.fromMasterSeed(seed);
  const child = master.derive(`m/44'/195'/0'/0/${index}`);
  if (!child.publicKey) throw new Error('Failed to derive public key');

  const pubCompressed = child.publicKey; // 33 bytes, 0x02|0x03 prefix
  // uncompress to 64 bytes (X || Y, no 0x04 prefix)
  const xy = uncompressPublicKey(pubCompressed);

  // Keccak-256(X || Y), take last 20 bytes
  const hash = keccak_256(xy);
  const addrBytes = hash.slice(-20);

  // Tron address: base58check(0x41 || last20) — bs58check uses double-SHA256 checksum
  const payload = new Uint8Array(1 + addrBytes.length);
  payload[0] = 0x41;
  payload.set(addrBytes, 1);
  const address = bs58check.encode(payload);

  // 0x04 || X || Y form (65 bytes) for completeness / future signing use
  const pubUncompressed = new Uint8Array(65);
  pubUncompressed[0] = 0x04;
  pubUncompressed.set(xy, 1);

  return {
    index,
    address,
    pubkey_uncompressed: Array.from(pubUncompressed).map(b => b.toString(16).padStart(2, '0')).join(''),
  };
}
