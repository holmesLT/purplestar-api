/**
 * XRP HD wallet address derivation.
 *
 * Verified against BIP44 standard test vector:
 *   Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
 *   Path:     m / 44' / 144' / 0' / 0 / 0
 *   Expected: rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3
 *
 * Dependencies (all pure-TS, audited):
 *   - @scure/bip32    : HD key derivation
 *   - @scure/bip39    : mnemonic -> seed
 *   - @noble/curves/secp256k1 : secp256k1 (used by bip32)
 *   - bitcoinjs-lib   : hash160 (ripemd160 + sha256)
 *
 * Path semantics for XRP:
 *   44'  = BIP44 multi-currency standard
 *   144' = XRP's SLIP-0044 coin type
 *   0'   = account 0
 *   0    = external chain (receive addresses)
 *   <i>  = address index (0 = first receive address)
 */

import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import * as bitcoin from 'bitcoinjs-lib';

// Ripple base58 alphabet (no 0/O/I/l)
const RIPPLE_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

function base58EncodeRipple(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '';
  for (let i = 0; i < zeros; i++) str += RIPPLE_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) str += RIPPLE_ALPHABET[digits[i]];
  return str;
}

export interface DerivedAddress {
  index: number;
  address: string;
  pubkey: string; // hex (compressed, 33 bytes)
}

/**
 * Derive XRP classic address from BIP39 mnemonic at a given index.
 *
 * @param mnemonic    - 12/15/18/21/24-word BIP39 mnemonic
 * @param passphrase  - BIP39 passphrase (empty string for none)
 * @param index       - address index (0 = first receive address)
 */
export function deriveXrpAddressFromMnemonic(
  mnemonic: string,
  index: number,
  passphrase: string = '',
): DerivedAddress {
  if (!bip39.validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid BIP39 mnemonic');
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  const master = HDKey.fromMasterSeed(seed);
  const child = master.derive(`m/44'/144'/0'/0/${index}`);
  if (!child.publicKey) throw new Error('Failed to derive public key');

  const pubCompressed = child.publicKey;
  // hash160(pub) = ripemd160(sha256(pub))
  const hash160: Uint8Array = (bitcoin.crypto as any).hash160(pubCompressed);

  // XRP classic address: base58ripple( 0x00 || hash160 || checksum(4 bytes) )
  // checksum = first 4 bytes of double-sha256(0x00 || hash160)
  const accountId = new Uint8Array(1 + hash160.length);
  accountId[0] = 0x00;
  accountId.set(hash160, 1);
  const checksum: Uint8Array = (bitcoin.crypto as any).hash256(accountId).slice(0, 4);
  const full = new Uint8Array(accountId.length + checksum.length);
  full.set(accountId, 0);
  full.set(checksum, accountId.length);

  const address = base58EncodeRipple(full);
  return {
    index,
    address,
    pubkey: Array.from(pubCompressed).map(b => b.toString(16).padStart(2, '0')).join(''),
  };
}
