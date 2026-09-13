/**
 * EVM HD wallet address derivation (BIP44 coin type 60 — Ethereum path).
 *
 * The same address format works on every EVM chain, including Arbitrum One.
 * Derivation only computes public addresses from the mnemonic — it never
 * signs transactions or touches funds.
 *
 * Verified against BIP44 standard test vector:
 *   Mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
 *   Path:     m / 44' / 60' / 0' / 0 / 0
 *   Expected: 0x9858EfFD232B4033E47d90003D41EC34EcaEda94 (checksummed)
 *
 * Dependencies (audited pure-TS): @scure/bip32, @scure/bip39,
 * @noble/curves/secp256k1, @noble/hashes/sha3 (Keccak-256).
 */

import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

export interface DerivedEvmAddress {
  index: number;
  address: string;          // EIP-55 checksummed 0x... address
  address_lowercase: string;
}

export interface DerivedEvmKeypair extends DerivedEvmAddress {
  private_key_hex: string;  // 0x... 32-byte private key (SENSITIVE — admin export only)
}

function toChecksumAddress(addrHexLower: string): string {
  // EIP-55: keccak-256 of the lowercase hex string (ASCII, no 0x) drives the case of each hex char
  const addr = addrHexLower.replace(/^0x/, '');
  const hash = keccak_256(new TextEncoder().encode(addr));
  let out = '0x';
  for (let i = 0; i < addr.length; i++) {
    const nibble = i < 40 ? (hash[i >> 1] >> (i % 2 === 0 ? 4 : 0)) & 0xf : 0;
    const ch = addr[i];
    out += nibble >= 8 ? ch.toUpperCase() : ch;
  }
  return out;
}

export function deriveEvmAddressFromMnemonic(
  mnemonic: string,
  index: number,
  passphrase: string = '',
): DerivedEvmAddress {
  if (!bip39.validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid BIP39 mnemonic');
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  const master = HDKey.fromMasterSeed(seed);
  const child = master.derive(`m/44'/60'/0'/0/${index}`);
  if (!child.publicKey) throw new Error('Failed to derive public key');

  // Uncompress 33-byte pubkey (0x02|0x03) to 64 bytes X||Y
  const point = secp256k1.Point.fromBytes(child.publicKey);
  const uncompressed = point.toBytes(false);
  const xy = uncompressed.slice(1, 65);

  const hash = keccak_256(xy);
  const addrBytes = hash.slice(-20);
  const addrLower = '0x' + Array.from(addrBytes).map(b => b.toString(16).padStart(2, '0')).join('');

  return {
    index,
    address: toChecksumAddress(addrLower),
    address_lowercase: addrLower,
  };
}

export function deriveEvmKeypairFromMnemonic(
  mnemonic: string,
  index: number,
  passphrase: string = '',
): DerivedEvmKeypair {
  if (!bip39.validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid BIP39 mnemonic');
  }
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  const master = HDKey.fromMasterSeed(seed);
  const child = master.derive(`m/44'/60'/0'/0/${index}`);
  if (!child.privateKey) throw new Error('Failed to derive private key');
  const base = deriveEvmAddressFromMnemonic(mnemonic, index, passphrase);
  return {
    ...base,
    private_key_hex: '0x' + Array.from(child.privateKey).map(b => b.toString(16).padStart(2, '0')).join(''),
  };
}
