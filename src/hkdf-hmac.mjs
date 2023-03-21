import { subtle } from 'node:crypto'

const enc = new TextEncoder()

const keydata = enc.encode('superSecret')
const salt = enc.encode('superSalt')
const info = enc.encode('contextInfo')
const hash = { name: 'SHA-512' }
const length = 4096
const derivedKeyType = { name: 'HMAC', hash, length }

const key = await subtle.importKey(
	'raw', //only "raw" is allowed
	keydata, //your raw key data as an ArrayBuffer
	'HKDF',
	false, //whether the key is extractable (i.e. can be used in exportKey)
	['deriveKey'], //can be any combination of "deriveKey" and "deriveBits"
)

console.log({ key })

const res = await subtle.deriveKey(
	{
		name: 'HKDF',
		hash: { name: 'SHA-512' },
		salt,
		info,
	},
	key, //your key from importKey
	derivedKeyType,
	false, //whether the derived key is extractable (i.e. can be used in exportKey)
	['sign'], //limited to the options in that algorithm's importKey
)

console.log({ res })
