import { subtle } from 'node:crypto'

// Unique for each user
const userSalt = 'highEntropySalt'
// Unique for each user, session
const sessionSalt = 'highEntropySalt'

// Only known to user, need to make sure it has enough entropy
const secret = 'highEntropySecret'

// Crypto params

// Password based key derivation function 2
// https://en.wikipedia.org/wiki/PBKDF2
const name = 'PBKDF2'
// How many iterations to run
const iterations = 210000 // FIPS 140-2 compliance
// Hash algorithm to use
const hash = { name: 'SHA-512' }
// the number of bits you want to derive
const length = 4096

const userKeyAlgorithm = { name, userSalt, iterations, hash }
const sessionKeyAlgorithm = { name, sessionSalt, iterations, hash }
const derivedKeyType = { name: 'HMAC', hash, length }

const userPassword = await subtle.importKey(
	'raw',
	secret,
	{ name },
	false, // Store the key in the trusted platform module, making it inaccessible from memory
	['deriveBits'],
)

// Stored in database
const derivedBits = await subtle.deriveBits(
	userKeyAlgorithm,
	userPassword,
	length,
)

const userKey = await subtle.importKey('raw', derivedBits, { name }, false, [
	'deriveKey',
])

console.log({ userPassword, derivedBits, userKey })

// Session key
const derivedKey = await subtle.deriveKey(
	sessionKeyAlgorithm,
	userKey,
	derivedKeyType,
	false,
	['sign'],
)

console.log({ derivedKey })
