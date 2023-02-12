import { subtle } from 'node:crypto'

// Alice generates her private and public keys

const aliceKey = await subtle.generateKey(
	{
		name: 'ECDH',
		namedCurve: 'P-521',
	},
	false, // Key is stored in the trusted platform module, making it inaccessible from ram
	['deriveKey'],
)

// Bob generates his private and public keys

const bobKey = await subtle.generateKey(
	{
		name: 'ECDH',
		namedCurve: 'P-521',
	},
	false,
	['deriveKey'],
)

// console.log({ aliceKey, bobKey })

// Alice derives a key from her private key and Bob's public key

const aliceDerivedKey = await subtle.deriveKey(
	{
		name: 'ECDH',
		namedCurve: 'P-521',
		public: bobKey.publicKey,
	},
	aliceKey.privateKey,
	{
		name: 'HMAC',
		hash: { name: 'SHA-384' },
		length: 256,
	},
	false,
	['sign', 'verify'],
)

// Bob derives a key from his private key and Alice's public key

const bobDerivedKey = await subtle.deriveKey(
	{
		name: 'ECDH',
		namedCurve: 'P-521',
		public: aliceKey.publicKey,
	},
	bobKey.privateKey,
	{
		name: 'HMAC',
		hash: { name: 'SHA-384' },
		length: 256,
	},
	false,
	['sign', 'verify'],
)

console.log({ aliceDerivedKey, bobDerivedKey })

const message = new TextEncoder().encode('Hello, world!')

// Alice signs the message with her derived key

const aliceSignature = await subtle.sign('HMAC', aliceDerivedKey, message)

console.log({ aliceSignature })

// Bob verifies the message with his derived key

const bobResult = await subtle.verify(
	'HMAC',
	bobDerivedKey,
	aliceSignature,
	message,
)

console.log({ bobResult })

// Bob signs the message with her derived key

const bobSignature = await subtle.sign('HMAC', bobDerivedKey, message)

console.log({ bobSignature })

// Alice verifies the message with his derived key

const aliceResult = await subtle.verify(
	'HMAC',
	aliceDerivedKey,
	bobSignature,
	message,
)

console.log({ aliceResult })
