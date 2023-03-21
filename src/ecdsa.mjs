import { subtle } from 'node:crypto'

// Alice generates her private and public keys

const key = await subtle.generateKey(
	{
		name: 'ECDSA',
		namedCurve: 'P-384',
	},
	false, // Key is stored in the trusted platform module, making it inaccessible from ram
	['sign', 'verify'],
)

const message = "Hello, world!"

const signedMsg = await subtle.sign(
	{
		name: 'ECDSA',
		hash: { name: 'SHA-512' },
	},
	key.privateKey,
	message,
)

console.log({ signedMsg })

const isValid = await subtle.verify(
	{
		name: 'ECDSA',
		hash: { name: 'SHA-512' },
	},
	key.publicKey,
	signedMsg,
	message,
)

console.log({ isValid })
