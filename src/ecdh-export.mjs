import { subtle } from 'node:crypto'

const kp = await subtle.generateKey(
	{
		name: 'ECDSA',
		namedCurve: 'P-521', //can be "P-256", "P-384", or "P-521"
	},
	true, //whether the key is extractable (i.e. can be used in exportKey)
	['sign', 'verify'], //can be any combination of "sign" and "verify"
)

console.log({ kp })

const private_material = await subtle.exportKey('jwk', kp.privateKey)
const public_material = await subtle.exportKey('jwk', kp.publicKey)

console.log({ private_material, public_material })

const nkp = await subtle.importKey(
	'jwk', //can be "jwk" or "raw"
	private_material, //this is an ArrayBuffer of the exported raw key
	{
		name: 'ECDSA',
		namedCurve: 'P-521', //can be "P-256", "P-384", or "P-521"
	},
	false,
	['sign'], //can be any combination of "sign" and "verify"
)

console.log({ nkp })
