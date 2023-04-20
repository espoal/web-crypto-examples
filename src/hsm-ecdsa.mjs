import { webcrypto } from 'node:crypto'
import cbor from 'cbor'

const { subtle } = webcrypto

const algorithm = {
    name: "ECDSA",
    namedCurve: "P-256",
}

const bufferToString = (buffer) => {
    return Buffer.from(buffer).toString('base64')
}

const stringToBuffer = (string) => Buffer.from(string, 'base64')

// Key held by the HSM

const hsmKey = await subtle.generateKey(
    algorithm,
    false,
    ["sign", "verify"]
)

// Instance key

const serviceKey = await subtle.generateKey(
    algorithm,
    false,
    ["sign", "verify"]
)

const publicServiceKey = await subtle.exportKey('spki', serviceKey.publicKey)

const identity = {
    identityID: webcrypto.randomUUID(),
    key: bufferToString(publicServiceKey),
    nonce: webcrypto.randomUUID(),
    timestamp: Date.now()
}

const buffer = JSON.stringify(identity)

const digest = await subtle.digest('SHA-512', buffer)

// Signing the identity token with the HSM key
const signature = await subtle.sign({
    name: "ECDSA",
    hash: {name: "SHA-512"},
}, hsmKey.privateKey, digest)

const token = {
    identity,
    digest: bufferToString(digest),
    signature: bufferToString(signature),
}

// Serialize identity token
const output_buffer = btoa(JSON.stringify(token))


// Deserialize identity token
const input = JSON.parse(atob(output_buffer))
input.digest = stringToBuffer(input.digest)
input.signature = stringToBuffer(input.signature)

// Verify the identity token
const new_digest = await subtle.digest('SHA-512', JSON.stringify(input.identity))
const verify = await subtle.verify(
    {
        name: "ECDSA",
        hash: {name: "SHA-512"}
    },
    hsmKey.publicKey,
    input.signature,
    new_digest
)


const cbor_token = {
    ...token,
    digest,
    signature,
}

cbor_token.identity.key = publicServiceKey

const encoded = cbor.encode(cbor_token)
const base64 = encoded.toString('base64')

const decoded = cbor.decode(stringToBuffer(base64))

console.log({ verify, length: encoded.length, base64_length: base64.length,  })
