import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
export const PROTOCOL_VERSION = '0.1';
export function canonicalize(value) {
    if (value === null || typeof value !== 'object')
        return JSON.stringify(value);
    if (Array.isArray(value))
        return '[' + value.map(canonicalize).join(',') + ']';
    const obj = value;
    return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonicalize(obj[k])).join(',') + '}';
}
export function digest(value) {
    return 'sha256:' + createHash('sha256').update(canonicalize(value)).digest('hex');
}
export function signManifest(manifest, privateKey) {
    const signature = sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64url');
    const publicKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64url');
    return { manifest, signature, algorithm: 'ed25519', publicKey };
}
export function verifyManifest(signed) {
    const key = createPublicKey({ key: Buffer.from(signed.publicKey, 'base64url'), type: 'spki', format: 'der' });
    return verify(null, Buffer.from(canonicalize(signed.manifest)), key, Buffer.from(signed.signature, 'base64url'));
}
export function generatePublisherKeypair() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    return {
        privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    };
}
