export function signatureFromAuthenticator(buffer: ArrayBuffer, algorithm?: number): Nimiq.ES256Signature | Nimiq.Signature {
    if (!algorithm || algorithm === -7) {
        return Nimiq.ES256Signature.fromAsn1(new Uint8Array(buffer));
    } else if (algorithm === -8) {
        // Signature schemes added after the initial ones are recommended not to use ASN.1 encoding, but raw bytes instead.
        // Yubikey provides the raw 64-byte signature.
        if (buffer.byteLength === 64) {
            return Nimiq.Signature.fromBytes(new Uint8Array(buffer));
        } else {
            return Nimiq.Signature.fromAsn1(new Uint8Array(buffer));
        }
    } else {
        throw new Error("Unsupported signature algorithm");
    }
}
