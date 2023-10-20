import type { Credential } from "../webauthn";

export function publicKeyFromSpki(buffer: ArrayBuffer, algorithm?: number): Nimiq.ES256PublicKey | Nimiq.PublicKey {
    if (!algorithm || algorithm === -7) {
        return Nimiq.ES256PublicKey.fromSpki(new Uint8Array(buffer));
    } else if (algorithm === -8) {
        return Nimiq.PublicKey.fromSpki(new Uint8Array(buffer));
    } else {
        throw new Error("Unsupported public key algorithm");
    }
}

export function publicKeyFromCredential(credential: Credential): Nimiq.ES256PublicKey | Nimiq.PublicKey {
    if (!credential.publicKeyAlgorithm || credential.publicKeyAlgorithm === -7) {
        return Nimiq.ES256PublicKey.fromHex(credential.publicKey);
    } else if (credential.publicKeyAlgorithm === -8) {
        return Nimiq.PublicKey.fromHex(credential.publicKey);
    } else {
        throw new Error("Unsupported public key algorithm");
    }
}
