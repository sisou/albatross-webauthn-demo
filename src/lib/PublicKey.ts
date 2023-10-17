import type { Credential } from "../webauthn";

export function publicKeyFromSpki(buffer: ArrayBuffer, algorithm?: number): Nimiq.WebauthnPublicKey | Nimiq.PublicKey {
    if (!algorithm || algorithm === -7) {
        return Nimiq.WebauthnPublicKey.fromSpki(new Uint8Array(buffer));
    } else if (algorithm === -8) {
        return new Nimiq.PublicKey(new Uint8Array(buffer.slice(buffer.byteLength - 32)));
    } else {
        throw new Error("Unsupported public key algorithm");
    }
}

export function publicKeyFromCredential(credential: Credential): Nimiq.WebauthnPublicKey | Nimiq.PublicKey {
    if (!credential.publicKeyAlgorithm || credential.publicKeyAlgorithm === -7) {
        return Nimiq.WebauthnPublicKey.fromHex(credential.publicKey);
    } else if (credential.publicKeyAlgorithm === -8) {
        return Nimiq.PublicKey.fromHex(credential.publicKey);
    } else {
        throw new Error("Unsupported public key algorithm");
    }
}
