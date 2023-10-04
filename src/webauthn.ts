import { fromHex, toHex } from '@smithy/util-hex-encoding';
import * as Debug from './stores/debug';

export type Credential = {
    id: string,
    publicKey: string,
    transports?: AuthenticatorTransport[],
};

export async function register(): Promise<Credential> {
    const registrationChallenge = crypto.getRandomValues(new Uint8Array(32));

    const createCredentialOptions: CredentialCreationOptions = {
        publicKey: {
            // Relying Party (a.k.a. - Service):
            rp: {
                name: "Albatross Webauthn Demo",
            },

            // User:
            user: {
                id: new Uint8Array(16), // Empty array
                name: "Webauthn Demo Account",
                displayName: "Webauthn Demo User",
            },

            pubKeyCredParams: [{
                type: "public-key",
                alg: -7, // ES256 = ECDSA over P-256 with SHA-256
            }],

            authenticatorSelection: {
                userVerification: "preferred", // Should be "required", but that excludes Ledgers
            },

            timeout: 60e3, // 1 minute

            challenge: registrationChallenge.buffer,
        }
    };

    // register/create a new credential
    const cred = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential | null;
    if (!cred) throw new Error("No credential created");

    // Convert public key from "spki" to compressed "raw" format
    const spkiPublicKey = (cred.response as AuthenticatorAttestationResponse).getPublicKey();
    if (!spkiPublicKey) throw new Error("No public key received");

    return {
        id: toHex(new Uint8Array(cred.rawId)),
        publicKey: new Nimiq.WebauthnPublicKey(new Uint8Array(spkiPublicKey)).toHex(),
        transports: (cred.response as AuthenticatorAttestationResponse).getTransports() as AuthenticatorTransport[],
    };
}

export async function sign(tx: Nimiq.Transaction, credential: Credential) {
    const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
            timeout: 60e3, // 1 minute
            allowCredentials: [{
                id: fromHex(credential.id),
                transports: credential.transports || ["usb", "nfc", "ble", "internal", "hybrid"], // allow all transports by default
                type: "public-key",
            }],
            userVerification: "preferred",
            challenge: fromHex(tx.hash()).buffer,
        },
    };
    const assertion = await navigator.credentials.get(credentialRequestOptions) as PublicKeyCredential | null;
    if (!assertion) throw new Error("No assertation received");

    const asn1Signature = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).signature);
    const authenticatorData = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).authenticatorData);
    const clientDataJSON = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).clientDataJSON);

    console.log("PUBLIC KEY", fromHex(credential.publicKey));
    Debug.publicKey.set(credential.publicKey);
    console.log("AUTHENTICATOR DATA", authenticatorData);
    Debug.authenticatorData.set(toHex(authenticatorData));
    console.log("CLIENT DATA JSON", clientDataJSON);
    Debug.clientDataJSON.set(new TextDecoder().decode(clientDataJSON));
    console.log("ASN1 SIGNATURE", asn1Signature);
    Debug.asn1Signature.set(toHex(asn1Signature));

    console.log("TX", tx.serialize());
    Debug.tx.set(tx.toHex());

    const proof = Nimiq.SignatureProof.webauthnSingleSig(
        Nimiq.WebauthnPublicKey.fromHex(credential.publicKey),
        Nimiq.Signature.fromAsn1(asn1Signature),
        authenticatorData,
        clientDataJSON,
    );

    console.log("PROOF", proof.serializeExtended());
    Debug.proof.set(toHex(proof.serializeExtended()));

    return proof.serializeExtended();
}
