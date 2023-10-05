import { fromHex, toHex } from '@smithy/util-hex-encoding';
import * as Debug from './stores/debug';

export type Credential = {
    id: string,
    publicKey: string,
    transports?: AuthenticatorTransport[],
};

let conditionalMediationAbortController: AbortController | undefined;

export async function register(): Promise<Credential> {
    conditionalMediationAbortController?.abort();

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
                requireResidentKey: true, // Required for allowing login with conditional mediation
            },

            timeout: 60e3, // 1 minute

            challenge: registrationChallenge,
        }
    };

    // register/create a new credential
    const cred = await navigator.credentials.create(createCredentialOptions) as PublicKeyCredential | null;
    if (!cred) throw new Error("No credential created");

    const spkiPublicKey = (cred.response as AuthenticatorAttestationResponse).getPublicKey();
    if (!spkiPublicKey) throw new Error("No public key received");

    await fetch('https://low-tuna-73.deno.dev/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            credentialId: cred.id,
            spkiPublicKey: toHex(new Uint8Array(spkiPublicKey)),
        }),
    }).then(response => response.text()).then((status) => {
        console.warn("Server registration:", status);

        if (status !== 'OK') throw new Error("Server registration failed");
    });

    return {
        id: toHex(new Uint8Array(cred.rawId)),
        publicKey: new Nimiq.WebauthnPublicKey(new Uint8Array(spkiPublicKey)).toHex(),
        transports: (cred.response as AuthenticatorAttestationResponse).getTransports() as AuthenticatorTransport[],
    };
}

export async function login(challenge: Uint8Array, conditionalMediation: boolean): Promise<Credential> {
    if (conditionalMediation) {
        // To abort the request when chosing to register instead
        conditionalMediationAbortController = new AbortController();
    }

    const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
            timeout: 60e3, // 1 minute
            allowCredentials: [],
            userVerification: "preferred",
            challenge: challenge,
        },
        ...(conditionalMediation ? {
            mediation: "conditional",
            signal: conditionalMediationAbortController!.signal,
        } : {}),
    };
    const assertion = await navigator.credentials.get(credentialRequestOptions) as PublicKeyCredential | null;
    if (!assertion) throw new Error("No assertation received");

    console.log(assertion);

    const credentialId = assertion.id;
    const authenticatorData = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).authenticatorData);
    const clientDataJSON = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).clientDataJSON);
    const asn1Signature = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).signature);

    const spkiPublicKey = await fetch('https://low-tuna-73.deno.dev/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            credentialId,
            authenticatorData: toHex(authenticatorData),
            clientDataJSON: toHex(clientDataJSON),
            asn1Signature: toHex(asn1Signature),
        }),
    }).then(async response => {
        const text = await response.text();
        if (!response.ok) throw new Error(text);
        return text;
    });
    console.warn("SPKI Public Key:", spkiPublicKey);

    return {
        id: toHex(new Uint8Array(assertion.rawId)),
        publicKey: new Nimiq.WebauthnPublicKey(fromHex(spkiPublicKey)).toHex(),
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
            challenge: fromHex(tx.hash()),
        },
    };
    const assertion = await navigator.credentials.get(credentialRequestOptions) as PublicKeyCredential | null;
    if (!assertion) throw new Error("No assertation received");

    const authenticatorData = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).authenticatorData);
    const clientDataJSON = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).clientDataJSON);
    const asn1Signature = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).signature);

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
