import { initialize, Entropy, PublicKey } from '@sisou/nimiq-ts';
import { fromHex, toHex } from '@smithy/util-hex-encoding';
import * as Debug from './stores/debug';
import { publicKeyFromCredential, publicKeyFromSpki } from './lib/PublicKey';
import { signatureFromAuthenticator } from './lib/Signature';

export type Credential = {
    id: string,
    publicKey: string,
    publicKeyAlgorithm?: number,
    transports?: AuthenticatorTransport[],
    multisigPubKey?: string,
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
                // Prefer Ed25519
                type: "public-key",
                alg: -8 // Ed25519 = EDDSA over Curve25519 with SHA-512
            }, {
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
    const algorithm = (cred.response as AuthenticatorAttestationResponse).getPublicKeyAlgorithm();

    await initialize();
    const multisigEntropy = Entropy.generate();
    const multisigExtPrivKey = multisigEntropy.toExtendedPrivateKey().derivePath("m/44'/242'/0'/0'"); // BIP44 path for Nimiq
    const multisigPubKey = PublicKey.derive(multisigExtPrivKey.privateKey).toHex();

    await fetch('https://low-tuna-73.deno.dev/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            credentialId: cred.id,
            spkiPublicKey: toHex(new Uint8Array(spkiPublicKey)),
            algorithm,
            multisigPubKey,
        }),
    }).then(response => response.text()).then((status) => {
        console.warn("Server registration:", status);

        if (status !== 'OK') throw new Error("Server registration failed");
    });

    const publicKeyAlgorithm = (cred.response as AuthenticatorAttestationResponse).getPublicKeyAlgorithm();

    return {
        id: toHex(new Uint8Array(cred.rawId)),
        publicKey: publicKeyFromSpki(spkiPublicKey, publicKeyAlgorithm).toHex(),
        publicKeyAlgorithm,
        transports: (cred.response as AuthenticatorAttestationResponse).getTransports() as AuthenticatorTransport[],
        multisigPubKey,
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

    const publicKeyData = await fetch('https://low-tuna-73.deno.dev/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            credentialId,
            authenticatorData: toHex(authenticatorData),
            clientDataJSON: toHex(clientDataJSON),
            asn1Signature: toHex(asn1Signature),
        }),
    }).then(async response => {
        if (!response.ok) {
            throw new Error(await response.text());
        }
        return response.json() as Promise<{
            spkiPublicKey: string, // hex
            algorithm?: number, // COSEAlgorithmIdentifier
            createdAt?: number, // unix timestamp (seconds)
            lastAccessedAt?: number, // unix timestamp (seconds)
            multisigPubKey?: string, // hex
        }>;
    });
    console.warn("Public Key data:", publicKeyData);

    return {
        id: toHex(new Uint8Array(assertion.rawId)),
        publicKey: publicKeyFromSpki(fromHex(publicKeyData.spkiPublicKey), publicKeyData.algorithm).toHex(),
        publicKeyAlgorithm: publicKeyData.algorithm,
        multisigPubKey: publicKeyData.multisigPubKey,
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
    const signature = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).signature);

    console.log("PUBLIC KEY", fromHex(credential.publicKey));
    Debug.publicKey.set(credential.publicKey);
    console.log("AUTHENTICATOR DATA", authenticatorData);
    Debug.authenticatorData.set(toHex(authenticatorData));
    console.log("CLIENT DATA JSON", clientDataJSON);
    Debug.clientDataJSON.set(new TextDecoder().decode(clientDataJSON));
    console.log("SIGNATURE", signature);
    Debug.signature.set(toHex(signature));

    console.log("TX", tx.serialize());
    Debug.tx.set(tx.toHex());

    const publicKey = publicKeyFromCredential(credential);

    let proof: Nimiq.SignatureProof;
    if (credential.multisigPubKey) {
        const multisigPubKey = Nimiq.PublicKey.fromHex(credential.multisigPubKey);
        proof = Nimiq.SignatureProof.webauthnMultiSig(
            publicKey,
            [publicKey, multisigPubKey],
            signatureFromAuthenticator(signature, credential.publicKeyAlgorithm),
            authenticatorData,
            clientDataJSON,
        );
    } else {
        proof = Nimiq.SignatureProof.webauthnSingleSig(
            publicKey,
            signatureFromAuthenticator(signature, credential.publicKeyAlgorithm),
            authenticatorData,
            clientDataJSON,
        );
    }

    console.log("PROOF", proof.serialize());
    Debug.proof.set(toHex(proof.serialize()));

    return proof.serialize();
}
