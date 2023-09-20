import { fromHex, toHex } from '@smithy/util-hex-encoding';

export async function register() {
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
    const publicKey = await compressKey(spkiPublicKey);

    return {
        id: toHex(new Uint8Array(cred.rawId)),
        publicKey: toHex(publicKey),
    };
}

async function compressKey(spkiUncompressed: ArrayBuffer) {
    if (spkiUncompressed.byteLength !== 91) {
        throw new Error('Invalid public key length, expected 91 bytes for "spki" format');
    }

    // Import as spki and reexport as raw
    const cryptoKey = await crypto.subtle.importKey(
        "spki",
        spkiUncompressed,
        {
            // these are the algorithm options
            // await cred.response.getPublicKeyAlgorithm() // returns -7
            // -7 is ES256 with P-256 // search -7 in https://w3c.github.io/webauthn
            // the W3C webcrypto docs:
            //
            // https://www.w3.org/TR/WebCryptoAPI/#informative-references (scroll down a bit)
            //
            // ES256 corrisponds with the following AlgorithmIdentifier:
            name: "ECDSA",
            namedCurve: "P-256",
            hash: { name: "SHA-256" },
        },
        true, // extractable
        ["verify"], // "verify" for public key import
    );

    const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", cryptoKey));

    // Compress public key
    if (rawKey.length !== 65) {
        throw new Error('Invalid raw key length, expected 65 bytes for "raw" format');
    }

    // Get the prefix and x coordinate
    const compressed = rawKey.slice(0, 33);

    // Adjust prefix according to y coordinate eveness
    compressed[0] = 0x02 | (rawKey[rawKey.length - 1] & 0x01);

    return compressed;
}

export async function sign(tx: Nimiq.Transaction, credentialId: string, publicKey: string) {
    const credentialRequestOptions: CredentialRequestOptions = {
        publicKey: {
            timeout: 60e3, // 1 minute
            allowCredentials: [{
                id: fromHex(credentialId),
                transports: ["usb", "nfc", "ble"],
                type: "public-key",
            }],
            userVerification: "preferred",
            challenge: fromHex(tx.hash()).buffer,
        },
    };
    const assertion = await navigator.credentials.get(credentialRequestOptions) as PublicKeyCredential | null;
    if (!assertion) throw new Error("No assertation received");

    const authenticatorData = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).authenticatorData);
    const asn1Signature = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).signature);

    // Find client data extra fields
    const clientDataJSONBytes = new Uint8Array((assertion.response as AuthenticatorAssertionResponse).clientDataJSON);
    const clientDataJSON = new TextDecoder().decode(clientDataJSONBytes);

    const crossOriginField = '"crossOrigin":false';
    const originFieldStandard = `"origin":"${location.origin}"`;
    const originFieldEscaped = `"origin":"${location.origin.replaceAll('/', '\\/')}"`;

    let clientDataFlags = 0;

    let clientDataExtraFields: string | undefined;

    if (clientDataJSON.includes(crossOriginField)) {
        const [_, extraFields] = clientDataJSON.split(crossOriginField, 2);
        if (extraFields.length > 1) {
            clientDataExtraFields = extraFields.slice(1, -1); // Cut off first comma and last curly brace
        }
    } else {
        clientDataFlags |= 1 << 0; // Set NO_CROSSORIGIN_FIELD flag

        if (clientDataJSON.includes(originFieldStandard)) {
            const [_, extraFields] = clientDataJSON.split(originFieldStandard, 2);
            if (extraFields.length > 1) {
                clientDataExtraFields = extraFields.slice(1, -1); // Cut off first comma and last curly brace
            }
        } else if (clientDataJSON.includes(originFieldEscaped)) {
            clientDataFlags |= 1 << 1; // Set ESCAPED_ORIGIN_SLASHES flag

            const [_, extraFields] = clientDataJSON.split(originFieldEscaped, 2);
            if (extraFields.length > 1) {
                clientDataExtraFields = extraFields.slice(1, -1); // Cut off first comma and last curly brace
            }
        }
    }

    console.log("PUBLIC KEY", fromHex(publicKey));
    console.log("AUTHENTICATOR DATA", authenticatorData);
    console.log("CLIENT DATA JSON", clientDataJSON);
    console.log("ASN1 SIGNATURE", asn1Signature);

    console.log("TX", tx.serialize());

    const proof = Nimiq.SignatureProof.webauthnSingleSig(
        new Nimiq.WebauthnPublicKey(fromHex(publicKey)),
        Nimiq.Signature.fromAsn1(asn1Signature),
        location.host,
        authenticatorData,
        clientDataFlags,
        clientDataExtraFields,
    );

    console.log("PROOF", proof.serializeExtended());

    return proof.serializeExtended();
}
