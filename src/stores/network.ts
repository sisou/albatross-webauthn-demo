import { derived, readable, writable, type Writable, type Readable } from 'svelte/store';
import { type Credential } from '../webauthn';
import { tick } from 'svelte';
import { publicKeyFromCredential } from '../lib/PublicKey';

let nimiqPromise: Promise<void> | undefined;
let clientPromise: Promise<Nimiq.Client> | undefined;

async function loadNimiq() {
    return nimiqPromise || (nimiqPromise = new Promise(async (resolve, reject) => {
        await Nimiq.default();
        resolve();
    }));
}

export async function getClient(): Promise<Nimiq.Client> {
    return clientPromise || (clientPromise = new Promise(async (resolve, reject) => {
        await loadNimiq();

        const config = new Nimiq.ClientConfiguration();
        config.logLevel('debug');
        config.network('devalbatross');
        config.seedNodes([
            // '/dns4/seed1.nimiq.local/tcp/8401/ws'
            '/dns4/seed1.webauthn.pos.nimiqwatch.com/tcp/443/wss',
            '/dns4/validator1.webauthn.pos.nimiqwatch.com/tcp/443/wss',
            '/dns4/validator2.webauthn.pos.nimiqwatch.com/tcp/443/wss',
            '/dns4/validator3.webauthn.pos.nimiqwatch.com/tcp/443/wss',
            '/dns4/validator4.webauthn.pos.nimiqwatch.com/tcp/443/wss',
        ]);

        resolve(Nimiq.Client.create(config.build()));
    }));
}

export const consensus = readable<Nimiq.ConsensusState>("connecting", (set) => {
    let handle: number | undefined;

    getClient().then((client) => {
        client.isConsensusEstablished().then((established) => set(established ? "established" : "syncing"));

        client.addConsensusChangedListener((consensusState) => {
            set(consensusState)
        }).then((h) => handle = h);
    });

    return () => {
        if (!handle) return;

        getClient().then((client) => {
            client.removeListener(handle!);
        });
    }
});

export const peers = readable(0, (set) => {
    let handle: number | undefined;

    getClient().then((client) => {
        client.addPeerChangedListener((peerId, reason, peerCount) => {
            set(peerCount)
        }).then((h) => handle = h);
    });

    return () => {
        if (!handle) return;

        getClient().then((client) => {
            client.removeListener(handle!);
        });
    }
});

export const height = readable(0, (set) => {
    let handle: number | undefined;

    getClient().then((client) => {
        client.getHeadHeight().then((height) => set(height));

        client.addHeadChangedListener((hash) => {
            client.getHeadHeight().then((height) => set(height));
        }).then((h) => handle = h);
    });

    return () => {
        if (!handle) return;

        getClient().then((client) => {
            client.removeListener(handle!);
        });
    }
});

export const credential = writable<Credential | undefined>();
export const address = derived<[Writable<Credential | undefined>], string | undefined>([credential], ([credential], set) => {
    if (!credential) {
        set(undefined);
        return;
    }
    loadNimiq().then(() => {
        const key = publicKeyFromCredential(credential);
        if (credential.multisigPubKey) {
            const multisigPubKey = Nimiq.PublicKey.fromHex(credential.multisigPubKey);
            const merkleRoot = Nimiq.MerkleTree.computeRoot([key.serialize(), multisigPubKey.serialize()]);
            const address = new Nimiq.Address(merkleRoot);
            set(address.toUserFriendlyAddress());
        } else {
            set(key.toAddress().toUserFriendlyAddress());
        }
    });
});

export const balance = derived<[Readable<string | undefined>], number | undefined>([address], ([address], set) => {
    if (!address) {
        set(undefined);
        return;
    }

    let handle: number | undefined;

    getClient().then(async (client) => {
        await client.waitForConsensusEstablished();

        client.getAccount(address).then((account) => set(account.balance));

        client.addTransactionListener((transaction) => {
            client.getAccount(address).then((account) => set(account.balance));
        }, [address]).then((h) => handle = h);
    });


    return () => {
        if (!handle) return;

        getClient().then((client) => {
            client.removeListener(handle!);
        });
    }
});

// @ts-expect-error
window.refetchBalance = async () => {
    let cred;
    credential.subscribe((c) => { cred = c; })();
    if (!cred) return;
    credential.set(undefined);
    await tick();
    credential.set(cred);
};
