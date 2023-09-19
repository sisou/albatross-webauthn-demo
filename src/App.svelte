<fieldset>
    <legend>Consensus</legend>

    <table>
        <tr>
            <td>Status:</td>
            <td class="{`consensus ${$consensus}`}">{ $consensus }</td>
        </tr>
        <tr>
            <td>Peers:</td>
            <td>{ $peers }</td>
        </tr>
        <tr>
            <td>Height:</td>
            <td>{ $height }</td>
        </tr>
    </table>
</fieldset>

{#if $consensus === 'established'}
    <fieldset>
        <legend>Account</legend>

        {#if !$credential}
            <button on:click={registerCredential}>Register Webauthn Credential</button>
        {:else}
            <code>{ $address }</code><br>
            <div class="balance">
                <strong>Balance:</strong>
                {#if $balance !== undefined}
                    { $balance / 1e5 } NIM
                    <button on:click="{tapFaucet}" disabled="{receiving}">Tap Faucet</button>
                {:else}
                    Loading...
                {/if}
            </div>
        {/if}
    </fieldset>
{/if}

{#if $balance && $balance > 100}
    <fieldset>
        <legend>Send Transaction</legend>

        <button on:click="{send}" disabled="{sending}">Send 100 NIM to Faucet</button>
    </fieldset>
{/if}

<script lang="ts">
import { onMount } from 'svelte';
import { consensus, peers, height, address, balance, type Credential, credential, getClient } from './stores/network';
import { register, sign } from './webauthn';

const GENESIS_ACCOUNTS = [
    { privkey: "a24591648e20642fe5107d0285c1cc35d67e2033a92566f1217fbd3a14e07abc"},
    { privkey: "3336f25f5b4272a280c8eb8c1288b39bd064dfb32ebc799459f707a0e88c4e5f"},
    { privkey: "6ca225de8c2a091a31ae48645453641069ae8a9d3158e9d6e004b417661af500"},
    { privkey: "5899a573451f72a4a1e58c7de3e091a1846d14bd82c98e4bfdaf1857986de7d8"},
    { privkey: "652be07036bf791644260eaa388534d7dbecb579c69bf3b70c0714ae7d5fdcc2"},
    { privkey: "e3e552194e1e56fb47ccc6eb8becea1c1b813ec23ae7613edff12be152a2e812"},
    { privkey: "c88cb69af940cc58a1f5aa8f1d943b53893a913af48d873c2e83169644b30edc"},
    { privkey: "1ef7aad365c195462ed04c275d47189d5362bbfe36b5e93ce7ba2f3add5f439b"},
];

onMount(() => {
    const storedCredential = localStorage.getItem('credential');

    if (storedCredential) {
        $credential = JSON.parse(storedCredential) as Credential;
    }
});

async function registerCredential() {
    const newCredential = await register();
    $credential = newCredential;

    localStorage.setItem('credential', JSON.stringify(newCredential));
}

let _faucetKeypair: Nimiq.KeyPair | undefined;

function getFaucetKeyPair() {
    if (!_faucetKeypair) {
        const faucetAccount = GENESIS_ACCOUNTS[Math.floor(Math.random() * GENESIS_ACCOUNTS.length)];
        const faucetPrivKey = Nimiq.PrivateKey.fromHex(faucetAccount.privkey);
        _faucetKeypair = Nimiq.KeyPair.derive(faucetPrivKey);
    }
    return _faucetKeypair;
}

let receiving = false;

async function tapFaucet() {
    if (!$address) throw new Error('No address');

    const client = await getClient();
    const faucetKeypair = getFaucetKeyPair();

    const tx = Nimiq.TransactionBuilder.newBasic(
        faucetKeypair.toAddress(),
        Nimiq.Address.fromString($address),
        1000_00000n,
        0n,
        await client.getHeadHeight(),
        await client.getNetworkId(),
    );

    tx.sign(faucetKeypair);

    receiving = true;
    try {
        const receipt = await client.sendTransaction(tx);
        console.log(receipt);
    } catch (error: any) {
        alert(error.message);
    }
    receiving = false;
}

let sending = false

async function send() {
    if (!$credential) throw new Error('No credential');
    if (!$address) throw new Error('No address');

    const client = await getClient();
    const faucetKeypair = getFaucetKeyPair();

    const tx = Nimiq.TransactionBuilder.newBasic(
        Nimiq.Address.fromString($address),
        faucetKeypair.toAddress(),
        100_00000n,
        0n,
        await client.getHeadHeight(),
        await client.getNetworkId(),
    );

    const proof = await sign(tx, $credential.id, $credential.publicKey);
    tx.proof = proof;

    sending = true;
    try {
        const receipt = await client.sendTransaction(tx);
        console.log(receipt);
    } catch (error: any) {
        alert(error.message);
    }
    sending = false;
}
</script>

<style>
fieldset {
    border-radius: 1rem;
}

fieldset + fieldset {
    margin-top: 2rem;
}

fieldset > *:not(legend) {
    width: 100%;
}

fieldset legend {
    font-weight: 600;
    text-transform: uppercase;
}

table {
    text-align: left;
}

table td:first-child {
    font-weight: bold;
}

.consensus.connecting {
    color: red;
}

.consensus.syncing {
    color: orange;
}

.consensus.established {
    color: green;
}

.balance {
    margin-top: 0.5rem;
}

.balance button {
    margin-left: 0.5rem;
}
</style>
