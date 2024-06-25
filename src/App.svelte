<fieldset>
    <legend>About</legend>
    <p class="align-left">
        This is a demo for Webauthn signature support, aka Passkeys, for Nimiq PoS Albatross.
    </p>
    <p class="align-left">
        Tested so far with Android Passkeys, iCloud Keychain and Yubikey Series 5. Let me know any other authenticators that you have tested, both if they work and if they don't.
    </p>
</fieldset>

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

<fieldset>
    <legend>Account</legend>

    {#if !$credential}
        <!-- {#if canConditionallyWebauthn}
            {#if loginChallenge}
                <input type="text" placeholder="Click here to login" name="username" autocomplete="username webauthn">
            {:else}
                Loading Passkey Login challenge...
            {/if}
        {:else if canConditionallyWebauthn === false} -->
            <button on:click="{passkeyLogin}">Login with Passkey</button>
        <!-- {:else}
            Testing Passkey Login availability...
        {/if} -->
        &mdash; or &mdash;
        <button on:click="{registerCredential}">Register new Passkey</button>
    {:else}
        <code>{ $address }</code>
        <button on:click="{logout}">Logout</button>
        <div class="balance">
            <strong>Balance:</strong>
            {#if $balance !== undefined}
                { $balance / 1e5 } NIM
                <button on:click="{tapFaucet}" disabled="{receiving}">💸 Tap Faucet</button>
            {:else}
                Loading...
            {/if}
        </div>
    {/if}
</fieldset>

<fieldset class:disabled="{!$balance}">
    <legend>Send Transaction</legend>

    <button on:click="{send}" disabled="{sending}">Send 100 NIM to Faucet</button>
</fieldset>

{#if sentTransactionHash}
<h3 class="color-success">Success</h3>
<p>
    The transaction was sent successfully 🎉
</p>
<code>{ sentTransactionHash.slice(0, 32) }<wbr>{ sentTransactionHash.slice(32) }</code>
{/if}

{#if signatureError}
<h3 class="color-error">Error</h3>
<p>
    Unfortunately, the signature is invalid 🧐<br>
    Please send me following information:
</p>
<button on:click="{copyError}">📋 Copy</button>
<pre class="error-data align-left">
Error: {signatureError}

PublicKey
{$publicKey}

AuthenticatorData
{$authenticatorData}

ClientDataJSON
{$clientDataJSON}

Signature
{$signature}

Transaction
{$tx}

Proof
{$proof}
</pre>
{/if}

<script lang="ts">
import { onMount } from 'svelte';
import { consensus, peers, height, address, balance, credential, getClient } from './stores/network';
import { type Credential, login, register, sign } from './webauthn';
import { publicKey, authenticatorData, clientDataJSON, signature, tx, proof} from './stores/debug';

const GENESIS_ACCOUNTS = [
    { privkey: "3336f25f5b4272a280c8eb8c1288b39bd064dfb32ebc799459f707a0e88c4e5f"}, // NQ87 HKRC JYGR PJN5 KQYQ 5TM1 26XX 7TNG YT27
];

onMount(() => {
    const storedCredential = localStorage.getItem('credential');

    if (storedCredential) {
        $credential = JSON.parse(storedCredential) as Credential;
    }
});

// let canConditionallyWebauthn: boolean | undefined;
let loginChallenge: string | undefined;

// if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
//     PublicKeyCredential.isConditionalMediationAvailable().then(async (available) => {
//         canConditionallyWebauthn = available;

//         if (available) {
//             loginChallenge = await fetch('https://low-tuna-73.deno.dev/challenge').then((response) => response.text());
//             console.warn('Login challenge:', loginChallenge);
//             // TODO: Refresh challenge every 1 minute

//             const challenge = new Uint8Array(atob(loginChallenge!.replaceAll("_", "/").replaceAll("-", "+")).split('').map(c => c.charCodeAt(0)));
//             const newCredential = await login(challenge, true);
//             $credential = newCredential;
//             localStorage.setItem('credential', JSON.stringify(newCredential));
//         }
//     });
// } else {
//     canConditionallyWebauthn = false;
// };

async function passkeyLogin() {
    try {
        loginChallenge = await fetch('https://low-tuna-73.deno.dev/challenge').then((response) => response.text());
        console.warn('Login challenge:', loginChallenge);

        const challenge = new Uint8Array(atob(loginChallenge!.replaceAll("_", "/").replaceAll("-", "+")).split('').map(c => c.charCodeAt(0)));
        const newCredential = await login(challenge, false);
        $credential = newCredential;
        localStorage.setItem('credential', JSON.stringify(newCredential));
    } catch (error: any) {
        alert(error.message);
    }
}

async function registerCredential() {
    try {
        const newCredential = await register();
        $credential = newCredential;
        localStorage.setItem('credential', JSON.stringify(newCredential));
    } catch (error: any) {
        alert(error.message);
    }
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
let signatureError: string | undefined;
let sentTransactionHash: string | undefined;

async function send() {
    if (!$credential) throw new Error('No credential');
    if (!$address) throw new Error('No address');

    signatureError = undefined;
    sentTransactionHash = undefined;

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

    try {
        const proof = await sign(tx, $credential);
        tx.proof = proof;
    } catch (error: any) {
        alert(error.message);
        return;
    }

    try {
        tx.verify();
    } catch (error: any) {
        signatureError = error.message;
        return;
    }

    sending = true;
    try {
        const receipt = await client.sendTransaction(tx);
        console.log(receipt);
        sentTransactionHash = receipt.transactionHash;
    } catch (error: any) {
        alert(error.message);
    }
    sending = false;
}

function logout() {
    $credential = undefined;
    localStorage.removeItem('credential');
}

function copyError() {
    const data = document.getElementsByClassName('error-data')[0].textContent!;
    navigator.clipboard.writeText(data);
}
</script>

<style>
.align-left {
    text-align: left;
}

.color-success {
    color: green;
}

.color-warn {
    color: orange;
}

.color-error {
    color: red;
}

.bg-warn {
    background-color: orange;
}

fieldset,
.rounded {
    border-radius: 1rem;
}

fieldset + fieldset {
    margin-top: 2rem;
}

fieldset.disabled {
    opacity: 0.4;
    pointer-events: none;
}

fieldset > *:not(legend) {
    width: 100%;
}

fieldset legend {
    font-weight: 600;
    text-transform: uppercase;
}

fieldset p:first-of-type {
    margin-top: 0;
}

fieldset p:last-of-type {
    margin-bottom: 0;
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

.error-data {
    word-break: break-all;
    white-space: pre-line;
    background: #f0f0f0;
    padding: 0.5rem;
    border-radius: 0.5rem;
}
</style>
