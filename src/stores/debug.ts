import { writable } from 'svelte/store';

export const publicKey = writable("");
export const authenticatorData = writable("");
export const clientDataJSON = writable("");
export const asn1Signature = writable("");
export const tx = writable("");
export const proof = writable("");
