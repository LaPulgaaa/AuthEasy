import type { RuntimeEnv } from "./types";

export function generate_random_str(){
    const env = get_runtime_env();
    if(env === undefined)
        throw new Error("Unknown runtime env.");

    if(env === "browser")
    {
        return window.crypto.randomUUID();
    }

    return new Crypto().randomUUID();
}

export function url_safe_encode64(url_unsafe_str: string){
    return btoa(url_unsafe_str)
    .replace(/\+/g, '-') // Convert '+' to '-'
    .replace(/\//g, '_') // Convert '/' to '_'
    .replace(/=+$/, ''); // Remove ending '='
}

export function url_safe_decode64(encoded_str: string){
    //restore the replaced characters
    const restored_url_str = encoded_str
    .replace(/\-/g, '+') // Convert '-' to '+'
    .replace(/\_/g, '/'); // Convert '_' to '/'

    //base64 decode the string
    const decoded_str = atob(restored_url_str);

    //create uint8Array
    const buffer = new Uint8Array(decoded_str.length);

    //convert each character to utf16 format and store in the buffer
    for(let i=0; i<decoded_str.length; i++){
        buffer[i] = decoded_str.charCodeAt(i)
    }

    return new TextDecoder().decode(buffer);

}

export async function sha256_hash(unhashed_str: string){
    const runtime_env = get_runtime_env();

    if(runtime_env === undefined)
        throw new Error("Unknown runtime env");

    const buffer = new TextEncoder().encode(unhashed_str);
    let buffer_digest:ArrayBuffer;

    if(runtime_env === "node"){
        const crypto_subtle = new Crypto().subtle;
        buffer_digest = await crypto_subtle.digest("SHA-256",buffer);
    }
    else{
        buffer_digest = await window.crypto.subtle.digest("SHA-256",buffer);
    }

    return new TextDecoder().decode(buffer_digest);
}

function get_runtime_env(): RuntimeEnv | undefined{
    if(typeof window !== undefined && window.document !== undefined)
        return "browser";
    else if(
        typeof process !== undefined &&
        typeof process.versions === "object" &&
        typeof process.versions.node !== undefined
    )
        return "node";

    return undefined;
}