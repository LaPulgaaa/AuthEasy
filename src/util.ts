export function generate_random_str(){
    return crypto.randomUUID();
}

export function url_safe_encode64(url_unsafe_str: string){
    try{
        const encoded_str = btoa(url_unsafe_str)
        .replace(/\+/g, '-') // Convert '+' to '-'
        .replace(/\//g, '_') // Convert '/' to '_'
        .replace(/=+$/, ''); // Remove ending '='
        return encoded_str;
    }catch(err){
        return url_unsafe_str;
    }
}

export function url_safe_decode64(encoded_str: string){
    try{
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
    }catch(err){
        return encoded_str;
    }

}

export async function sha256_hash(unhashed_str: string){

    const buffer = new TextEncoder().encode(unhashed_str);

    const crypto_subtle = crypto.subtle;
    const buffer_digest = await crypto_subtle.digest("SHA-256",buffer);

    const arr_buffer = Array.from(new Uint8Array(buffer_digest));

    const hash_hex = arr_buffer
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(""); // convert bytes to hex string
    
    return hash_hex;
}

export function store_data_in_session(data:Record<string,string>){
    try{
        if(typeof window !== undefined && window.sessionStorage !== undefined){
            Object.entries(data).forEach(([key,value]) => {
                sessionStorage.setItem(key,value);
            })
        }
    }catch(err){
        return;
    }
}

export function get_session_data(key: string){
    try{
        if(typeof window !== undefined && window.sessionStorage !== undefined){
            return sessionStorage.getItem(key);
        }
    }catch(err){
        return null;
    }
}