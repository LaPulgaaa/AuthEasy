import { generate_random_str, sha256_hash, url_safe_decode64, url_safe_encode64 } from "./util";
import { TokenManager } from "./token_manager";
import type { OAuthClientConfigParams,CallbackRequestParams, CallbackResponse, CallbackParams } from "./types";


export class OAuthClient{
    private static instance:OAuthClient;

    private authorization_url: string;
    private token_url: string;

    private scope?: string;
    private audience?:string;
    private response_type: string;
    private client_id: string;
    private client_secret: string;
    private redirect_uri: string;
    private connection: string;
    //Auth0 has introduced a new field "organisation" ie. ID of the organisation
    // to use when authentication the user. 
    private organisation?: string;

    private config_store: Map<string,string> = new Map();

    private constructor(config: OAuthClientConfigParams){
        this.authorization_url = config.authorization_url;
        this.token_url = config.token_url;
        // We are implementing PKCE authorization flow. Hence "code" response_type 
        // field tells the authorization server to redirect with authorization_code.
        this.response_type = config.connection ?? "code";
        this.client_id = config.client_id;
        this.client_secret = config.client_secret;
        this.redirect_uri = config.redirect_uri;
        this.scope = config.scope;
        this.connection = config.connection;
        this.organisation = config.organisation;
        this.audience = config.audience;
        //generate state param
        this.generate_state();
    }

    static get_instance(config?: OAuthClientConfigParams){
        if(OAuthClient.instance === undefined){
            if(config === undefined)
                throw new Error("OAuth client config parameters not available");
            OAuthClient.instance = new OAuthClient(config);
        }

        return OAuthClient.instance;
    }

    public async start_auth_flow(){

        const state = this.config_store.get("state");
        if(state === undefined)
            throw new Error("state parameter is undefined.");

        const code_challenge = await this.create_code_challenge();

        const params_obj = {
            response_type: this.response_type,
            client_id: this.client_id,
            state: state,
            redirect_uri: this.redirect_uri,
            code_challenge_method: "S256",
            code_challenge: code_challenge,
            connection: this.connection,
            prompt: "none", // use "prompt=none" to initiate a silent authentication request
        };

        const auth_url_search_params = new URLSearchParams(params_obj);

        // these are optional fields. Auth server assumes default values when 
        // these are not passed.
        if(this.audience !== undefined)
            auth_url_search_params.set("audience",this.audience);
        if(this.organisation !== undefined)
            auth_url_search_params.set("organisation",this.organisation);
        if(this.scope !== undefined)
            auth_url_search_params.set("scope",this.scope);

        return `${this.authorization_url}?${auth_url_search_params.toString()}`
    }

    public async handle_callback(callback_params:CallbackParams){

        const original_state = this.config_store.get(callback_params.state);
        if(original_state === undefined)
            throw new Error("State param not available");

        // check whether the "state" returned from the auth server 
        // matches the original "state"
        const decoded_state = url_safe_decode64(callback_params.state);
        if(decoded_state !== original_state)
            throw new Error("State param returned from the auth server does not match original state. Potential CSRF attack!!")

        const code_verifier = this.config_store.get("code_verifier");
        if(code_verifier === undefined)
            throw new Error("code verifier is undefined");

        const callback_req_params:CallbackRequestParams = {
            grant_type: "authorization_code" as const,
            client_id: this.client_id,
            code_verifier: code_verifier,
            code: callback_params.authorization_code,
            redirect_uri: this.redirect_uri,
        }

        const request_form = new FormData();
        Object.entries(callback_req_params).forEach(([key,values]) => {
            request_form.set(key,values);
        });

        try{
            const resp = await fetch(`${this.token_url}`,{
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: request_form,
            });

            if(resp.ok){
                const body:CallbackResponse = await resp.json();

                // initialise TokenManager singleton instance with token params 
                // returned from auth server.
                TokenManager.get_instance().set_token_params(body);

                return body;
            }
        }catch(err){
            console.log(err);
        }
    }

    public async refresh_token(){
        const token_resp = await TokenManager.get_instance().handle_refresh_token({
            client_id: this.client_id,
            client_secret: this.client_secret,
            token_url: this.token_url,
            scope: this.scope,
        });

        if(token_resp === undefined)
            throw new Error("Could not fetch new access token");

        return token_resp;
    }

    private generate_state(){
        // generate a cryptographically secure random string. We can also store specific
        // details in 'state' variable and sign it. For now, we use this only detection 
        // potential CSRF attacks.
        const random_state = generate_random_str()

        this.config_store.set("state",random_state);

        const encoded_state = url_safe_encode64(random_state);
        return encoded_state;
    }

    private generate_code_verifier(){
        // generate code verifier string
        const random_verifier_str = generate_random_str();
        const encoded_code_verifier = url_safe_encode64(random_verifier_str);

        this.config_store.set("code_verifier",encoded_code_verifier);
        
        return encoded_code_verifier;
    }

    private async create_code_challenge(){
        // create a code challenge using "code_verifier"
        const code_verifier = this.generate_code_verifier();

        const hashed_code_verifier = await sha256_hash(code_verifier);
        const code_challenge_str = url_safe_encode64(hashed_code_verifier);
        this.config_store.set("code_challenge",code_challenge_str);
        
        return code_challenge_str;
    }
}