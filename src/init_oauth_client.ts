import { 
    generate_random_str,
    get_session_data,
    sha256_hash,
    store_data_in_session,
    url_safe_encode64 
} from "./util";
import { TokenManager } from "./token_manager";
import type { OAuthClientConfigParams,CallbackRequestParams, CallbackResponse, CallbackParams } from "./types";


export class OAuthClient{
    private static instance:OAuthClient;

    private config_store: Map<string,string> = new Map();

    private constructor(config: OAuthClientConfigParams){
        this.config_store.set("authorization_url",config.authorization_url);
        this.config_store.set("token_url",config.token_url);
        this.config_store.set("redirect_uri",config.redirect_uri);
        // We are implementing PKCE authorization flow. Hence "code" response_type 
        // field tells the authorization server to redirect with authorization_code.
        this.config_store.set("response_type",config.connection ?? "code");
        this.config_store.set("client_id",config.client_id);
        this.config_store.set("client_secret",config.client_secret);
        if(config.scope)
        this.config_store.set("scope",config.scope);
        this.config_store.set("connection",config.connection);
        //Auth0 has introduced a new field "organisation" ie. ID of the organisation
    // to use when authentication the user. 
        if(config.organisation)
        this.config_store.set("organisation",config.organisation);
        if(config.audience)
            this.config_store.set("audience",config.audience);
        //generate state param
        this.generate_state();
        store_data_in_session(config);
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
            response_type: this.always_get_param_value("response_type"),
            client_id: this.always_get_param_value("client_id"),
            state: state,
            redirect_uri: this.always_get_param_value("redirect_uri"),
            code_challenge_method: "S256",
            code_challenge: code_challenge,
            connection: this.always_get_param_value("connection"),
            prompt: "none", // use "prompt=none" to initiate a silent authentication request
        };

        const auth_url_search_params = new URLSearchParams(params_obj);

        // these are optional fields. Auth server assumes default values when 
        // these are not passed.
        if(this.maybe_get_param_value("audience") !== undefined)
            auth_url_search_params.set("audience",this.maybe_get_param_value("audience")!);
        if(this.maybe_get_param_value("organisation") !== undefined)
            auth_url_search_params.set("organisation",this.maybe_get_param_value("organisation")!);
        if(this.maybe_get_param_value("scope") !== undefined)
            auth_url_search_params.set("scope",this.maybe_get_param_value("scope")!);

        return `${this.always_get_param_value("authorization_url")}?${auth_url_search_params.toString()}`
    }

    public async handle_callback(callback_params:CallbackParams){

        if(this.always_get_param_value("state") !== callback_params.state)
            throw new Error("State values don't match. Potential CSRF!");

        const callback_req_params:CallbackRequestParams = {
            grant_type: "authorization_code" as const,
            client_id: this.always_get_param_value("client_id"),
            client_secret: this.always_get_param_value("client_secret"),
            code_verifier: this.always_get_param_value("code_verifier"),
            code: callback_params.authorization_code,
            redirect_uri: this.always_get_param_value("redirect_uri"),
        }

        const request_form = new FormData();
        Object.entries(callback_req_params).forEach(([key,values]) => {
            request_form.set(key,values);
        });

        try{
            const resp = await fetch(`${this.always_get_param_value("token_url")}`,{
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: request_form,
            });

            if(resp.ok){
                const body:CallbackResponse = await resp.json();
                console.log("Access token recieved successfully");
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
            client_id: this.always_get_param_value("client_id"),
            client_secret: this.always_get_param_value("client_secret"),
            token_url: this.always_get_param_value("token_url"),
            scope: this.maybe_get_param_value("scope"),
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
        store_data_in_session({
            state: random_state
        })
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
        store_data_in_session({
            code_verifier,
            code_challenge_str
        });
        return code_challenge_str;
    }

    private always_get_param_value(param: string){
        const value = this.maybe_get_param_value(param);

        if(value === undefined)
            throw new Error(`Value of ${param} is not present.`);

        return value;
    }

    private maybe_get_param_value(param: string){
        if(this.config_store.has(param))
            return this.config_store.get(param)!;
        else {
            const backed_up_val = get_session_data(param);
            if(backed_up_val === null)
                return undefined;

            return backed_up_val;
        }
    }
}