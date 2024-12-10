import type { TokenParams,RefreshTokenRequestBody,RefreshTokenResponseBody, RefreshTokenArgs } from "./types";

export class TokenManager{
    private static instance: TokenManager;

    private token_param_store:Map<string,string>;

    private constructor(){
        this.token_param_store = new Map();
    }

    static get_instance(){
        if(TokenManager.instance === undefined){
            TokenManager.instance = new TokenManager();
        }

        return TokenManager.instance;
    }

    public set_token_params(token_params: TokenParams){
        this.token_param_store.set("access_token",token_params.access_token);
        this.token_param_store.set("refresh_token",token_params.refresh_token);
        this.token_param_store.set("token_id",token_params.token_id);
        this.token_param_store.set("token_type",token_params.token_type);

        const expires_in = token_params.expires_in;
        const expires_at = Date.now() + expires_in;

        // We store expiry as string for consistency.
        this.token_param_store.set("expires_at",expires_at.toString());
    }

    public async handle_refresh_token(config: RefreshTokenArgs){

        const refresh_token = this.get_refresh_token();

        if(refresh_token === undefined)
            throw new Error("Refresh token not present.");

        const request_form = new FormData();

        const req_body_params:RefreshTokenRequestBody = {
            grant_type: "refresh_token",
            client_id: config.client_id,
            refresh_token,
        };

        Object.entries(req_body_params).forEach(([key,value]) => {
            request_form.set(key,value);
        });

        if(config.client_secret !== undefined)
            request_form.set("client_secret",config.client_secret);

        if(config.scope !== undefined)
            request_form.set("scope",config.scope);

        try{
            const resp = await fetch(`${config.token_url}`,{
                method: 'POST',
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: request_form
            });

            if(resp.ok === false){
                throw new Error("Error fetching new access token");
            }
            const body:RefreshTokenResponseBody = await resp.json();
            this.update_token_params(body);
            return body;

        }catch(err){
            console.log(err);
        }
    }

    private get_refresh_token(){
        if(this.token_param_store.has("refresh_token")){
            return this.token_param_store.get("refresh_token");
        }

        return undefined;
    }

    private update_token_params(response_body: RefreshTokenResponseBody){
        this.token_param_store.set("access_token",response_body.access_token);
        this.token_param_store.set("token_id",response_body.token_id);
        this.token_param_store.set("token_type",response_body.token_type);

        const expires_at = Date.now()+response_body.expires_in;
        this.token_param_store.set("expires_at",expires_at.toString());
    }
}