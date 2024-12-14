import type { TokenParams,RefreshTokenRequestBody,RefreshTokenResponseBody, RefreshTokenArgs } from "./types";
import { get_session_data, store_data_in_session } from "./util";

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

    public set_token_params(token_params: Record<string,string>){
        const { expires_in,...data } = token_params;
    
        const expires_at = Date.now() + Number.parseInt(expires_in);

        this.store_token_data({
            ...data,
            expires_at: expires_at.toString(),// We store expiry as string for consistency.
        })

    }

    public async handle_refresh_token(config: RefreshTokenArgs){

        const refresh_token = this.always_get_param_value("refresh_token");

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

    private update_token_params(data: RefreshTokenResponseBody){
        const { expires_in, ...updated_data } = data;

        const expires_at = Date.now()+expires_in;
        this.token_param_store.set("expires_at",expires_at.toString());

        this.store_token_data({
            ...updated_data,
            expires_at: expires_at.toString(),
        })
    }

    private always_get_param_value(param: string){
        const value = this.maybe_get_param_value(param);

        if(value === undefined)
            throw new Error(`Value of ${param} is not present.`);

        return value;
    }

    private maybe_get_param_value(param: string){
        if(this.token_param_store.has(param))
            return this.token_param_store.get(param)!;
        else {
            const backed_up_val = get_session_data(param);
            if(backed_up_val === null)
                return undefined;

            return backed_up_val;
        }
    }

    private store_token_data(token_params:Record<string,string>){

        Object.entries(token_params).forEach(([key,value]) => {
            this.token_param_store.set(key,value);
        })

        store_data_in_session(token_params);
    }
}