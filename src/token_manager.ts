import { BASE_URL } from "./const";
import type { TokenParams,RefreshTokenRequestBody,RefreshTokenResponseBody } from "./types";

export class TokenManager{
    private static instance: TokenManager;
    private access_token: string;
    private refresh_token: string;
    private expires_at: number;
    private token_id: string;
    private token_type: string;

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
        this.token_param_store.set("expires_at",token_params.expires_at.toString());
        this.token_param_store.set("token_id",token_params.token_id);
        this.token_param_store.set("token_type",token_params.token_type);
    }

    public get_refresh_token(){
        if(this.token_param_store.has("refresh_token")){
            return this.token_param_store.get("refresh_token");
        }

        return undefined;
    }

    public async handle_refresh_token(client_id: string,client_secret?:string,scope?: string){

        const refresh_token = this.get_refresh_token();

        if(refresh_token === undefined)
            throw new Error("Refresh token not present.");

        const request_form = new FormData();

        const req_body_params:RefreshTokenRequestBody = {
            grant_type: "refresh_token",
            client_id: client_id,
            refresh_token,
        };

        Object.entries(req_body_params).forEach(([key,value]) => {
            request_form.set(key,value);
        });

        if(client_secret !== undefined)
            request_form.set("client_secret",client_secret);

        if(scope !== undefined)
            request_form.set("scope",scope);

        try{
            const resp = await fetch(`${BASE_URL}/oauth/token`,{
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

    private update_token_params(response_body: RefreshTokenResponseBody){
        this.access_token = response_body.access_token;
        this.expires_at = response_body.expires_in;
        this.token_id = response_body.token_id;
        this.token_type = response_body.token_type;
    }
}