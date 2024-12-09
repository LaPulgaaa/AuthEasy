import assert from "minimalistic-assert";
import sha256 from "crypto-js/sha256";
import Base64 from "crypto-js/enc-base64";

type OAuthClientConfigParams = {
    client_id: string,
    client_secret: string,
    redirect_uri: string,
    connection: string,
    scope: string,
    response_type?: string,
    organisation?: string,
}

export class OAuthClient{
    private static instance:OAuthClient;

    private static oauth_server_url = "https://dev-8y1fpu7abt6p5vkk.au.auth0.com";

    private scope: string;
    private response_type: string;
    private client_id: string;
    private client_secret: string;
    private state: string;
    private redirect_uri: string;
    private connection: string;
    //Auth0 has introduced a new field "organisation" ie. ID of the organisation to use when authentication the user. 
    private organisation?: string;

    private config_store: Map<string,unknown> = new Map();

    private constructor(config: OAuthClientConfigParams){
        this.response_type = "code";
        this.state = this.generate_state();
        this.client_id = config.client_id;
        this.client_secret = config.client_secret;
        this.redirect_uri = config.redirect_uri;
        this.scope = config.scope;
        this.connection = config.connection;
        this.organisation = config.organisation;
        this.response_type = config.connection ?? "code";
    }

    public get_instance(config?: OAuthClientConfigParams){
        if(OAuthClient.instance === undefined){
            assert(config !== undefined)
            OAuthClient.instance = new OAuthClient(config);
        }

        return OAuthClient.instance;
    }

    public start_auth_flow(): string {

        const code_challenge = this.create_code_challenge();

        const params_obj = {
            scope: this.scope,
            response_type: this.response_type,
            client_id: this.client_id,
            state: this.state,
            redirect_uri: this.redirect_uri,
            code_challenge_method: "S256",
            code_challenge: code_challenge,
            connection: this.connection,
            prompt: "none", // use "prompt=none" to initiate a silent authentication request
        };

        const auth_url_search_params = new URLSearchParams(params_obj);

        if(this.organisation !== undefined)
            auth_url_search_params.set("organisation",this.organisation);

        return `${OAuthClient.oauth_server_url}/authorize?${auth_url_search_params.toString()}`
    }

    private generate_state(){
        //TODO: generate random csrf protection state param using external library
        const random_state = "randomstrtobereplaced";

        this.config_store.set("state",random_state);

        return random_state;
    }

    private generate_code_verifier(){
        // generate code verifier string
        const random_verifier_str = sha256("randomstrtobereplaced");
        const encoded_code_verifier = Base64.stringify(random_verifier_str);

        this.config_store.set("code_verifier",encoded_code_verifier);
        
        return encoded_code_verifier;
    }

    private create_code_challenge(){
        // create a code challenge using generate code verifier
        const code_verifier = this.generate_code_verifier();

        const hashed_code_verifier = sha256(code_verifier);
        const code_challenge_str = Base64.stringify(hashed_code_verifier);
        this.config_store.set("code_challenge",code_challenge_str);
        
        return code_challenge_str;
    }
}