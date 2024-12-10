export type TokenParams = {
    access_token: string,
    refresh_token: string,
    expires_at: number,
    token_id: string,
    token_type: string
}

export type RefreshTokenRequestBody = {
    grant_type: "refresh_token",
    client_id: string,
    client_secret?: string,
    refresh_token: string,
    scope?: string,
}

export type RefreshTokenArgs = (Omit<RefreshTokenRequestBody,"grant_type"|"refresh_token">)& {
    token_url: string,
}

export type RefreshTokenResponseBody = {
    access_token: string,
    expires_in: number,
    scope: string,
    token_id: string,
    token_type: string,
}

export type OAuthClientConfigParams = {
    client_id: string,
    client_secret: string,
    redirect_uri: string,
    connection: string,
    scope?: string,
    response_type?: string,
    organisation?: string,
}

export type CallbackParams = {
    authorization_code: string,
    state: string,
}

export type CallbackRequestParams = {
    grant_type: "authorization_code",
    client_id: string,
    code: string,
    code_verifier: string,
    redirect_uri: string,
}

export type CallbackResponse = TokenParams;

export type RuntimeEnv = "browser" | "node";