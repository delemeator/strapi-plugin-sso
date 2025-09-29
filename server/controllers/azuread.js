import axios from "axios";
import {Buffer} from 'buffer';
import { randomUUID } from "crypto";
import pkceChallenge from "pkce-challenge";

const configValidation = () => {
  const config = strapi.config.get("plugin::strapi-plugin-sso");
  if (
    config["AZUREAD_OAUTH_CLIENT_ID"] &&
    config["AZUREAD_OAUTH_CLIENT_SECRET"] &&
    config["AZUREAD_TENANT_ID"]
  ) {
    return config;
  }
  throw new Error(
    "AZUREAD_OAUTH_CLIENT_ID, AZUREAD_OAUTH_CLIENT_SECRET, and AZUREAD_TENANT_ID are required"
  );
};

/**
 * Common constants
 */
const OAUTH_ENDPOINT = (tenantId) =>
  `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize`;
const OAUTH_TOKEN_ENDPOINT = (tenantId) =>
  `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
const OAUTH_USER_INFO_ENDPOINT = "https://graph.microsoft.com/oidc/userinfo";
const OAUTH_GRANT_TYPE = "authorization_code";
const OAUTH_RESPONSE_TYPE = "code";

async function azureAdSignIn(ctx) {
  const config = configValidation();
  const endpoint = OAUTH_ENDPOINT(config["AZUREAD_TENANT_ID"]);

  // Generate code verifier and code challenge
  const { code_verifier: codeVerifier, code_challenge: codeChallenge } =
    pkceChallenge();

  // Store the code verifier in the session
  ctx.session.codeVerifier = codeVerifier;

  const state = crypto.getRandomValues(Buffer.alloc(32)).toString('base64url');
  ctx.session.oidcState = state;

  const params = new URLSearchParams();
  params.append('client_id', config['AZUREAD_OAUTH_CLIENT_ID']);
  params.append('redirect_uri', config['AZUREAD_OAUTH_REDIRECT_URI']);
  params.append('scope', config['AZUREAD_SCOPE']);
  params.append('response_type', OAUTH_RESPONSE_TYPE);
  params.append('code_challenge', codeChallenge);
  params.append('code_challenge_method', 'S256');
  params.append('state', state);
  const url = `${endpoint}?${params.toString()}`;
  ctx.set("Location", url);
  return ctx.send({}, 302);
}

export const REFRESH_COOKIE_NAME = 'strapi_admin_refresh';

export const DEFAULT_MAX_REFRESH_TOKEN_LIFESPAN = 30 * 24 * 60 * 60;
export const DEFAULT_IDLE_REFRESH_TOKEN_LIFESPAN = 14 * 24 * 60 * 60;
export const DEFAULT_MAX_SESSION_LIFESPAN = 1 * 24 * 60 * 60;
export const DEFAULT_IDLE_SESSION_LIFESPAN = 2 * 60 * 60;

export const getRefreshCookieOptions = () => {
  const isProduction = strapi.config.get('environment') === 'production';
  const domain =
    strapi.config.get('admin.auth.cookie.domain') || strapi.config.get('admin.auth.domain');
  const path = strapi.config.get('admin.auth.cookie.path', '/admin');

  const sameSite =
    strapi.config.get('admin.auth.cookie.sameSite') ?? 'lax';

  return {
    httpOnly: true,
    secure: isProduction,
    overwrite: true,
    domain,
    path,
    sameSite,
    maxAge: undefined,
  };
};

const getLifespansForType = (
  type
) => {
  if (type === 'refresh') {
    const idleSeconds = Number(
      strapi.config.get(
        'admin.auth.sessions.idleRefreshTokenLifespan',
        DEFAULT_IDLE_REFRESH_TOKEN_LIFESPAN
      )
    );
    const maxSeconds = Number(
      strapi.config.get(
        'admin.auth.sessions.maxRefreshTokenLifespan',
        DEFAULT_MAX_REFRESH_TOKEN_LIFESPAN
      )
    );

    return { idleSeconds, maxSeconds };
  }

  const idleSeconds = Number(
    strapi.config.get('admin.auth.sessions.idleSessionLifespan', DEFAULT_IDLE_SESSION_LIFESPAN)
  );
  const maxSeconds = Number(
    strapi.config.get('admin.auth.sessions.maxSessionLifespan', DEFAULT_MAX_SESSION_LIFESPAN)
  );

  return { idleSeconds, maxSeconds };
};

const buildCookieOptionsWithExpiry = (
  type,
  absoluteExpiresAtISO
) => {
  const base = getRefreshCookieOptions();
  if (type === 'session') {
    return base;
  }

  const { idleSeconds } = getLifespansForType('refresh');
  const now = Date.now();
  const idleExpiry = now + idleSeconds * 1000;
  const absoluteExpiry = absoluteExpiresAtISO
    ? new Date(absoluteExpiresAtISO).getTime()
    : idleExpiry;
  const chosen = new Date(Math.min(idleExpiry, absoluteExpiry));

  return { ...base, expires: chosen, maxAge: Math.max(0, chosen.getTime() - now) };
};

async function azureAdSignInCallback(ctx) {
  const config = configValidation();
  const userService = strapi.service('admin::user')
  const sessionManager = strapi.sessionManager('admin');
  const oauthService = strapi.plugin("strapi-plugin-sso").service("oauth");
  const roleService = strapi.plugin("strapi-plugin-sso").service("role");
  const whitelistService = strapi.plugin('strapi-plugin-sso').service('whitelist')

  if (!ctx.query.code) {
    return ctx.send(oauthService.renderSignUpError(`code Not Found`));
  }
  if (!ctx.query.state || ctx.query.state !== ctx.session.oidcState) {
    return ctx.send(oauthService.renderSignUpError(`Invalid state`))
  }

  const params = new URLSearchParams();
  params.append("code", ctx.query.code);
  params.append("client_id", config["AZUREAD_OAUTH_CLIENT_ID"]);
  params.append("client_secret", config["AZUREAD_OAUTH_CLIENT_SECRET"]);
  params.append("redirect_uri", config["AZUREAD_OAUTH_REDIRECT_URI"]);
  params.append("grant_type", OAUTH_GRANT_TYPE);

  // Include the code verifier from the session
  params.append("code_verifier", ctx.session.codeVerifier);

  try {
    const tokenEndpoint = OAUTH_TOKEN_ENDPOINT(config["AZUREAD_TENANT_ID"]);
    const response = await axios.post(tokenEndpoint, params, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    const userResponse = await axios.get(OAUTH_USER_INFO_ENDPOINT, {
      headers: {
        Authorization: `Bearer ${response.data.access_token}`,
      },
    });

    if (!userResponse.data.email) {
      throw new Error('Email address is not set. Please set email property to the Azure AD user.');
    }

    // whitelist check
    await whitelistService.checkWhitelistForEmail(userResponse.data.email)

    const dbUser = await userService.findOneByEmail(userResponse.data.email);
    let activateUser;
    let refreshToken;

    if (dbUser) {
      activateUser = dbUser;
      refreshToken = await sessionManager.generateRefreshToken(activateUser.id, undefined, { type: 'refresh' });
    } else {
      const azureAdRoles = await roleService.azureAdRoles();
      const roles =
        azureAdRoles && azureAdRoles["roles"]
          ? azureAdRoles["roles"].map((role) => ({
              id: role,
            }))
          : [];

      const defaultLocale = oauthService.localeFindByHeader(
        ctx.request.headers
      );
      activateUser = await oauthService.createUser(
        userResponse.data.email,
        userResponse.data.family_name,
        userResponse.data.given_name,
        defaultLocale,
        roles
      );
      refreshToken = await sessionManager.generateRefreshToken(activateUser.id, undefined, { type: 'refresh' });

      // Trigger webhook
      await oauthService.triggerWebHook(activateUser);
    }
    // Login Event Call
    oauthService.triggerSignInSuccess(activateUser);

    const cookieOptions = buildCookieOptionsWithExpiry(
      'refresh',
      refreshToken.absoluteExpiresAt
    );
    ctx.cookies.set(REFRESH_COOKIE_NAME, refreshToken.token, cookieOptions);

    const accessToken = await sessionManager.generateAccessToken(refreshToken.token);

    const nonce = randomUUID();
    const html = oauthService.renderSignUpSuccess(
      accessToken.token,
      activateUser,
      nonce
    );
    ctx.set("Content-Security-Policy", `script-src 'nonce-${nonce}'`);
    ctx.send(html);
  } catch (e) {
    console.error(e);
    ctx.send(oauthService.renderSignUpError(e.message));
  }
}

export default {
  azureAdSignIn,
  azureAdSignInCallback,
};
