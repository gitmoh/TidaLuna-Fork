import { memoizeArgless } from "@inrixia/helpers";
import { findModuleProperty } from "@luna/core";

type TidalCredentials = {
	clientId: string;
	clientUniqueKey: string;
	expires: number;
	grantedScopes: string[];
	requestedScopes: string[];
	token: string;
	userId: string;
};

type BearerTokenData = {
	token_type: string;
	access_token: string;
	refresh_token: string;
	expiry_time: number;
	userId?: number;
	clientId?: string;
};

// Decode JWT token to extract payload (without verification)
const decodeJWT = (token: string): any => {
	try {
		const parts = token.split(".");
		if (parts.length !== 3) return null;

		const payload = parts[1];
		const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
		return JSON.parse(decoded);
	} catch (err) {
		console.error("[Luna] Failed to decode JWT:", err);
		return null;
	}
};

// Extract userId and clientId from access token
const extractTokenInfo = (tokenData: BearerTokenData): BearerTokenData => {
	const payload = decodeJWT(tokenData.access_token);

	if (payload) {
		// Extract userId from "uid" field
		if (payload.uid && !tokenData.userId) {
			tokenData.userId = payload.uid;
		}
		// Extract clientId from "cid" field
		if (payload.cid && !tokenData.clientId) {
			tokenData.clientId = payload.cid.toString();
		}
	}

	return tokenData;
};

// IPC helpers for token file operations
const readTokenFile = async (): Promise<BearerTokenData | null> => {
	try {
		return await (window as any).__ipcRenderer?.invoke("__Luna.readToken");
	} catch (err) {
		console.error("[Luna] Failed to read token file:", err);
		return null;
	}
};

const writeTokenFile = async (tokenData: BearerTokenData): Promise<void> => {
	try {
		await (window as any).__ipcRenderer?.invoke("__Luna.writeToken", tokenData);
	} catch (err) {
		console.error("[Luna] Failed to write token file:", err);
	}
};

// Refresh the bearer token using Tidal's OAuth endpoint
const refreshBearerToken = async (refreshToken: string, clientId: string = "13319"): Promise<BearerTokenData | null> => {
	try {
		const response = await fetch("https://auth.tidal.com/v1/oauth2/token", {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				grant_type: "refresh_token",
				refresh_token: refreshToken,
				client_id: clientId,
			}),
		});

		if (!response.ok) {
			console.error("[Luna] Token refresh failed:", response.status, response.statusText);
			return null;
		}

		const data = await response.json();
		const expiryTime = Date.now() / 1000 + (data.expires_in || 3600);

		return {
			token_type: data.token_type || "Bearer",
			access_token: data.access_token,
			refresh_token: data.refresh_token || refreshToken,
			expiry_time: expiryTime,
		};
	} catch (err) {
		console.error("[Luna] Token refresh error:", err);
		return null;
	}
};

// Convert bearer token data to TidalCredentials format
const bearerTokenToCredentials = (tokenData: BearerTokenData): TidalCredentials => {
	return {
		clientId: tokenData.clientId || "13319",
		clientUniqueKey: "",
		expires: tokenData.expiry_time * 1000, // Convert to milliseconds
		grantedScopes: ["r_usr", "w_usr", "w_sub"],
		requestedScopes: ["r_usr", "w_usr", "w_sub"],
		token: tokenData.access_token,
		userId: tokenData.userId?.toString() || "0",
	};
};

const _getCredentialsMemo = memoizeArgless(() =>
	findModuleProperty<() => Promise<TidalCredentials>>((key, value) => key === "getCredentials" && typeof value === "function")!.value!(),
);

export const getCredentials = async (): Promise<TidalCredentials> => {
	// First, try to get credentials from token.json
	let tokenData = await readTokenFile();

	if (tokenData) {
		// Extract userId and clientId from JWT if not present
		tokenData = extractTokenInfo(tokenData);

		const now = Date.now() / 1000;
		const timeUntilExpiry = tokenData.expiry_time - now;

		// If token expires in less than 5 minutes, refresh it
		if (timeUntilExpiry < 300) {
			console.log("[Luna] Token expiring soon, refreshing...");
			const refreshedToken = await refreshBearerToken(tokenData.refresh_token, tokenData.clientId);

			if (refreshedToken) {
				// Preserve userId and clientId from original token
				refreshedToken.userId = tokenData.userId;
				refreshedToken.clientId = tokenData.clientId || "13319";

				// Extract info from refreshed token as well
				const updatedToken = extractTokenInfo(refreshedToken);

				await writeTokenFile(updatedToken);
				console.log("[Luna] Token refreshed successfully");
				return bearerTokenToCredentials(updatedToken);
			} else {
				console.warn("[Luna] Token refresh failed, using existing token");
			}
		}

		// Token is still valid or refresh failed, use existing token
		return bearerTokenToCredentials(tokenData);
	}

	// Fall back to extracting credentials from Tidal's internals
	const creds = await _getCredentialsMemo();
	if (creds.expires < Date.now()) {
		_getCredentialsMemo.clear();
		return _getCredentialsMemo();
	}
	return creds;
};
