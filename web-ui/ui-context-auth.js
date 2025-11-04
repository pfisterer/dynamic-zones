import { createContext, html, useState, useEffect, useContext, UserManager } from './dist/deps.mjs';
export const AuthContext = createContext();

// Custom hook to access auth state
export const useAuth = () => useContext(AuthContext);

export function authHeaders(user) {
    return user && user.access_token ? { Authorization: `Bearer ${user.access_token}` } : {}
}

export function AuthProvider({ userManager, loading, children }) {
    const [user, setUser] = useState(null);
    useEffect(() => {
        if (!userManager || loading) return;
        userManager.getUser().then((u) => { if (u && !u.expired) setUser(u); });
        userManager.events.addUserLoaded(setUser);
        userManager.events.addUserUnloaded(() => setUser(null));
    }, [userManager, loading]);
    const login = () => userManager?.signinRedirect()
    const logout = () => userManager?.signoutRedirect()
    return html`<${AuthContext.Provider} value=${{ user, login, logout, loading }}>${children}<//>`
}

// User Manager Configuration
export function useUserManager() {
    const [userManager, setUserManager] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        (async () => {
            try {
                const auth_config = await (await fetch("../auth_config.json")).json();
                if (auth_config.auth_provider !== 'oidc') {
                    throw new Error('Unsupported authentication provider: ' + auth_config.auth_provider);
                }

                const config = {
                    authority: auth_config.issuer_url,
                    client_id: auth_config.client_id,
                    redirect_uri: auth_config.redirect_uri,
                    post_logout_redirect_uri: auth_config.logout_uri,
                    response_type: 'code', // Authorization Code Flow with PKCE (default for oidc-client-ts)
                    scope: 'openid profile email', // What claims you need
                    loadUserInfo: true, // Fetch user info from /userinfo endpoint
                    //monitorSession: false, // Enable session monitoring
                    //automaticSilentRenew: false, // Automatically renew tokens before they expire
                    // silent_renew_url: 'http://localhost:8000/silent-renew.html', // Optional: if you need a dedicated silent renew iframe
                }

                let userManager = new UserManager(config)
                const urlParams = new URLSearchParams(window.location.search);
                const isCallback = urlParams.has('code') || urlParams.has('error');

                // 👇 Handle redirect from Keycloak
                if (isCallback) {
                    try {
                        await userManager.signinRedirectCallback();
                        window.history.replaceState({}, document.title, window.location.pathname);
                    } catch (err) {
                        console.error("Error handling redirect callback:", err);
                    }
                }

                setUserManager(userManager)
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        })();
    }, []);

    return { userManager, loading };
}
