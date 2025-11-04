import { createContext, html, useState, useEffect, useContext, UserManager } from './dist/deps.mjs';

export const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export function authHeaders(user) {
    return user?.access_token ? { Authorization: `Bearer ${user.access_token}` } : {};
}

export function AuthProvider({ children }) {
    const [userManager, setUserManager] = useState(null);
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        (async () => {
            try {
                const auth_config = await (await fetch("../auth_config.json")).json();

                if (auth_config.auth_provider !== 'oidc')
                    throw new Error('Unsupported authentication provider: ' + auth_config.auth_provider);

                const config = {
                    authority: auth_config.issuer_url,
                    client_id: auth_config.client_id,
                    redirect_uri: auth_config.redirect_uri,
                    post_logout_redirect_uri: auth_config.logout_uri,
                    response_type: 'code',
                    scope: 'openid profile email',
                    loadUserInfo: true
                };

                const um = new UserManager(config);
                setUserManager(um);

                // Handle OIDC callback
                const urlParams = new URLSearchParams(window.location.search);
                const isCallback = urlParams.has('code') || urlParams.has('error');
                if (isCallback) {
                    await um.signinRedirectCallback();
                    window.history.replaceState({}, document.title, window.location.pathname);
                }

                const u = await um.getUser();
                if (u && !u.expired) setUser(u);

                um.events.addUserLoaded(setUser);
                um.events.addUserUnloaded(() => setUser(null));

            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        })();
    }, []);

    const login = () => userManager?.signinRedirect();
    const logout = () => userManager?.signoutRedirect();

    return html`
        <${AuthContext.Provider} value=${{ user, login, logout, loading }}>
            ${children}
        <//>
    `;
}
