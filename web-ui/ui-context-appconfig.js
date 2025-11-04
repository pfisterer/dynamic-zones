import { createContext, html, useState, useEffect } from './dist/deps.mjs';

// Centralized App Configuration Context
export const AppConfigContext = createContext(null);

export function useAppConfig(apiUrl) {
    const dnsConfigUrl = apiUrl + '../dns_config.json';
    const [appConfig, setAppConfig] = useState({ dnsConfig: null, apiUrl });
    const [error, setError] = useState(null);

    useEffect(() => {
        (async () => {
            try {
                const response = await fetch(dnsConfigUrl);
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                const dnsConfig = await response.json();
                setAppConfig(prev => ({ ...prev, dnsConfig }));
            } catch (e) {
                setError(e);
            }
        })();
    }, [apiUrl]);

    return { appConfig, error };
}

export function AppConfigProvider({ apiUrl, children }) {
    const { appConfig, error } = useAppConfig(apiUrl);

    if (error) return html`<div>Error loading app configuration: ${error.message}</div>`;
    if (!appConfig) return html`<p>Loading app configuration...</p>`;

    return html`<${AppConfigContext.Provider} value=${appConfig}>${children}<//>`;
}
