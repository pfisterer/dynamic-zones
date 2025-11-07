import { createContext, html, useState, useEffect, useContext } from './dist/deps.mjs';

export const AppConfigContext = createContext(null);
export const useAppConfig = () => useContext(AppConfigContext);

export function AppConfigProvider({ children }) {
    const [config, setConfig] = useState(null);
    const [error, setError] = useState(null);

    // Set API URL based on current location
    useEffect(() => {
        const currentUrl = new URL(window.location.href);
        const normalizedApiUrl = new URL('../', currentUrl).toString();
        setConfig(prev => ({ ...prev, apiUrl: normalizedApiUrl }));
    }, []);

    // Load DNS config from dns_config.json
    useEffect(() => {
        (async () => {
            try {
                const apiUrl = config?.apiUrl;
                if (!apiUrl) return;

                // Load app config relative to API
                const appConfigUrl = new URL('../app_config.json', apiUrl).toString();
                const response = await fetch(appConfigUrl);
                if (!response.ok) throw new Error(`Failed to load app_config.json`);
                const appConfig = await response.json();

                console.log("Got app config:", appConfig);

                setConfig({ apiUrl, appConfig });
            } catch (e) {
                setError(e);
            }
        })();
    }, [config?.apiUrl]);

    if (error) return html`<div>Error loading config: ${error.message}</div>`;
    if (!config) return html`<p>Loading configuration...</p>`;

    return html`
        <${AppConfigContext.Provider} value=${config}>
            ${children}
        <//>
    `;
}
