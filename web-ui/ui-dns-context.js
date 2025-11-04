import { createContext, html, useState, useEffect } from './dist/deps.mjs';

// DNS Server Configuration
export const DnsConfigContext = createContext(null);

export function useDnsConfig(url) {
    const [dnsConfig, setDnsConfig] = useState(null)
    const [error, setError] = useState(null)
    useEffect(() => {
        async function fetchData() {
            try {
                const response = await fetch(url)
                if (!response.ok)
                    throw new Error(`HTTP error! status: ${response.status}`)
                const jsonData = await response.json();
                setDnsConfig(jsonData)
            } catch (e) {
                setError(e)
            }
        }
        fetchData()
    }, [])
    return { dnsConfig, error }
}

export function DnsConfigProvider({ url, children }) {
    const { dnsConfig, error } = useDnsConfig(url);
    if (error) return (html`<div>Error loading data: {error.message}</div>`)
    return (html`<${DnsConfigContext.Provider} value=${dnsConfig}>${children}<//>`)
}


