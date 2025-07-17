
import { UserManager } from 'oidc';
import { deleteV1ZonesByZone, getV1Zones, getV1ZonesByZone, postV1ZonesByZone } from 'dynamic-zones';
import { render, createContext } from 'preact';
import { html } from 'htm/preact';
import { useState, useEffect, useContext } from 'preact/hooks';

// DNS Server Configuration
const DnsConfigContext = createContext(null);

function useDnsConfig(url) {
    const [dnsConfig, setDnsConfig] = useState(null)
    const [error, setError] = useState(null)
    useEffect(() => {
        async function fetchData() {
            try {
                const response = await fetch(url)
                if (!response.ok)
                    throw new Error(`HTTP error! status: ${response.status}`)
                const jsonData = await response.json();
                console.log("Fetched DNS config:", jsonData)
                setDnsConfig(jsonData)
            } catch (e) {
                setError(e)
            }
        }
        fetchData()
    }, [])
    return { dnsConfig, error }
}

function DnsConfigProvider({ url, children }) {
    const { dnsConfig, error } = useDnsConfig(url);
    console.log("Got ", dnsConfig, " from ", url, "with error", error)
    if (error) return (html`<div>Error loading data: {error.message}</div>`)
    return (html`<${DnsConfigContext.Provider} value=${dnsConfig}>${children}<//>`)
}

// User Manager Configuration
function useUserManager() {
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

const AuthContext = createContext();

function AuthProvider({ userManager, loading, children }) {
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

const useAuth = () => useContext(AuthContext);

function authHeaders(user) {
    return user && user.access_token ? { Authorization: `Bearer ${user.access_token}` } : {}
}





function LoginLogoutButton() {
    const { user, login, logout } = useAuth()

    if (user) {
        return html`Welcome ${user.profile.name}! <a onClick=${logout}>Logout</a>`
    } else {
        return html`<a onClick=${login}>Login</a>`
    }
}

function Header(props) {
    return html`
    <header>
        <div class="grid">
            <div>
                <h1>${props.title}</h1>
            </div>
            <div></div>
            <div>
                <${LoginLogoutButton} />
            </div>
        </div>
    </header>
  `
}

async function getAvailableZones(user) {
    const response = await getV1Zones({ headers: authHeaders(user) })
    const zones = response?.data?.zones
    if (!zones)
        throw new Error(`HTTP error! status: ${response.status}`);
    console.log("Available zones:", zones)
    return zones
}

async function getZone(user, zone) {
    const res = await getV1ZonesByZone({ path: { zone }, headers: authHeaders(user) })
    if (res.response.status === 404) {
        return null
    }

    return res.data
}

async function getZones(user) {
    const availableZones = await getAvailableZones(user)

    const result = {
        available: [],
        existing: []
    }

    for (const zone of availableZones) {
        try {
            const zoneData = await getZone(user, zone)
            if (zoneData) {
                console.log(`Zone ${zone} data:`, zoneData)
                result.existing.push(zoneData)
            } else {
                console.warn(`Zone ${zone} not found`)
                result.available.push(zone)
            }
        } catch (err) {
            console.error(`Error fetching zone ${zone}:`, err)
        }

    }
    return result
}

async function deleteZone(user, zone) {
    const res = await deleteV1ZonesByZone({ path: { zone }, headers: authHeaders(user) })
    if (res.response.status !== 204) {
        throw new Error(`Failed to delete zone ${zone}: ${res.response.statusText}`);
    }
}

function ActivateZone(props) {
    const { user } = useAuth()
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const zone = props.zone

    if (loading)
        return html`<p>Activating zone ${zone}</p>`;

    if (error)
        return html`Sorry, there was an error activating the zone: ${error.message}. Please <a onClick=${() => window.location.reload()}>refresh the page</a>.`;

    async function activate() {
        setLoading(true);
        setError(null);

        try {
            const res = await postV1ZonesByZone({ path: { zone }, headers: authHeaders(user) })

            if (res.response.status === 201) {
                console.log(`Zone ${zone} activated successfully`);
                props?.onChange(zone)
            } else {
                throw new Error(`Failed to activate zone ${zone}: ${res.response.statusText}`);
            }
        } catch (err) {
            console.error("Error activating zone:", err);
            setError(err);
        } finally {
            setLoading(false);
        }
    }

    return html`${props.zone} <a onClick=${activate}>Activate</a>`;
}

function AvailableDomainsList(props) {
    return html`
    <h3>Available Domains</h3>
        <ul>
            ${props.available.map(zone => html`
                <li key=${zone}>
                    <${ActivateZone} zone=${zone} onChange=${props.onChange} />
                </li>
            `)}
        </ul>
    `
}

function ExternalDnsConfig(props) {
    const dnsConfig = useContext(DnsConfigContext)
    const txtPrefix = "dynamic-zones-dns-"
    const txtOwnerId = "dynamic-zones-dns"

    const contents = `apiVersion: v1
kind: Namespace
metadata:
  name: external-dns
  labels:
    name: external-dns
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  namespace: external-dns
spec:
  selector:
    matchLabels:
      app: external-dns
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      containers:
      - name: external-dns
        image: registry.k8s.io/external-dns/external-dns:v0.18.0
        args:
        - --registry=txt
        - --txt-prefix=${txtPrefix}
        - --txt-owner-id=${txtOwnerId}
        - --provider=rfc2136
        - --rfc2136-host=${dnsConfig.server_address}
        - --rfc2136-port=${dnsConfig.server_port}
        - --rfc2136-zone=${props.zone.zone}.
        - --rfc2136-tsig-secret=${props.keydata.key}
        - --rfc2136-tsig-secret-alg=${props.keydata.algorithm}
        - --rfc2136-tsig-keyname=${props.keydata.keyname}
        - --rfc2136-tsig-axfr
        - --source=ingress
        - --domain-filter=${props.zone.zone}.
`
    return html`<pre><code>${contents}</code></pre>`
}

function DnsUpdateCommand(props) {
    const dnsConfig = useContext(DnsConfigContext)
    const tmp = "<<"

    const contents = `nsupdate -y "${props.keydata.algorithm}:${props.keydata.keyname}:${props.keydata.key}" -v ${tmp}EOF
server ${dnsConfig.server_address} ${dnsConfig.server_port}
zone ${props.zone.zone}
update add your-zone-name.${props.zone.zone}. 300 IN A 192.0.2.1
send
EOF
dig @${dnsConfig.server_address} -p ${dnsConfig.server_port} your-zone-name.${props.zone.zone} A +short
`

    return html`<pre><code>${contents}</code></pre>`
}

function ActiveDomainsList(props) {
    const { user } = useAuth()

    return html`
    <h3>Active Domains</h3>
        <ul>
            ${props.active.map(zone => html`<li key=${zone.zone}>
                ${zone.zone + " "}
                
                <a onClick=${() => { deleteZone(user, zone.zone); props.onChange(); }}>Delete</a>   
                <ul>
                    ${zone.zone_keys.map(key => html`
                        <li>Keyname: ${key.keyname}</li>
                        <li>Algorithm: ${key.algorithm}</li>
                        <li>Key: ${key.key}</li>
                        <li>Command to test DNS updates: <br/>
                            <${DnsUpdateCommand} keydata=${key} zone=${zone}/>
                        </li>
                        <li>External DNS config: <br/>
                            <${ExternalDnsConfig} keydata=${key} zone=${zone}/>
                        </li>
                    `)}
                </ul>
            </li>`)}
        </ul>
    `
}

function ListZones() {
    const { user } = useAuth()
    const [zones, setZones] = useState({ available: [], existing: [] })
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [reloadTrigger, setReloadTrigger] = useState(0)
    const dnsConfig = useContext(DnsConfigContext)

    useEffect(() => {
        try {
            getZones(user).then(zones => setZones(zones))
        } catch (error) {
            setError(error)
        } finally {
            setLoading(false)
        }
        return () => { }
    }, [reloadTrigger, user])

    if (loading)
        return html`<p>Loading zones...</p> `;

    if (error)
        return html`<a onClick=${handleReloadClick}>Retry Load</a>`;

    return html`
            <${AvailableDomainsList} available=${zones.available} onChange=${() => setReloadTrigger(reloadTrigger + 1)}/>
            <${ActiveDomainsList} active=${zones.existing} dnsConfig=${dnsConfig} onChange=${() => setReloadTrigger(reloadTrigger + 1)}/>
    `
}

function Main() {
    const { user, login } = useAuth()

    if (!user) {
        return html`<p> Please <a onClick="${login}">log in</a> to access your data.</p> `;
    }

    return html`
        <main>
            <${ListZones} />
        </main>`
}

// App
function App() {
    const { userManager, loading } = useUserManager()

    if (loading)
        return html`<p>Loading configuration...</p>`;

    return html`
        <${AuthProvider} userManager=${userManager} loading=${loading}>
            <${DnsConfigProvider} url="../dns_config.json">
                <${Header} title="Dynamic Zones DNS API" />
                <${Main} />
            <//>
        <//>
    `
}

render(
    html`<${App} name="Dynamic Zones DNS API" />`, document.getElementById('app')
)
