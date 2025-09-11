import { deleteV1ZonesByZone, getV1Zones, getV1ZonesByZone, postV1ZonesByZone } from 'dynamic-zones';
// Import from the bundled dependencies file
import { render, createContext, html, useState, useEffect, useContext, UserManager, Button, Navbar, Container, Panel, Section, Heading, Block } from './dist/deps.mjs';

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
        return html`Welcome ${user.profile.name}! <${Button} onClick=${logout}>Logout<//>`
    } else {
        return html`<${Button} onClick=${login}>Login<//>`
    }
}

function Header(props) {
    return html`
        <${Navbar} class="has-background-white-bis has-text-primary-invert " hoverable="false">    
            <${Navbar.Brand}>
                <a class="navbar-item" href="#">
                    <img src="img/DHBW-Logo.svg" style="height: 160px;" />
                </a>
                <${Navbar.Item}>
                    ${props.title}
                <//>
                <${Navbar.Burger} />
            <//>

            <${Navbar.Container} align="right">
                <${Navbar.Item}>
                    <${LoginLogoutButton} />
                <//>
            <//>
        <//>
  `
}

function ActivateZone(props) {
    const { user } = useAuth()
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const zone = props.zone

    if (loading)
        return html`<p>Activating zone ${zone}</p>`;

    if (error)
        return html`
            <${Block}>
            Sorry, there was an error activating the zone: 
            <pre>${error.message}</pre>
            <//>

            <${Block}>
                <${Button} onClick=${() => window.location.reload()}>Please refresh the page<//>.
            <//>
        `;

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

    return html`<${Button} onClick=${activate}>Activate<//>`;
}

function ExternalDnsConfig(props) {
    const dnsConfig = useContext(DnsConfigContext)
    const keys = props.zone.zone_keys
    const txtPrefix = "dynamic-zones-dns-"
    const txtOwnerId = "dynamic-zones-dns"

    function generateConfig(key) {
        return [
            `apiVersion: v1`,
            `kind: Namespace`,
            `metadata:`,
            `  name: external-dns`,
            `  labels:`,
            `    name: external-dns`,
            `---`,
            `apiVersion: apps/v1`,
            `kind: Deployment`,
            `metadata:`,
            `  name: external-dns`,
            `  namespace: external-dns`,
            `spec:`,
            `  selector:`,
            `    matchLabels:`,
            `      app: external-dns`,
            `  template:`,
            `    metadata:`,
            `      labels:`,
            `        app: external-dns`,
            `    spec:`,
            `      containers:`,
            `      - name: external-dns`,
            `        image: registry.k8s.io/external-dns/external-dns:v0.18.0`,
            `        args:`,
            `        - --registry=txt`,
            `        - --txt-prefix=${txtPrefix}`,
            `        - --txt-owner-id=${txtOwnerId}`,
            `        - --provider=rfc2136`,
            `        - --rfc2136-host=${dnsConfig.server_address}`,
            `        - --rfc2136-port=${dnsConfig.server_port}`,
            `        - --rfc2136-zone=${props.zone.zone}.`,
            `        - --rfc2136-tsig-secret=${key.key}`,
            `        - --rfc2136-tsig-secret-alg=${key.algorithm}`,
            `        - --rfc2136-tsig-keyname=${key.keyname}`,
            `        - --rfc2136-tsig-axfr`,
            `        - --source=ingress`,
            `        - --domain-filter=${props.zone.zone}.`,
        ].join('\n')
    }

    return html`
        ${keys.map(key => html`
            <div class="panel-block">
                <div class="box" style="max-width: 90%; overflow: auto;">
                    <h2 class="subtitle">Keyname: ${key.keyname}</h2>
                        <pre><code>${generateConfig(key)}</code></pre>
                </div>
            </div>

        `)}
    `
}

function DnsUpdateCommand(props) {
    const dnsConfig = useContext(DnsConfigContext)
    const keys = props.zone.zone_keys

    function generateNsUpdate(key) {
        const tmp = "<<"
        return [
            `# This command creates a new entry in DNS:`,
            `nsupdate -y "${key.algorithm}:${key.keyname}:${key.key}" -v ${tmp}EOF`,
            `server ${dnsConfig.server_address} ${dnsConfig.server_port}`,
            `zone ${props.zone.zone}`,
            `update add your-zone-name.${props.zone.zone}. 300 IN A 192.0.2.1`,
            `send`,
            `EOF`,
            ``,
            `# This command verifies the update:`,
            `dig @${dnsConfig.server_address} -p ${dnsConfig.server_port} your-zone-name.${props.zone.zone} A +short`
        ].join('\n')
    }

    return html`
            ${keys.map(key => html`
                <div class="panel-block">
                    <div class="box" style="max-width: 90%; overflow: auto;">
                        <h2 class="subtitle">Keyname: ${key.keyname}</h2>
                          <pre><code>${generateNsUpdate(key)}</code></pre>
                    </div>
                </div>
            `)}
    `
}

function ShowKeys(props) {
    const keys = props.zone.zone_keys

    return html`
        <div class="panel-block">
        This zone has ${keys.length} key${keys.length !== 1 ? 's' : ''} configured.
        </div>
        ${keys.map((key, index) => html`
            <div class="panel-block">
            <div class="box">
                    <h2 class="subtitle">Key #${index + 1}</h2>
                    <strong>Keyname:</strong> ${key.keyname}<br/>
                    <strong>Algorithm:</strong> ${key.algorithm}<br/>
                    <strong>Key:</strong> ${key.key}
                </div>
            </div>
        `)}
    `
}


function ActiveDomain(props) {
    const { user } = useAuth()
    const tabs = ["Manage", "Keys", "DNS Update Command", "External DNS Config"]
    const [activeTab, setActiveTab] = useState(tabs[0])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [zone, setZone] = useState(null)

    useEffect(async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await getV1ZonesByZone({ path: { zone: props.zone }, headers: authHeaders(user) })
            const zoneData = res?.data

            if (!zoneData) {
                setError(new Error(`Zone ${props.zone} not found or not active.`))
            } else {
                setZone(zoneData)
            }

        } catch (err) {
            setError(err)
        } finally {
            setLoading(false)
        }

    }, [user, props.zone])

    if (loading)
        return html`<p>Loading zone details...</p> `;

    if (error)
        return html`<p>Error loading zone details: ${error.message}</p>`;

    async function deleteZone(user, zone) {
        const res = await deleteV1ZonesByZone({ path: { zone }, headers: authHeaders(user) })
        if (res.response.status !== 204) {
            throw new Error(`Failed to delete zone ${zone}: ${res.response.statusText}`);
        }
    }

    return html`
        <p class="panel-tabs">
            ${tabs.map(tab => html`<a class=${tab === activeTab ? "is-active" : ""} onClick=${() => setActiveTab(tab)}>${tab}</a>`)}
        </p>

        ${activeTab === "Manage" && html`
                <div class="panel-block">
                    <${Button} onClick=${() => { deleteZone(user, zone.zone); props.onChange(); }}> Delete<//>
                </div>`} 
        ${activeTab === "Keys" && html`<${ShowKeys} zone=${zone} />`}
        ${activeTab === "DNS Update Command" && html`<${DnsUpdateCommand} zone=${zone} />`}
        ${activeTab === "External DNS Config" && html`<${ExternalDnsConfig} zone=${zone} />`}
    `
}

function AvailableDomain(props) {
    return html`
        <nav class="panel">
            <div class="panel-heading">
                Zone: ${props.zone.name}
            </div>
            
                ${props.zone.exists ?
            html`<${ActiveDomain} zone=${props.zone.name} onChange=${props.onChange} />` :
            html`<div class="panel-block"><${ActivateZone} zone=${props.zone.name} onChange=${props.onChange} /></div`
        }
        </nav>
        `
}

function AvailableDomainsList(props) {
    return html`
        <${Section}>
            <${Container}>
                <${Heading}>Domains<//>
                ${props.zones.map(zone => html`<${AvailableDomain} zone=${zone} onChange=${props.onChange} />`)}
            <//>
        <//>
    `
}
function ListZones() {
    const { user } = useAuth()
    const [zones, setZones] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [reloadTrigger, setReloadTrigger] = useState(true)
    const dnsConfig = useContext(DnsConfigContext)

    useEffect(async () => {
        try {
            const response = await getV1Zones({ headers: authHeaders(user) })
            const zones = response?.data?.zones
            if (!zones)
                throw new Error(`Unable to load available zones, message: ${response.statusText}, HTTP status: ${response.status} `)

            setZones(zones)
        } catch (error) {
            setError(error)
        } finally {
            setLoading(false)
        }
        return () => { }
    }, [reloadTrigger, user])

    if (loading)
        return html`<p>Loading zones...</p>`;

    if (error)
        return html`<a onClick=${handleReloadClick}>Retry Load</a> `;

    return html`<${AvailableDomainsList} zones=${zones} dnsConfig=${dnsConfig} onChange=${() => setReloadTrigger(!reloadTrigger)}/>`
}

function Main() {
    const { user, login } = useAuth()

    if (!user) {
        return html`<p>Please <a onClick="${login}">log in</a> to access your data.</p>`;
    }

    return html`
        <${Container}>
            <${ListZones} />
        <//>`
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
