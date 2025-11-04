import { deleteV1ZonesByZone, getV1Zones, getV1ZonesByZone, postV1ZonesByZone } from 'dynamic-zones';
import { html, useState, useEffect, useContext } from './dist/deps.mjs';
import { useAuth, authHeaders } from './ui-auth-context.js';
import { DnsConfigContext } from './ui-dns-context.js';


function ActivateZone(props) {
    const { user } = useAuth()
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const zone = props.zone

    if (loading)
        return html`<p>Activating zone ${zone}</p>`;

    if (error)
        return html`
            <div class="block">
            Sorry, there was an error activating the zone: 
            <pre>${error.message}</pre>
            </div>

            <div class="block">
                <button class="button" onClick=${() => window.location.reload()}>Please refresh the page</button>.
            </div>
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

    return html`<button class="button" onClick=${activate}>Activate</button>`;
}

function ExternalDnsConfig(props) {

    return html`
            <div class="panel-block">
                <div class="box" style="max-width: 90%; overflow: auto;">
                        <pre><code>${props.externalDnsConfig}</code></pre>
                </div>
            </div>
        `
}

function DnsUpdateCommand(props) {
    const dnsConfig = useContext(DnsConfigContext)
    const keys = props.zone.zone_keys

    function generateNsUpdate(key) {
        const tmp = "<<"
        return [
            `# This command creates a new entry in DNS: `,
            `nsupdate - y "${key.algorithm}:${key.keyname}:${key.key}" - v ${tmp} EOF`,
            `server ${dnsConfig.server_address} ${dnsConfig.server_port} `,
            `zone ${props.zone.zone} `,
            `update add your - zone - name.${props.zone.zone} .300 IN A 192.0.2.1`,
            `send`,
            `EOF`,
            ``,
            `# This command verifies the update: `,
            `dig @${dnsConfig.server_address} -p ${dnsConfig.server_port} your - zone - name.${props.zone.zone} A + short`
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
            `)
        }
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
        `)
        }
    `
}


function ActiveDomain(props) {
    const { user } = useAuth()
    const tabs = ["Manage", "Keys", "DNS Update Command", "External DNS Config"]
    const [activeTab, setActiveTab] = useState(tabs[0])
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const [message, setMessage] = useState(null)
    const [zone, setZone] = useState(null)

    useEffect(async () => {
        setLoading(true)
        setMessage("Loading zone details...")
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
        return html`<p>${message}</p>`;

    if (error)
        return html`<p>An error occured: ${error.message}</p>`;

    async function handleDeleteClick() {
        try {
            setMessage("Deleting zone...")
            setLoading(true)

            const res = await deleteV1ZonesByZone({ path: { zone: zone.zoneData.zone }, headers: authHeaders(user) })
            if (res.response.status !== 204) {
                throw new Error(`Failed to delete zone ${zone.zoneData.zone}: ${res.response.statusText} `);
            }

            props.onChange();
        } catch (e) {
            setError(e)
        } finally {
            setLoading(false)
        }
    }

    return html`
    <p class="panel-tabs">
        ${tabs.map(tab => html`<a class=${tab === activeTab ? "is-active" : ""} onClick=${() => setActiveTab(tab)}>${tab}</a>`)}
        </p>

    ${activeTab === "Manage" && html`
                <div class="panel-block">
                    <button class="button is-danger" onClick=${handleDeleteClick}> Delete</button>
                </div>`}
        ${activeTab === "Keys" && html`<${ShowKeys} zone=${zone.zoneData} />`}
        ${activeTab === "DNS Update Command" && html`<${DnsUpdateCommand} zone=${zone.zoneData} />`}
        ${activeTab === "External DNS Config" && html`<${ExternalDnsConfig} externalDnsConfig=${zone.externalDnsConfig} />`}
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
            html`<div class="panel-block"><${ActivateZone} zone=${props.zone.name} onChange=${props.onChange} /></div>`
        }
        </nav>
    `
}

function AvailableDomainsList(props) {
    return html`
    <section class="mt-3">
        <div class="container">
            <h1 class="title">Domains</h1>
            ${props.zones.map(zone => html`<${AvailableDomain} zone=${zone} onChange=${props.onChange} />`)}
        </div>
    </section>
    `
}

export function ListZones() {
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
        return html`<a onClick=${handleReloadClick}>Retry Load</a>`;

    return html`<${AvailableDomainsList} zones=${zones} dnsConfig=${dnsConfig} onChange=${() => setReloadTrigger(!reloadTrigger)}/>`
}
