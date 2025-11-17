import { html, useState, useEffect, Route, Switch, Link, useRoute, useLocation } from './dist/deps.mjs';
import { useAuth, authHeaders } from './ui-context-auth.js';
import { ShowKeys } from './ui-component-show-keys.js';
import { ExternalDnsConfig } from './ui-component-external-dns.js';
import { DnsUpdateCommand } from './ui-component-dns-update-cmd.js';
import { DnsRecordsList } from './ui-component-dns-record-list.js';
import { getV1Zones, getV1ZonesByZone, postV1ZonesByZone, deleteV1ZonesByZone } from 'dynamic-zones';

// ----------------------------------------
// Activate Zone
// ----------------------------------------
function ActivateZone({ zone, onChange }) {
    const { user } = useAuth();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    async function activate() {
        setLoading(true);
        setError(null);
        try {
            const res = await postV1ZonesByZone({ path: { zone }, headers: authHeaders(user) });
            if (res.response.status !== 201) throw new Error(res.response.statusText);
            onChange(zone);
        } catch (err) {
            setError(err);
        } finally {
            setLoading(false);
        }
    }

    if (loading) return html`<p>Activating zone ${zone}...</p>`;
    if (error)
        return html`
            <div class="block">
                <pre>${error.message}</pre>
                <button class="button" onClick=${() => window.location.reload()}>Refresh</button>
            </div>
        `;

    return html`<button class="button" onClick=${activate}>Activate</button>`;
}


// ----------------------------------------
// Active Domain Tabs
// ----------------------------------------
function ActiveDomain({ zone: zoneName, onChange }) {
    const { user } = useAuth();
    const [zone, setZone] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [message, setMessage] = useState("Loading zone details...");
    const [currentLocation] = useLocation()
    const tabs = [
        { name: "Manage", path: "/" },
        { name: "Keys", path: "/keys" },
        { name: "DNS Update Command", path: "/update" },
        { name: "External DNS Config", path: "/config" }
    ];

    // Fetch zone data
    useEffect(async () => {
        setLoading(true);
        setError(null);
        try {
            const res = await getV1ZonesByZone({ path: { zone: zoneName }, headers: authHeaders(user) });
            if (!res.data) throw new Error(`Zone ${zoneName} not found`);
            setZone(res.data);
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }, [user, zoneName, currentLocation]);

    async function handleDeleteClick() {
        try {
            setLoading(true);
            setMessage("Deleting zone...");
            const res = await deleteV1ZonesByZone({ path: { zone: zone.zoneData.zone }, headers: authHeaders(user) });
            if (res.response.status !== 204)
                throw new Error(res.response.statusText);
            onChange();
        } catch (e) { setError(e); } finally { setLoading(false); }
    }

    if (loading) return html`<p>${message}</p>`;
    if (error) return html`<p class="has-text-danger">${error.message}</p>`;
    if (!zone || !zone.zoneData) return html`<p class="has-text-danger">Zone data corrupted.</p>`;

    return html`
        <div class="active-domain-wrapper">
            <p class="panel-tabs">
                ${tabs.map(({ name, path }) => html`<${Link} to=${path} class=${path === currentLocation ? "is-active" : ""}>${name} <//>`)}
            </p>

            <${Switch}>
                <${Route} path="/">
                    ${html`
                        <div class="panel-block">
                            <button class="button is-danger" onClick=${handleDeleteClick}>Delete Zone</button>
                        </div>
                        <div class="panel-block">
                            <${DnsRecordsList} zone=${zone.zoneData.zone} tsigKey=${zone.zoneData.zone_keys[0]} />
                        </div>
                    `}
                <//>
                
                <${Route} path="/keys">
                    ${html`<${ShowKeys} zone=${zone.zoneData} />`}
                <//>

                <${Route} path="/update">
                    ${html`<${DnsUpdateCommand} zone=${zone.zoneData} />`}
                <//>

                <${Route} path="/config">
                    ${html`<${ExternalDnsConfig} externalDnsValuesYaml=${zone.externalDnsValuesYaml} externalDnsSecretYaml=${zone.externalDnsSecretYaml} zone=${zone.zoneData} />`}
                <//>
                
                <${Route}>
                    <div class="panel-block has-text-danger">Tab not found.</div>
                <//>
            <//>
        </div>
    `;
}

// ----------------------------------------
// Available Domain List
// ----------------------------------------
function AvailableDomain({ zone, onChange }) {
    return html`
        <nav class="panel">
            <div class="panel-heading">Zone: ${zone.name}</div>
            ${zone.exists
            ? html`<${ActiveDomain} zone=${zone.name} onChange=${onChange} />`
            : html`<div class="panel-block"><${ActivateZone} zone=${zone.name} onChange=${onChange} /></div>`}
        </nav>
    `;
}

function RouteNotFound() {
    return html`
        <section class="mt-3">
            <div class="container">
                <h3 class="title is-4 has-text-danger">❌ Zone Not Found</h3>
                <p>The zone specified in the URL could not be located in your account.</p>
            </div>
        </section>
    `
}
// ----------------------------------------
// List Zones
// ----------------------------------------
export function ListZones() {
    const { user } = useAuth();
    const [zones, setZones] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [reloadTrigger, setReloadTrigger] = useState(true);
    const [match, params] = useRoute("/zone/:name/*?");
    const activeZoneName = match ? params.name : null;
    const [_, navigate] = useLocation()

    useEffect(async () => {
        setLoading(true); setError(null);
        try {
            const res = await getV1Zones({ headers: authHeaders(user) });
            if (!res.data?.zones) throw new Error("Unable to load zones");
            setZones(res.data.zones);
        } catch (e) { setError(e); } finally { setLoading(false); }
    }, [user, reloadTrigger]);

    if (loading) return html`<p>Loading zones...</p>`;
    if (error) return html`<a onClick=${() => setReloadTrigger(!reloadTrigger)}>Retry Load</a>`;

    function getZoneHtml(name) {
        const zone = zones.find(z => z.name === name)
        return zone ?
            html`<${AvailableDomain} zone=${zone} onChange=${() => setReloadTrigger(!reloadTrigger)} />` :
            html`<${RouteNotFound}>`
    }

    return html`
        <section class="section pt-4">
            <h1 class="title is-3">Zone Management</h1>
            
            <div class="mb-5">
                <nav class="panel">
                    <p class="panel-heading">
                        Available Zones (${zones.length})
                    </p>
                    ${zones.map(zone => html`
                        <${Link} 
                            to=${"/zone/" + zone.name} 
                            class="panel-block ${activeZoneName === zone.name ? 'has-background-grey-light has-text-white-ter' : ''}"
                        >
                            <span class="panel-icon">
                                <i class="fas fa-globe"></i>
                            </span>
                            ${zone.name}
                        <//> 
                    `)}
                    ${zones.length === 0 && html`
                        <div class="panel-block">
                            No zones available.
                        </div>
                    `}
                </nav>
            </div>

            <div class="box">
                <${Switch}>
                    <!-- Show the currently selected zone -->
                    <${Route} path="/zone/:name" nest>
                        ${param => getZoneHtml(param.name)}
                    <//>

                    <!-- Redirect to the first zone if available -->
                    <${Route} path="/">
                        ${() => zones.length > 0 ? (navigate(`/zone/${zones[0].name}`, { replace: true }), null) : html`
                            <div class="content has-text-centered p-6">
                                    <h3 class="subtitle is-5">⬆️ Select a zone above to manage its DNS records.</h3>
                            </div>
                        `}  
                    <//>

                 <//>
            </div>
        </section>
    `;
}
