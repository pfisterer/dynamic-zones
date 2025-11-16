import { html, useState, useEffect, Route, Switch, Link, useRoute, useLocation } from './dist/deps.mjs';
import { useAuth, authHeaders } from './ui-context-auth.js';
import { useAppConfig } from './ui-context-appconfig.js';
import { CodeBlock } from './ui-component-codeblock.js';
import { getV1Zones, getV1ZonesByZone, postV1ZonesByZone, deleteV1ZonesByZone, getV1DnsRecords, postV1DnsRecordsCreate, postV1DnsRecordsDelete, getV1Tokens } from 'dynamic-zones';

function normalizeRecordName(name, zone) {
    if (!name) return '';
    let trimmedName = name.trim();

    // 1. Handle Zone Apex (Crucial for user input)
    // Send '@' if the input is '@' or the escaped '\@'.
    if (trimmedName === '@' || trimmedName === '\\@') {
        return '@';
    }

    // 2. Remove any trailing dot (CRITICAL FIX for server-side double-dot issue)
    // Prevents sending 'karls.' which leads to 'karls..zone.com.' on the server.
    // Use a loop/regex for robust removal in case of multiple trailing dots, though simple replace is usually enough.
    trimmedName = trimmedName.replace(/\.+$/, '');

    // 3. Fallback check for the zone name itself (often treated as apex)
    // If the stripped name is now equivalent to the zone name (minus the final dot), 
    // it's safest to treat it as the apex.
    if (trimmedName === zone.replace(/\.$/, '')) {
        return '@';
    }

    // 4. Pass the clean relative name to the backend.
    return trimmedName;
}

/**
 * Strips the zone name from the fully qualified record name for display.
 * Handles the special case of the zone apex ('@') record.
 * @param {string} recordName - The fully qualified record name (e.g., 'www.example.com.')
 * @param {string} zoneName - The zone name (e.g., 'example.com.')
 * @returns {string} The relative name (e.g., 'www' or '@')
 */
function stripZone(recordName, zoneName) {
    // Ensure both names end with a dot for consistent comparison
    const fqdnRecord = recordName.endsWith('.') ? recordName : recordName + '.';
    const fqdnZone = zoneName.endsWith('.') ? zoneName : zoneName + '.';

    // Check for the apex record case (Name is exactly the Zone)
    if (fqdnRecord === fqdnZone) {
        return '@'; // Conventionally represents the zone apex
    }

    // Strip the zone name from the end
    if (fqdnRecord.endsWith(fqdnZone)) {
        // Remove the zone name and the dot preceding it (e.g., remove '.example.com.')
        const relativeName = fqdnRecord.slice(0, -(fqdnZone.length + 1));

        // Final trim for safety, though slice should handle it
        return relativeName.replace(/\.$/, '');
    }

    // Fallback: Return the original name if stripping failed (e.g., if it was already relative)
    return recordName;
}

// ----------------------------------------
// Shared NSUPDATE command generator
// ----------------------------------------
export function generateNsUpdate(record, zone, tsigKey, appConfig) {
    return [
        `# Create/Update record in DNS`,
        `nsupdate -y "${tsigKey.algorithm}:${tsigKey.keyname}:${tsigKey.key}" <<EOF`,
        `server ${appConfig.dns_server_address} ${appConfig.dns_server_port}`,
        `zone ${zone}`,
        `update delete ${record.name}.${zone}. IN ${record.type}`,
        `update add ${record.name}.${zone}. ${record.ttl} IN ${record.type} ${record.value}`,
        `send`,
        `EOF`,
        ``,
        `# Verify`,
        `dig @${appConfig.dns_server_address} -p ${appConfig.dns_server_port} ${record.name}.${zone}. ${record.type} +short`
    ].join('\n');
}

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
// External DNS config display
// ----------------------------------------
function ExternalDnsConfig({ externalDnsValuesYaml, externalDnsSecretYaml, zone }) {
    const { apiUrl } = useAppConfig();
    const { user } = useAuth();
    const [token, setToken] = useState(null);

    useEffect(() => {
        (async () => {
            try {
                const res = await getV1Tokens({ headers: authHeaders(user) });
                const tokens = res?.data?.tokens
                if (tokens && tokens.length > 0) {
                    const readOnlyToken = tokens.find(t => t.read_only === true);
                    console.log("Found tokens:", tokens, "Using token:", readOnlyToken || tokens[0]);
                    setToken(readOnlyToken.token_string || tokens[0].token_string);
                }
            } catch (e) {
                console.error("Failed to fetch tokens:", e);
            }
        })();
    }, [user]);

    const url = `${apiUrl}v1/zones/${zone.zone}/?format=external-dns&part=`;
    const helmCommand = `curl -H 'Authorization: Bearer ${token || "insert_your_token"}' '${url}values.yaml' | helm upgrade --install external-dns external-dns/external-dns -n external-dns -f -`;

    return html`
        <div class="panel-block">
            <h2 class="subtitle">Kubernetes External DNS support</h2>
        </div>

        <div class="panel-block">
            <p>
                You can curl helm's values.yaml and a secret's yaml below directly using something like. Don't forget to add the local helm repository for external-dns first: 
                <code>helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/; helm repo update</code>.
            </p>
        </div>

        <div class="panel-block">
            <${CodeBlock} code=${helmCommand} />
        </div>

        <div class="panel-block">
            <h2 class="subtitle">Kubernetes External DNS Deployment</h2>
        </div>

        <div class="panel-block">
            <p>
                Use the following configuration to set up your Kubernetes cluster to automatically perform updates on this DNS server. 
                Please refer to the <a href="https://github.com/kubernetes-sigs/external-dns">External DNS documentation</a> for more information.
            </p>
        </div>
        
        <div class="panel-block">
            <${CodeBlock} code=${externalDnsValuesYaml} />
        </div>

    `;
}

// ----------------------------------------
// DNS Records Management
// ----------------------------------------
const SUPPORTED_TYPES = ["A", "AAAA"];


function DnsRecordRow({ zone, tsigKey, record, onChange }) {
    const { user } = useAuth();
    const { appConfig } = useAppConfig()

    const [editing, setEditing] = useState(false);
    const [fields, setFields] = useState({ ...record });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const isEditable = SUPPORTED_TYPES.includes(record.type.toUpperCase());

    async function handleUpdate() {
        setLoading(true);
        setError(null);
        try {
            const normalizedName = normalizeRecordName(fields.name, zone);

            const createRes = await postV1DnsRecordsCreate({
                body: {
                    ...fields,
                    name: normalizedName,
                    zone,
                    key_name: tsigKey.keyname,
                    key_algorithm: tsigKey.algorithm,
                    key: tsigKey.key
                },
                headers: authHeaders(user)
            });

            if (!createRes.response.ok) throw new Error(createRes.response.statusText);

            setEditing(false);
            onChange();
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }


    async function handleDelete() {
        if (!confirm(`Delete DNS record ${fields.name}?`)) return;
        setLoading(true);
        setError(null);
        try {
            const normalizedName = normalizeRecordName(fields.name, zone);

            const res = await postV1DnsRecordsDelete({
                body: {
                    ...fields,
                    name: normalizedName,
                    zone,
                    key_name: tsigKey.keyname,
                    key_algorithm: tsigKey.algorithm,
                    key: tsigKey.key
                },
                headers: authHeaders(user)
            });
            if (!res.response.ok) throw new Error(res.response.statusText);
            onChange();
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    async function handleCopy() {
        const nsupdate = generateNsUpdate(fields, zone, tsigKey, appConfig);
        try {
            await navigator.clipboard.writeText(nsupdate);
            alert('nsupdate command copied!');
        } catch {
            alert('Failed to copy.');
        }
    }

    return html`
        <tr>
            <td>
                <input class="input" value=${fields.name} onInput=${e => setFields({ ...fields, name: e.target.value })} disabled=${loading || !editing || !isEditable} /> 
            </td>
            <td>
                ${editing && isEditable ? html`
                <div class="select">
                    <select value=${fields.type} onChange=${e => setFields({ ...fields, type: e.target.value })} > ${SUPPORTED_TYPES.map(t => html`<option value=${t}>${t}</option>`)}
                    </select>
                </div>
                ` : html`<input class="input" value=${fields.type} disabled=${true} />
                `}
            </td>
            <td>
                <input class="input" type="number" value=${fields.ttl} onInput=${e => setFields({ ...fields, ttl: e.target.value })} disabled=${loading || !editing || !isEditable} />
            </td>
            <td>
                <input class="input" value=${fields.value} onInput=${e => setFields({ ...fields, value: e.target.value })} disabled=${loading || !editing || !isEditable} />
            </td>
            <td>
                ${editing && isEditable ? html`
                <button class="button is-success" onClick=${handleUpdate} disabled=${loading}>${loading ? "Saving..." : "Save"} </button>
                ` : html`
                <button class="button" onClick=${() => isEditable && setEditing(true)} disabled=${loading || !isEditable}> Edit </button> `}
                <button class="button is-danger ml-1" onClick=${handleDelete} disabled=${loading || !isEditable} >
                ${loading ? "Deleting..." : "Delete"}
                </button>

                <button class="button ml-1" onClick=${handleCopy}>Copy nsupdate</button>

                ${error && html`<div class="has-text-danger">${error.message}</div>`}
            </td>
            </tr>
    `;
}

function AddDnsRecordRow({ zone, tsigKey, onAdd }) {
    const { user } = useAuth();
    const [fields, setFields] = useState({ name: '', type: 'A', ttl: 300, value: '' });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    async function handleAdd() {
        setLoading(true);
        setError(null);
        try {
            const res = await postV1DnsRecordsCreate({
                body: {
                    ...fields,
                    zone,
                    name: normalizeRecordName(fields.name, zone),
                    key_name: tsigKey.keyname,
                    key_algorithm: tsigKey.algorithm,
                    key: tsigKey.key
                },
                headers: authHeaders(user)
            });
            if (!res.response.ok) throw new Error(res.response.statusText);
            setFields({ name: '', type: 'A', ttl: 300, value: '' });
            onAdd();
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    return html`
        <tr>
            <td><input class="input" placeholder="Name" value=${fields.name} onInput=${e => setFields({ ...fields, name: e.target.value })} /></td>
            <td>
            <div class="select">
                <select value=${fields.type} onChange=${e => setFields({ ...fields, type: e.target.value })} >
                ${SUPPORTED_TYPES.map(t => html`<option value=${t}>${t}</option>`)}
                </select>
            </div>
            </td>            
            <td><input class="input" type="number" value=${fields.ttl} onInput=${e => setFields({ ...fields, ttl: e.target.value })} /></td>
            <td><input class="input" value=${fields.value} onInput=${e => setFields({ ...fields, value: e.target.value })} /></td>
            <td>
                <button class="button is-primary" onClick=${handleAdd} disabled=${loading}>${loading ? 'Adding...' : 'Add'}</button>
                ${error && html`<div class="has-text-danger">${error.message}</div>`}
            </td>
        </tr>
    `;
}


function DnsRecordsList({ zone, tsigKey }) {
    const { user } = useAuth();
    const [records, setRecords] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    async function fetchRecords() {
        setLoading(true);
        setError(null);
        try {
            const res = await getV1DnsRecords({
                query: { zone },
                headers: {
                    ...authHeaders(user),
                    "X-DNS-Key-Name": tsigKey.keyname,
                    "X-DNS-Key-Algorithm": tsigKey.algorithm,
                    "X-DNS-Key": tsigKey.key,
                }
            });
            if (!res.data) throw new Error('No records found');

            const strippedRecords = res.data.records.map(record => ({
                ...record,
                name: stripZone(record.name, zone)
            }));

            setRecords(strippedRecords);
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => { fetchRecords(); }, []);

    if (loading) return html`<p>Loading DNS records...</p>`;
    if (error) return html`<div class="has-text-danger">Error loading DNS records: ${error.message}</div>`;

    return html`
        <table class="table is-fullwidth is-striped">
            <thead>
                <tr>
                    <th>Name</th><th>Type</th><th>TTL</th><th>Value</th><th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${records.map(record => html`<${DnsRecordRow} zone=${zone} tsigKey=${tsigKey} record=${record} onChange=${fetchRecords} />`)}
                <${AddDnsRecordRow} zone=${zone} tsigKey=${tsigKey} onAdd=${fetchRecords} />
            </tbody>
        </table>
    `;
}

// ----------------------------------------
// DNS Update Command Component
// ----------------------------------------
function DnsUpdateCommand({ zone }) {
    const { appConfig } = useAppConfig();
    return html`
        ${zone.zone_keys.map(key => html`
            <div class="panel-block">
                <div class="box" style="max-width:90%; overflow:auto;">
                    <h2 class="subtitle">Keyname: ${key.keyname}</h2>
                    <${CodeBlock} code=${generateNsUpdate({ name: 'your-zone-name', type: 'A', ttl: 300, value: '192.0.2.1' }, zone.zone, key, appConfig)} />
                </div>
            </div>
        `)}
    `;
}

// ----------------------------------------
// Show Keys
// ----------------------------------------
function ShowKeys({ zone }) {
    return html`
        <div class="panel-block">
            This zone has ${zone.zone_keys.length} key${zone.zone_keys.length !== 1 ? 's' : ''} configured.
        </div>
        ${zone.zone_keys.map((key, index) => html`
            <div class="panel-block">
                <div class="box">
                    <h2 class="subtitle">Key #${index + 1}</h2>
                    <strong>Keyname:</strong> ${key.keyname}<br/>
                    <strong>Algorithm:</strong> ${key.algorithm}<br/>
                    <strong>Key:</strong> ${key.key}
                </div>
            </div>
        `)}
    `;
}

// ----------------------------------------
// Active Domain Tabs
// ----------------------------------------
function ActiveDomain({ zone: zoneName, onChange }) {
    const { user } = useAuth();
    const tabs = ["Manage", "Keys", "DNS Update Command", "External DNS Config"];
    const [activeTab, setActiveTab] = useState(tabs[0]);
    const [zone, setZone] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [message, setMessage] = useState("Loading zone details...");

    useEffect(async () => {
        setLoading(true); setError(null);
        try {
            const res = await getV1ZonesByZone({ path: { zone: zoneName }, headers: authHeaders(user) });
            if (!res.data) throw new Error(`Zone ${zoneName} not found`);
            setZone(res.data);
        } catch (e) { setError(e); } finally { setLoading(false); }
    }, [user, zoneName]);

    async function handleDeleteClick() {
        try {
            setLoading(true); setMessage("Deleting zone...");
            const res = await deleteV1ZonesByZone({ path: { zone: zone.zoneData.zone }, headers: authHeaders(user) });
            if (res.response.status !== 204) throw new Error(res.response.statusText);
            onChange();
        } catch (e) { setError(e); } finally { setLoading(false); }
    }

    if (loading) return html`<p>${message}</p>`;
    if (error) return html`<p class="has-text-danger">${error.message}</p>`;

    return html`
        <p class="panel-tabs">
            ${tabs.map(tab => html`<a class=${tab === activeTab ? "is-active" : ""} onClick=${() => setActiveTab(tab)}>${tab}</a>`)}
        </p>

        ${activeTab === "Manage" && html`
            <div class="panel-block">
                <button class="button is-danger" onClick=${handleDeleteClick}>Delete Zone</button>
            </div>
            <div class="panel-block">
                <${DnsRecordsList} zone=${zone.zoneData.zone} tsigKey=${zone.zoneData.zone_keys[0]} />
            </div>
        `}
        ${activeTab === "Keys" && html`<${ShowKeys} zone=${zone.zoneData} />`}
        ${activeTab === "DNS Update Command" && html`<${DnsUpdateCommand} zone=${zone.zoneData} />`}
        ${activeTab === "External DNS Config" && html`<${ExternalDnsConfig} externalDnsValuesYaml=${zone.externalDnsValuesYaml} externalDnsSecretYaml=${zone.externalDnsSecretYaml} zone=${zone.zoneData} />`}
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
    const [match, params] = useRoute("/zone/:name");
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

    const selectedZone = zones.find(e => e.name === params?.name);
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
                    <${Route} path="/zone/:name">
                        ${() => selectedZone ? html`<${AvailableDomain} zone=${selectedZone} onChange=${() => setReloadTrigger(!reloadTrigger)} />` : html`<${RouteNotFound}/>`}
                    <//>

                    <!-- Redirect to the first zone if available -->
                    <${Route} path="/">
                        ${() => zones.length > 0 ? (navigate(`/zone/${zones[0].name}`, { replace: true }), null) : html`
                            <div class="content has-text-centered p-6">
                                    <h3 class="subtitle is-5">⬆️ Select a zone above to manage its DNS records.</h3>
                            </div>
                        `}  
                    <//>

                    <${Route} component=${RouteNotFound} />
                 <//>
            </div>
        </section>
    `;
}