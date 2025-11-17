import { html, useState, useEffect } from './dist/deps.mjs';
import { useAuth, authHeaders } from './ui-context-auth.js';
import { useAppConfig } from './ui-context-appconfig.js';
import { CodeBlock } from './ui-component-codeblock.js';
import { getV1Tokens } from 'dynamic-zones';

// ----------------------------------------
// External DNS config display
// ----------------------------------------
export function ExternalDnsConfig({ externalDnsValuesYaml, zone }) {
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
            <h2 class="subtitle">Kubernetes <a href="https://github.com/kubernetes-sigs/external-dns">External DNS</> support</h2>
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
