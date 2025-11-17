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
    const helmAddRepoCommand = `helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/; helm repo update`;
    const helmCommand = `curl -H 'Authorization: Bearer ${token || "insert_your_token"}' '${url}values.yaml' | helm upgrade --install external-dns external-dns/external-dns -n external-dns -f -`;

    return html`
        <section class="section p-4">
            <div class="container content">
                <p>
                    This section show how to configure <a href="https://github.com/kubernetes-sigs/external-dns">External DNS</a>. 
                    
                    This allows for the automatic management of DNS records in this Dynamic Zones server based on the resources in your Kubernetes cluster. 
                    
                    You need to add the External DNS Helm repository to your local Helm setup first (only once):

                    <${CodeBlock} code=${helmAddRepoCommand} />
                </p>
                <p>
                    You can curl Helm's values.yaml directly using something like the following command:
                    
                    <${CodeBlock} code=${helmCommand} />

                    ${!token ? html`
                        <div class="has-background-danger has-text-white">
                            You need a valid token to authenticate the request. Use the "API Tokens" section to create one.
                            This token should have read-only permissions. Once created, a token (preferably read-only) 
                            will be automatically inserted into the command above.
                        </div>
                        ` : ''}
                </p>
                        
                <p>
                    For a manual installation, use the following values.yaml content:

                    <${CodeBlock} code=${externalDnsValuesYaml} />
                </p>
            </div>
        </section>
    `;

}
