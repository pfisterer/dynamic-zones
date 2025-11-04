import { getV1Tokens, postV1Tokens, deleteV1TokensById } from 'dynamic-zones';
import { useAuth, authHeaders } from './ui-context-auth.js';
import { html, useState, useEffect } from './dist/deps.mjs';
import { FetchModal } from './ui-modal-fetch.js';

export function ListTokens() {
    const { user } = useAuth();
    const [tokens, setTokens] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [readOnly, setReadOnly] = useState(false)

    async function fetchTokens() {
        setLoading(true);
        setError(null);
        try {
            const res = await getV1Tokens({ headers: authHeaders(user) });
            setTokens(res?.data?.tokens || []);
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    useEffect(() => { fetchTokens(); }, [user]);

    async function createToken() {
        setLoading(true);
        setError(null);
        try {
            const res = await postV1Tokens({
                body: { read_only: readOnly },
                headers: {
                    "Content-Type": "application/json",
                    ...authHeaders(user)
                }
            });

            if (res?.data?.token) {
                setTokens(prev => [...prev, res.data.token]);
            }
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    async function deleteToken(tokenId) {
        setLoading(true);
        setError(null);
        try {
            await deleteV1TokensById({ path: { id: tokenId }, headers: authHeaders(user) });
            setTokens(prev => prev.filter(t => t.id !== tokenId));
        } catch (e) {
            setError(e);
        } finally {
            setLoading(false);
        }
    }

    if (loading) return html`<p>Loading tokens...</p>`;
    if (error) return html`<p>Error: ${error.message}</p>`;

    return html`
        <section class="mt-5">
            <div class="container">
                <h1 class="title">API Tokens</h1>

                <div class="panel">
                    <div class="panel-heading">API Tokens</div>

                    <div class="panel-block" style="gap: 10px; align-items: center;">
                        <button class="button is-primary" onClick=${createToken}>Create Token</button>
                        <label>
                            <input type="checkbox" checked=${readOnly}
                                onChange=${e => setReadOnly(e.target.checked)} />
                            Read-only
                        </label>
                    </div>

                    ${tokens.length === 0 && html`<div class="panel-block">No tokens found.</div>`}

                    ${tokens.map(t => html`
                        <div class="panel-block">
                            <div style="display:flex; justify-content: space-between; width:100%;">
                                <div>
                                    <strong>${t.token_string}</strong> (ID: ${t.id})<br/>
                                    Expires: ${t.expires_at}<br/>
                                    Mode: ${t.read_only ? "🔒 read-only" : "✏️ read-write"}
                                </div>
                                <${FetchModal} endpoint=${window.location + "../v1/tokens/"} token=${t.token_string} />
                                <button class="button is-danger is-small" onClick=${() => deleteToken(t.id)}>Delete</button>
                            </div>
                        </div>
                    `)}
                </div>
            </div>
        </div>
    `;
}
