import { render, html, useState, useEffect } from './dist/deps.mjs';
import { ListTokens } from './ui-component-tokens.js';
import { ListZones } from './ui-component-zones.js';
import { useUserManager, useAuth, AuthProvider } from './ui-context-auth.js';
import { AppConfigProvider } from './ui-context-appconfig.js';

function LoginLogoutButton() {
    const { user, login, logout } = useAuth()

    if (user) {
        return html`Welcome ${user.profile.name}! <button class="button" onClick=${logout}>Logout</button>`
    } else {
        return html`<button class="button" onClick=${login}>Login</button>`
    }
}

function Header(props) {
    return html`
        <nav class="navbar is-fixed-top" role="navigation" class="has-background-white-bis has-text-primary-invert" hoverable="false">
                <div class="navbar-brand">
                <a class="navbar-item" href="#">
                    <img src="img/DHBW-Logo.svg" style="height: 2em;" />
                </a>

                <div class="navbar-item">
                    ${props.title}
                </div>
                
                <div class="navbar-end">
                    <div class="navbar-item">
                        <${LoginLogoutButton} />
                    </div>
                </div>
            </div>
        </nav>
  `
}

function Documentation() {
    const [endpoint, setEndpoint] = useState(null)
    useEffect(() => setEndpoint(window.location.protocol + "//" + window.location.host + "/v1/"), []);

    return html`
        <section class="mt-5">
            <div class="container">
                <h1 class="title">Documentation</h1>
                <div class="card">
                    <header class="card-header">
                        <p class="card-header-title">API Access</p>
                    </header>
                    <div class="card-content">
                        <div class="content">
                            The API endpoint for version 1 of the API is available at <a href="${endpoint}">${endpoint}</a>. Please visit the <a href="swagger-index.html">Swagger UI</a> to view the API documentation.
                
                        </div>
                        <div class="content">
                            Use can use <a href="../client/dist/sdk.gen.js">this JS client</a> or the <a href="../client/dist/sdk.gen.mjs">module variant</a> to access the API.
            
                        </div>
                    </div>
                </div>

            </div>
        </section>
    `
}

function Main() {
    const { user, login } = useAuth()

    if (!user) {
        return html`
            <div class="container">
                <div class="box">Please <a onClick="${login}">log in</a> to access your data.</div>
            </div>
        `
    }

    return html`
        <div class="container">
            <${ListZones} />
            <${ListTokens} />
            <${Documentation} />
            <br/>
        </div>`
}

function App() {
    const { userManager, loading } = useUserManager()
    const [apiUrl, setApiUrl] = useState(null)

    useEffect(() => {
        const currentUrl = new URL(window.location.href);
        const normalizedApiUrl = new URL('../api/', currentUrl).toString();
        setApiUrl(normalizedApiUrl);
    }, []);

    if (loading || !apiUrl)
        return html`<p>Initializing app, please wait...</p>`;

    return html`
        <${AuthProvider} userManager=${userManager} loading=${loading}>
            <${AppConfigProvider} apiUrl=${apiUrl}>
                <${Header} title="Dynamic Zones DNS API" />
                <${Main} />
            <//>
        <//>
    `
}

render(
    html`<${App} name="Dynamic Zones DNS API" />`, document.getElementById('app')
)
