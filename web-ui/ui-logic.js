import { render, html, Router, Route, Switch, Link, useHashLocation, useLocation, useEffect } from './dist/deps.mjs';
import { useAuth, AuthProvider } from './ui-context-auth.js';
import { AppConfigProvider, useAppConfig } from './ui-context-appconfig.js';
import { ListTokens } from './ui-component-tokens.js';
import { ListZones } from './ui-component-zones.js';
import { Documentation } from './ui-component-documentation.js';


function LoginLogoutButton() {
    const { user, login, logout } = useAuth()

    if (user) {
        return html`Welcome ${user.profile.name}! <button class="button" onClick=${logout}>Logout</button>`
    } else {
        return html`<button class="button" onClick=${login}>Login</button>`
    }
}

function Header(props) {
    const [currentPath] = useLocation();
    const getLinkClass = (href) => { return (currentPath.startsWith(href)) ? "has-text-danger" : ""; };

    return html`
        <nav class="navbar is-fixed-top" role="navigation" class="has-background-white-bis has-text-primary-invert" hoverable="false">
                <div class="navbar-brand">
                <a class="navbar-item" href="#">
                    <img src="img/DHBW-Logo.svg" style="height: 2em;" />
                </a>

                <div class="navbar-item">
                    ${props.title}
                </div>

                <div class="navbar-item">
                    <${Link} className=${getLinkClass("/zones")} href="/zones">Home<//>
                </div>
                <div class="navbar-item">
                    <${Link} className=${active => active ? "has-text-danger" : ""} href="/tokens">API Tokens<//>
                </div>

                <div class="navbar-item">
                    <${Link} className=${active => active ? "has-text-danger" : ""} href="/documentation">Documentation<//>
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

function Main() {
    const { user, login } = useAuth()
    const { appConfig } = useAppConfig()

    const appVersion = appConfig?.version || "unknown"
    const title = appConfig ? html`<b>Dynamic Zones</b> (${appVersion})` : "Loading application..."
    const header = html`<${Header} title=${title} version=${appVersion} />`

    if (!appConfig)
        return header

    if (!user) {
        return html`
            ${header}
            <div class="container">
                <div class="box">Please <a onClick="${login}">log in</a> to access your data.</div>
            </div>
        `
    }

    function Redirect({ to }) {
        const [_, navigate] = useLocation();
        useEffect(() => {
            navigate(to, { replace: true });
        }, [to]);
        return null;
    }


    return html`
        <${Router} hook=${useHashLocation}>
            ${header}   
            <${Switch}>
                <${Route} path="/">
                    ${html`<${Redirect} to="/zones" />`}
                <//>
                <${Route} path="/zones" component=${ListZones} nest/>
                <${Route} path="/tokens" component=${ListTokens} />
                <${Route} path="/documentation" component=${Documentation} />
                <${Route} component=${NotFound} />
            <//>
        <//>
        <div class="mb-6"></div>
        `
}

function NotFound() {
    return html`
        <div class="container">
            <div class="box">404: Page not found</div>
        </div>
    `
}

function App() {
    return html`
        <${AppConfigProvider}>
            <${AuthProvider}>
                <${Main} />
            <//>
        <//>
    `
}

render(
    html`<${App} name="Dynamic Zones DNS API" />`, document.getElementById('app')
)
