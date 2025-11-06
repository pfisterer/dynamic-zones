import { render, html, Router, Route, Switch, Link, useHashLocation } from './dist/deps.mjs';
import { useAuth, AuthProvider } from './ui-context-auth.js';
import { AppConfigProvider } from './ui-context-appconfig.js';
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
                    <${Link}  className=${(active) => (active ? "has-text-danger" : "")} href="/">Home</$Link>
                </div>
                <div class="navbar-item">
                    <${Link} className=${(active) => (active ? "has-text-danger" : "")} href="/tokens">API Tokens</$Link>
                </div>

                <div class="navbar-item">
                    <${Link} className=${(active) => (active ? "has-text-danger" : "")} href="/documentation">Documentation</$Link>
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
    const header = html`<${Header} title="Dynamic Zones DNS Management UI" />`

    if (!user) {
        return html`
            ${header}
            <div class="container">
                <div class="box">Please <a onClick="${login}">log in</a> to access your data.</div>
            </div>
        `
    }

    return html`
        <${Router} hook=${useHashLocation}>
            ${header}   
            <${Switch}>
                <${Route} path="/" component=${ListZones} />
                <${Route} path="/tokens" component=${ListTokens} />
                <${Route} path="/documentation" component=${Documentation} />
                <${Route} component=${NotFound} />
            <//>
        <//>
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
