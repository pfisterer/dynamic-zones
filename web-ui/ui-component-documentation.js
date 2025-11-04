import { useAppConfig } from './ui-context-appconfig.js';
import { html, useState, useEffect } from './dist/deps.mjs';

export function Documentation() {
    const { apiUrl } = useAppConfig();

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
                            The API endpoint for version 1 of the API is available at <a href="${apiUrl}">${apiUrl}</a>. Please visit the <a href="swagger-index.html">Swagger UI</a> to view the API documentation.
                
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
