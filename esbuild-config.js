import esbuild from 'esbuild';

esbuild.build({
    entryPoints: [
        './web-ui/dependencies.js'
    ],
    bundle: true,
    outfile: './web-ui/dist/deps.mjs',
    format: 'esm',
    sourcemap: true,
    minify: true,
    alias: {
        'react': 'preact/compat',
        'react-dom': 'preact/compat',
        'react-dom/test-utils': 'preact/test-utils',
        'react/jsx-runtime': 'preact/jsx-runtime'
    },
}).catch(() => process.exit(1));