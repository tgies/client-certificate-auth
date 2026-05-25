import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'client-certificate-auth',
  description: 'mTLS client certificate authentication for Node.js',
  base: '/client-certificate-auth/',
  srcExclude: ['**/plans/**', '**/superpowers/**'],

  transformHead({ assets }) {
    const preloads = [
      /AtkinsonHyperlegibleNext-VariableFont_wght\.[\w-]+\.woff2$/,
      /AtkinsonHyperlegibleMono-VariableFont_wght\.[\w-]+\.woff2$/,
    ]
    return preloads.flatMap((re) => {
      const href = assets.find((file) => re.test(file))
      return href
        ? [['link', { rel: 'preload', href, as: 'font', type: 'font/woff2', crossorigin: '' }] as const]
        : []
    })
  },

  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API Reference', link: '/api/' },
      { text: 'Examples', link: '/examples/e2e-mtls' },
      { text: 'Support', link: '/support' },
    ],

    sidebar: [
      {
        text: 'Guide',
        items: [
          { text: 'Getting Started', link: '/guide/getting-started' },
          { text: 'Reverse Proxy Support', link: '/guide/reverse-proxy' },
          { text: 'AWS Lambda', link: '/guide/lambda' },
          { text: 'Fetch / Web Request', link: '/guide/fetch' },
          { text: 'WebSocket Support', link: '/guide/websocket' },
          { text: 'Authorization Helpers', link: '/guide/helpers' },
          { text: 'TypeScript & CJS', link: '/guide/typescript' },
          { text: 'Troubleshooting', link: '/guide/troubleshooting' },
        ],
      },
      {
        text: 'API Reference',
        link: '/api/',
        items: [
          { text: 'clientCertificateAuth', link: '/api/clientCertificateAuth/' },
          { text: 'helpers', link: '/api/helpers/' },
          { text: 'parsers', link: '/api/parsers/' },
          { text: 'extractor', link: '/api/extractor/' },
          { text: 'fetch', link: '/api/fetch/' },
          { text: 'lambda', link: '/api/lambda/' },
        ],
      },
      {
        text: 'Examples',
        items: [
          { text: 'End-to-End mTLS Demo', link: '/examples/e2e-mtls' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/tgies/client-certificate-auth' },
    ],

    editLink: {
      pattern: 'https://github.com/tgies/client-certificate-auth/edit/master/docs/:path',
    },

    search: {
      provider: 'local',
    },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2013-2026 Tony Gies',
    },
  },
})
