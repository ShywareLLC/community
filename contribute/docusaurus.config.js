// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'shyware — contribute',
  tagline: 'Go internals, protocol implementation, and contributor reference',
  favicon: 'img/favicon.svg',
  url: 'https://contribute.shyware.fyi',
  baseUrl: '/',
  organizationName: 'NickCarducci',
  projectName: 'Populist-Backend',
  onBrokenLinks: 'warn',
  markdown: { hooks: { onBrokenMarkdownLinks: 'warn' } },
  i18n: { defaultLocale: 'en', locales: ['en'] },
  presets: [
    [
      'classic',
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
          path: 'docs',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],
  themeConfig: ({
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'shyware / contribute',
      items: [
        { type: 'docSidebar', sidebarId: 'contribute', position: 'left', label: 'Go internals' },
        { type: 'html', position: 'right', value: '<a href="https://docs.shyware.fyi/introduction/" class="navbar__item navbar__link">← Docs</a>' },
        { type: 'html', position: 'right', value: '<a href="https://shyware.fyi" class="navbar__item navbar__link">shyware.fyi</a>' },
      ],
    },
    footer: {
      style: 'dark',
      copyright: `© ${new Date().getFullYear()} Co-Mission`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['go', 'bash', 'json'],
    },
  }),
};

config.customFields = {
  docsPassphrase: process.env.DOCS_PASSPHRASE || '',
};

module.exports = config;
