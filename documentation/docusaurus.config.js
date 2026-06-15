// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'shyware',
  tagline: 'structurally anonymous, authority-reconcilable distributed-ledger protocol',
  favicon: 'img/favicon.svg',
  url: 'https://docs.shyware.fyi',
  baseUrl: '/',
  organizationName: 'NickCarducci',
  projectName: 'Populist-Backend',
  onBrokenLinks: 'warn',
  markdown: { hooks: { onBrokenMarkdownLinks: 'warn' } },
  customFields: {
    docsPassphrase: process.env.DOCS_PASSPHRASE || '',
  },
  i18n: { defaultLocale: 'en', locales: ['en'] },
  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          routeBasePath: '/',
          sidebarPath: require.resolve('./sidebars.js'),
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],
  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      colorMode: {
        defaultMode: 'dark',
        disableSwitch: false,
        respectPrefersColorScheme: true,
      },
      navbar: {
        title: 'shyware',
        logo: { alt: 'shyware logo', src: 'img/logo-light.svg', srcDark: 'img/logo-dark.svg' },
        items: [
          { type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs' },
          { type: 'html', position: 'left',  value: '<a href="https://contribute.shyware.fyi/introduction/" class="navbar__item navbar__link">Go internals</a>' },
          { type: 'html', position: 'right', value: '<a href="https://shyware.fyi" class="navbar__item navbar__link">shyware.fyi</a>' },
          { type: 'html', position: 'right', value: '<a href="https://shyware.fyi" class="navbar__item navbar__link">shyware.fyi</a>' },
          { href: '/contact', label: 'Contact', position: 'right' },
        ],
      },
      footer: {
        style: 'dark',
        copyright: `© ${new Date().getFullYear()} Shyware LLC · Patent Pending, App. No. 64/074,348`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['go', 'bash', 'json', 'kotlin', 'swift'],
      },
    }),
};

module.exports = config;
// 2026-05-12T12:33:28Z

