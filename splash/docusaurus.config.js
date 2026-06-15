// @ts-check
const { themes: prismThemes } = require('prism-react-renderer');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'shyware',
  tagline: 'anonymous by design. auditable by law.',
  favicon: 'img/favicon.svg',
  url: 'https://shyware.fyi',
  baseUrl: '/',
  organizationName: 'NickCarducci',
  projectName: 'Populist-Backend',
  onBrokenLinks: 'warn',
  i18n: { defaultLocale: 'en', locales: ['en'] },
  presets: [
    [
      'classic',
      ({
        docs: false,
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
      title: 'shyware',
      logo: { alt: 'shyware logo', src: 'img/logo-light.svg', srcDark: 'img/logo-dark.svg' },
      items: [
        { type: 'html', position: 'left',  value: '<a href="https://docs.shyware.fyi/introduction/" class="navbar__item navbar__link">Docs</a>' },
        { type: 'html', position: 'left',  value: '<a href="https://contribute.shyware.fyi/introduction/" class="navbar__item navbar__link">Contribute</a>' },
        { type: 'html', position: 'right', value: '<a href="mailto:inquiries@shyware.fyi" class="navbar__item navbar__link">Contact</a>' },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          items: [
            { label: 'Docs', href: 'https://docs.shyware.fyi/introduction/' },
            { label: 'Legal', href: 'https://shyware.fyi/legal/' },
            { label: 'Privacy', href: 'https://shyware.fyi/legal/privacy/' },
          ],
        },
        {
          items: [
            { label: 'inquiries@shyware.fyi', href: 'mailto:inquiries@shyware.fyi' },
          ],
        },
      ],
      copyright: `© ${new Date().getFullYear()} Shyware LLC · Patent Pending, App. No. 64/074,348`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
    },
  }),
};

config.customFields = {
  docsPassphrase: process.env.DOCS_PASSPHRASE || '',
};

module.exports = config;
