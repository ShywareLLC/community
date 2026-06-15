/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    {
      type: 'category',
      label: 'Protocol',
      collapsed: false,
      items: ['introduction', 'quickstart', 'architecture', 'cli', 'sdk/web/shyconfig'],
    },
    {
      type: 'category',
      label: 'Mobile SDKs',
      collapsed: false,
      items: [
        {
          type: 'category',
          label: 'iOS',
          items: ['sdk/ios/overview', 'sdk/ios/attestation', 'sdk/ios/distribution'],
        },
        {
          type: 'category',
          label: 'Android',
          items: ['sdk/android/overview', 'sdk/android/attestation'],
        },
        {
          type: 'category',
          label: 'Server API',
          items: [
            'api/voting',
            'api/wire',
            'api/custody',
            'api/financing',
            'api/store',
            'api/chat',
            'api/shares',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'Web SDK',
      items: [
        'sdk/web/overview',
        'sdk/web/adapters',       // interfaces first — the infrastructure layer
        'sdk/web/compositions',   // how clients compose — before the client pages
        'sdk/web/count-match',
        'sdk/web/sealer',
        'sdk/web/utility',
        'sdk/web/protocol',
        'sdk/web/identity',
        'sdk/web/zkp',
        'sdk/web/migration',
      ],
    },

    {
      type: 'category',
      label: 'Operations',
      items: [
        'deployments/infrastructure',
        'deployments/posture-dashboard',
        'deployments/fabric-ccaas',
      ],
    },
  ],
};

module.exports = sidebars;
