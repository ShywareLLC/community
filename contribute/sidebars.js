/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  contribute: [
    {
      type: 'doc',
      id: 'introduction',
      label: 'Protocol overview',
    },
    {
      type: 'doc',
      id: 'architecture',
      label: 'Architecture',
    },
    {
      type: 'category',
      label: 'Voting / governance',
      collapsed: false,
      items: [
        'sdk/state',
        'sdk/tx',
        'sdk/types',
        'sdk/signer',
        'sdk/verify',
        'sdk/zkp',
      ],
    },
    {
      type: 'category',
      label: 'Wire / transfer',
      items: ['sdk/wire-state', 'sdk/wire-tx', 'sdk/wire-types'],
    },
    {
      type: 'category',
      label: 'Store',
      items: ['sdk/store-state', 'sdk/store-tx', 'sdk/store-types'],
    },
    {
      type: 'category',
      label: 'Chat',
      items: ['sdk/chat-state', 'sdk/chat-tx'],
    },
    {
      type: 'category',
      label: 'Shares',
      items: ['sdk/shares-state', 'sdk/shares-tx', 'sdk/shares-types'],
    },
    {
      type: 'category',
      label: 'Protocol layer',
      items: ['sdk/protocol-config', 'sdk/protocol-submission', 'sdk/rpc'],
    },
    {
      type: 'category',
      label: 'Services',
      items: ['sdk/services'],
    },
  ],
};

module.exports = sidebars;
