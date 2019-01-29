/* eslint-env node, jest */

import * as utils from '../EncryptionUtils';

const sessions = [
  {
    recipientId: 'erika',
    deviceIds: '1,5,6'
  },
  {
    recipientId: 'isabel',
    deviceIds: '3,4,5'
  }
];

const blacklistedKnownDevices = [
  {
    name: 'erika',
    devices: [1, 5]
  }
];

describe('Methods to encrypt emails', () => {
  it('Should create object recipientId with its deviceIds', () => {
    const knownAddresses = utils.createObjectRecipientIdByDevices(sessions);
    expect(knownAddresses).toMatchObject(
      expect.objectContaining({
        erika: [1, 5, 6],
        isabel: [3, 4, 5]
      })
    );
  });

  it('Should filter knownAddresses by blacklist', () => {
    const knownAddresses = utils.createObjectRecipientIdByDevices(sessions);
    const {
      knownAddressesFiltered,
      sessionIdentifiersToDelete
    } = utils.filterRecipientsByBlacklisted(
      blacklistedKnownDevices,
      knownAddresses
    );
    expect(knownAddressesFiltered).toMatchObject(
      expect.objectContaining({
        erika: [6],
        isabel: [3, 4, 5]
      })
    );
    expect(sessionIdentifiersToDelete).toEqual(['erika.1', 'erika.5']);
  });
});
