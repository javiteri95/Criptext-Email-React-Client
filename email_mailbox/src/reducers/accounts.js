import { Account, Activity } from '../actions/types';
import { fromJS } from 'immutable';
import { defineAccounts } from './../utils/AccountUtils';
import { myAccount } from './../utils/electronInterface';

const formAccounts = account => {
  const activeAccount = {
    id: account.activeAccount.id,
    badge: 0,
    isActive: account.activeAccount.isActive,
    name: account.activeAccount.name,
    recipientId: account.activeAccount.recipientId
  };
  const inactiveAccounts = account.inactiveAccounts
    ? Object.keys(account.inactiveAccounts).map(key => {
        const item = account.inactiveAccounts[key];
        return item;
      })
    : [];
  return [activeAccount, ...inactiveAccounts];
};

const initAccounts = account => fromJS(defineAccounts(formAccounts(account)));

const accounts = (state = initAccounts(myAccount), action) => {
  switch (action.type) {
    case Account.ADD_BATCH: {
      const accounts = fromJS(action.accounts);
      return state.merge(accounts);
    }
    case Activity.LOGOUT: {
      return initAccounts(myAccount);
    }
    case Account.UPDATE_ACCOUNTS: {
      const { accounts } = action;
      return accounts.reduce((result, item) => {
        const accountId = item.id;
        const accountItem = state.get(`${accountId}`);
        return state.set(
          `${accountId}`,
          account(accountItem, {
            account: item,
            type: action.type
          })
        );
      }, state);
    }
    default:
      return state;
  }
};

const account = (state, action) => {
  switch (action.type) {
    case Account.UPDATE_ACCOUNTS: {
      const { badge } = action.account;
      return state.merge({
        badge: badge || state.get('badge')
      });
    }
    default:
      return state;
  }
};

export default accounts;
