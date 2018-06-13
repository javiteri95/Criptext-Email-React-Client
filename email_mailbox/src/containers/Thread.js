import { connect } from 'react-redux';
import {
  loadEmails,
  updateUnreadEmails,
  updateUnreadThread,
  removeThreadLabel
} from '../actions';
import ThreadView from '../components/Thread';
import { List, Map } from 'immutable';
import { LabelType } from '../utils/electronInterface';

const emailsMapToList = (emailsMap, emailIds) => {
  const result =
    emailsMap.size === 0 || !emailIds
      ? List()
      : emailIds.map(emailId => {
          return emailsMap.get(emailId.toString()) || Map();
        });
  return result;
};

const getEmails = (emails, thread) => {
  const emailIds = thread ? thread.get('emailIds') : null;
  return emailsMapToList(emails, emailIds);
};

const getThread = (threads, threadId) => {
  return threads.find(thread => {
    return thread.get('id') === threadId;
  });
};

const getThreadFromSuggestions = (suggestions, threadId) => {
  return suggestions.get('threads').find(thread => {
    return thread.get('id') === threadId;
  });
};

const defineLabels = (labels, labelIds) => {
  const labelIdsFiltered = labelIds.filter(
    labelId => labelId !== LabelType.sent.id
  );
  const result = labelIdsFiltered.toArray().map(labelId => {
    return labels.get(labelId.toString()).toObject();
  });

  return result ? result : [];
};

const createReadableThread = thread => {
  const subject = thread.get('subject');
  return thread
    .set('subject', subject.length === 0 ? '(No Subject)' : subject)
    .toJS();
};

const mapStateToProps = (state, ownProps) => {
  const thread =
    getThread(state.get('threads'), ownProps.threadIdSelected) ||
    getThreadFromSuggestions(
      state.get('suggestions'),
      ownProps.threadIdSelected
    );
  const emails = getEmails(state.get('emails'), thread);
  const labelIds =
    LabelType[ownProps.mailboxSelected].id === LabelType.inbox.id
      ? thread.get('allLabels')
      : thread.get('labels');
  const labels = defineLabels(state.get('labels'), labelIds);
  const threadReadable = createReadableThread(thread);
  return {
    emails,
    labels,
    thread: threadReadable
  };
};

const mapDispatchToProps = (dispatch, ownProps) => {
  return {
    onLoadEmails: threadId => {
      return dispatch(loadEmails(threadId));
    },
    onRemoveThreadLabel: (threadIdDB, labelId) => {
      const threadParams = {
        threadIdStore: ownProps.threadIdSelected,
        threadIdDB
      };
      return dispatch(removeThreadLabel(threadParams, labelId));
    },
    onUpdateUnreadEmails: (thread, unread) => {
      const paramsThread = {
        id: thread.threadId,
        unread
      };
      const labelId = LabelType[ownProps.mailboxSelected].id;
      const paramsLabel =
        labelId === LabelType.inbox.id || labelId === LabelType.spam.id
          ? {
              id: labelId,
              badgeOperation: -1
            }
          : null;

      dispatch(updateUnreadEmails(paramsThread, paramsLabel));
    },
    onUpdateUnreadThread: (thread, unread) => {
      const params = {
        id: thread.id,
        unread
      };
      dispatch(updateUnreadThread(params));
    }
  };
};

const Thread = connect(mapStateToProps, mapDispatchToProps)(ThreadView);

export default Thread;
