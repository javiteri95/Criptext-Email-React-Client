import React, { Component } from 'react';
import SignIn from './SignIn';
import SignUpWrapper from './SignUpWrapper';
import SignInPasswordWrapper from './SignInPasswordWrapper';
import SignInToApprove from './SignInToApprove';
import ChangePasswordWrapper from './ChangePasswordWrapper';
import PopupHOC from './PopupHOC';
import LoginPopup from './LoginPopup';
import DialogPopup, { DialogTypes } from './DialogPopup';
import {
  createTemporalAccount,
  deleteTemporalAccount,
  socketClient,
  confirmWaitingApprovalLogin
} from './../utils/electronInterface';
import {
  canLogin,
  checkAvailableUsername,
  closeLoginWindow,
  getComputerName,
  linkAuth,
  linkBegin,
  linkStatus,
  openCreateKeysLoadingWindow,
  throwError,
  getAccountByParams
} from '../utils/ipc.js';
import { validateEmail, validateUsername } from './../validators/validators';
import { DEVICE_TYPE, appDomain } from '../utils/const';
import DeviceNotApproved from './DeviceNotApproved';
import { hashPassword } from '../utils/HashUtils';
import string from './../lang';
import './panelwrapper.scss';

const { signIn, signUp } = string;

const mode = {
  SIGNUP: 'SIGNUP',
  SIGNIN: 'SIGNIN',
  SIGNINTOAPPROVE: 'SIGNINTOAPPROVE',
  SIGNINPASSWORD: 'SIGNINPASSWORD',
  CHANGEPASSWORD: 'CHANGEPASSWORD',
  DEVICE_NOT_APPROVED: 'DEVICE_NOT_APPROVED'
};

const errorMessages = {
  EMAILADDRESS_NOT_EXISTS: signIn.errorMessages.emailAddressNotExits,
  USERNAME_EMAILADDRESS_INVALID:
    signIn.errorMessages.usernameOrEmailAddressInvalid,
  USERNAME_INVALID: signIn.errorMessages.usernameInvalid,
  USERNAME_NOT_EXISTS: signIn.errorMessages.usernameNotExits,
  STATUS_UNKNOWN: signIn.errorMessages.statusUnknown,
  USERNAME_NOT_AVAILABLE: signIn.errorMessages.usernameNotAvailable
};

const LINK_STATUS_RETRIES = 12;
// eslint-disable-next-line fp/no-let
let LINK_STATUS_ATTEMPS = LINK_STATUS_RETRIES;
const LINK_STATUS_DELAY = 5000;
const rejectedDeviceStatus = 493;
const approvedDeviceStastus = 200;

const shouldDisableLogin = state =>
  !!state.errorMessage || state.values.usernameOrEmailAddress === '';

const LoginWithPasswordPopup = PopupHOC(DialogPopup);
const ResetPasswordPopup = PopupHOC(LoginPopup);
const NoRecoverySignUpPopup = PopupHOC(DialogPopup);
const SignInAnotherAccount = PopupHOC(DialogPopup);

const commitNewUser = validInputData => {
  openCreateKeysLoadingWindow({
    loadingType: 'signup',
    remoteData: validInputData
  });
  closeLoginWindow();
};

class PanelWrapper extends Component {
  constructor() {
    super();
    this.state = {
      currentStep: mode.SIGNIN,
      lastStep: [mode.SIGNIN],
      mode: mode.SIGNIN,
      values: {
        usernameOrEmailAddress: '',
        password: ''
      },
      disabledResendLoginRequest: false,
      errorMessage: '',
      ephemeralToken: undefined,
      hasTwoFactorAuth: undefined,
      popupContent: undefined,
      oldPassword: undefined
    };
  }

  render() {
    return (
      <div className="panel-wrapper">
        {this.renderPopup()}
        {this.renderHeader()}
        <section>{this.renderSection()}</section>
      </div>
    );
  }

  renderHeader = () => (
    <header className={this.defineHeaderClass()}>
      <div className="button-section">
        <button
          className="back-button"
          onClick={ev => this.onClickBackView(ev)}
        >
          <i className="icon-back" />
        </button>
      </div>
      <div className="criptext-logo">
        <div className="icon" />
      </div>
    </header>
  );

  renderPopup = () => {
    if (!this.state.popupContent) {
      return null;
    }
    switch (this.state.mode) {
      case mode.SIGNINTOAPPROVE:
        return (
          <LoginWithPasswordPopup
            {...this.state.popupContent}
            onCancelClick={this.handleStayLinking}
            onConfirmClick={this.handleCancelLink}
          />
        );
      case mode.SIGNINPASSWORD:
        return (
          <ResetPasswordPopup
            {...this.state.popupContent}
            onDismiss={this.dismissPopup}
          />
        );
      case mode.SIGNUP:
        return (
          <NoRecoverySignUpPopup
            {...this.state.popupContent}
            onCancelClick={this.dismissPopup}
            onConfirmClick={this.handleSignUpContinue}
          />
        );
      case mode.SIGNIN:
        return (
          <SignInAnotherAccount
            {...this.state.popupContent}
            type={DialogTypes.SIGN_ANOTHER_ACCOUNT}
            onCancelClick={this.dismissPopup}
            onConfirmClick={this.handleConfirmSignInAnotherAccount}
          />
        );
      default:
        return null;
    }
  };

  renderSection = () => {
    switch (this.state.mode) {
      case mode.SIGNUP:
        return (
          <SignUpWrapper
            checkAvailableUsername={checkAvailableUsername}
            onFormReady={this.onFormReady}
            onSubmitWithoutRecoveryEmail={this.onSubmitWithoutRecoveryEmail}
          />
        );
      case mode.SIGNINTOAPPROVE:
        return (
          <SignInToApprove
            onLeftButtonClick={this.handlePopupLeftButton}
            onRightButtonClick={this.handlePopupRightButton}
            popupContent={this.state.popupContent}
            disabledResendLoginRequest={this.state.disabledResendLoginRequest}
            onClickSignInWithPassword={this.handleClickSignInWithPassword}
            onClickResendLoginRequest={this.handleClickResendLoginRequest}
            hasTwoFactorAuth={this.state.hasTwoFactorAuth}
          />
        );
      case mode.DEVICE_NOT_APPROVED:
        return (
          <DeviceNotApproved
            onClickSignInWithPassword={this.handleClickSignInWithPassword}
            hasTwoFactorAuth={this.state.hasTwoFactorAuth}
          />
        );
      case mode.SIGNINPASSWORD:
        return (
          <SignInPasswordWrapper
            cleanState={this.cleanState}
            dismissPopup={this.dismissPopup}
            goToWaitingApproval={this.goToWaitingApproval}
            hasTwoFactorAuth={this.state.hasTwoFactorAuth}
            setPopupContent={this.setPopupContent}
            onGoToChangePassword={this.hangleGoToChangePassword}
            value={this.state.values.usernameOrEmailAddress}
          />
        );
      case mode.CHANGEPASSWORD:
        return (
          <ChangePasswordWrapper
            emailAddress={this.state.values.usernameOrEmailAddress}
            oldPassword={this.state.oldPassword}
            values={''}
          />
        );
      case mode.SIGNIN:
      default:
        return (
          <SignIn
            disabledLoginButton={shouldDisableLogin(this.state)}
            errorMessage={this.state.errorMessage}
            goToSignUp={this.goToSignUp}
            onClickSignIn={this.handleClickSignIn}
            onChangeField={this.handleChange}
            value={this.state.values.usernameOrEmailAddress}
          />
        );
    }
  };

  hangleGoToChangePassword = oldPassword => {
    this.setState(state => ({
      lastStep: state.lastStep.concat([mode.CHANGEPASSWORD]),
      currentStep: mode.CHANGEPASSWORD,
      mode: mode.CHANGEPASSWORD,
      oldPassword
    }));
  };

  onSubmitWithoutRecoveryEmail = validInputData => {
    const popUp = signUp.popUp.warningRecoveryEmail;
    this.setState({
      popupContent: {
        title: popUp.title,
        prefix: popUp.prefix,
        strong: popUp.strong,
        suffix: popUp.suffix,
        cancelButtonLabel: popUp.leftButtonLabel,
        confirmButtonLabel: popUp.rightButtonLabel,
        data: validInputData
      }
    });
  };

  onFormReady = validInputData => {
    if (validInputData.recoveryEmail === '')
      return this.onSubmitWithoutRecoveryEmail(validInputData);
    commitNewUser(validInputData);
  };

  handleSignUpContinue = () => {
    const inputData = this.state.popupContent.data;
    if (!inputData) {
      return;
    }
    this.setState(
      {
        popupContent: undefined
      },
      () => {
        commitNewUser(inputData);
      }
    );
  };

  handleConfirmSignInAnotherAccount = async () => {
    const nextMode = this.state.popupContent.successMode;
    this.dismissPopup();
    if (nextMode === mode.SIGNINTOAPPROVE) {
      await this.initLinkDevice(this.state.values.usernameOrEmailAddress);
      return;
    } else if (nextMode === mode.SIGNUP) {
      this.setState({
        lastStep: this.concat(this.state.lastStep, nextMode),
        currentStep: mode.SIGNUP,
        mode: mode.SIGNUP
      });
    }
  };

  onClickBackView = ev => {
    ev.preventDefault();
    ev.stopPropagation();
    if (this.state.currentStep === mode.SIGNINTOAPPROVE) {
      socketClient.disconnect();
      this.stopCountdown();
    }
    const tmplastStep = [...this.state.lastStep];
    const popStep = tmplastStep.pop();
    const checkStep = tmplastStep[tmplastStep.length - 1];
    if (
      (popStep === mode.SIGNINPASSWORD && checkStep === mode.SIGNINTOAPPROVE) ||
      (popStep === mode.SIGNINTOAPPROVE && checkStep === mode.SIGNINPASSWORD) ||
      popStep === mode.DEVICE_NOT_APPROVED
    ) {
      tmplastStep.pop();
      const checkOtherStep = tmplastStep[tmplastStep.length - 1];
      if (checkOtherStep === mode.SIGNINPASSWORD) tmplastStep.pop();
    }
    const lastStep = tmplastStep;
    const currentStep = tmplastStep[tmplastStep.length - 1];
    this.setState(
      {
        lastStep,
        currentStep,
        mode: currentStep
      },
      this.cleanState
    );
  };

  stopCountdown = () => {
    clearTimeout(this.linkStatusTimeout);
  };

  handleCanLoginResponse = emailAddress => ({ status }) => {
    this.setState(state => {
      if (state.values.usernameOrEmailAddress !== emailAddress) return state;
      if (state.errorMessage) return state;

      switch (status) {
        case 200:
          return { errorMessage: '' };

        case 400:
          return {
            errorMessage: errorMessages.EMAILADDRESS_NOT_EXISTS
          };
        default:
          return {
            errorMessage: errorMessages.STATUS_UNKNOWN + status
          };
      }
    });
  };

  handleCheckUsernameResponse = username => ({ status }) => {
    this.setState(state => {
      if (state.values.usernameOrEmailAddress !== username) return state;
      if (state.errorMessage) return state;

      switch (status) {
        case 200:
          return {
            errorMessage: errorMessages.USERNAME_NOT_EXISTS
          };
        case 422:
          return {
            errorMessage: errorMessages.USERNAME_INVALID
          };
        case 400:
          return { errorMessage: '' };
        case 410: {
          return {
            errorMessage: errorMessages.USERNAME_NOT_AVAILABLE
          };
        }
        default:
          return {
            errorMessage: errorMessages.STATUS_UNKNOWN + status
          };
      }
    });
  };

  handleChange = event => {
    const usernameOrEmailAddress = event.target.value;
    if (!usernameOrEmailAddress) {
      return this.setState({
        values: {
          ...this.state.values,
          usernameOrEmailAddress: usernameOrEmailAddress
        },
        errorMessage: ''
      });
    }
    const isUsernameValid = validateUsername(usernameOrEmailAddress);
    const isEmailAddressValid = validateEmail(usernameOrEmailAddress);
    if (!isUsernameValid && !isEmailAddressValid) {
      return this.setState({
        values: {
          ...this.state.values,
          usernameOrEmailAddress: usernameOrEmailAddress
        },
        errorMessage: errorMessages.USERNAME_EMAILADDRESS_INVALID
      });
    }
    if (this.lastCheck) clearTimeout(this.lastCheck);

    this.lastCheck = setTimeout(() => {
      if (this.state.values.usernameOrEmailAddress !== usernameOrEmailAddress)
        return;

      if (isUsernameValid) {
        checkAvailableUsername(usernameOrEmailAddress).then(
          this.handleCheckUsernameResponse(usernameOrEmailAddress)
        );
      } else if (isEmailAddressValid) {
        const [username, domain] = usernameOrEmailAddress.split('@');
        canLogin({ username, domain }).then(
          this.handleCanLoginResponse(usernameOrEmailAddress)
        );
      }
    }, 300);

    this.setState({
      values: {
        ...this.state.values,
        usernameOrEmailAddress: usernameOrEmailAddress
      },
      errorMessage: ''
    });
  };

  handleClickSignIn = async ev => {
    ev.preventDefault();
    ev.stopPropagation();
    const { usernameOrEmailAddress } = this.state.values;
    const [recipientId] = usernameOrEmailAddress.includes(`@${appDomain}`)
      ? usernameOrEmailAddress.split('@')
      : [usernameOrEmailAddress];
    const [existsAccount] = await getAccountByParams({
      recipientId
    });
    if (!existsAccount) {
      const successMode = mode.SIGNINTOAPPROVE;
      const check = await this.checkLoggedOutAccounts(successMode);
      if (check === true) {
        await this.initLinkDevice(recipientId);
      }
    } else {
      await this.initLinkDevice(recipientId);
    }
  };

  checkLoggedOutAccounts = async successMode => {
    const loggedOutAccounts = await getAccountByParams({ deviceId: '' });
    if (!loggedOutAccounts.length) return true;

    this.setState({
      mode: mode.SIGNIN,
      popupContent: {
        title: signIn.loginNewAccount.title,
        prefix: signIn.loginNewAccount.prefix,
        list: this.formLoggedOutAccountsList(loggedOutAccounts),
        suffix: signIn.loginNewAccount.suffix,
        cancelButtonLabel: signIn.loginNewAccount.cancelButtonLabel,
        confirmButtonLabel: signIn.loginNewAccount.confirmButtonLabel,
        successMode
      }
    });
    return false;
  };

  formLoggedOutAccountsList = loggedOutAccounts => {
    return loggedOutAccounts.map(account =>
      this.defineEmailAddress(account.recipientId)
    );
  };

  defineEmailAddress = usernameOrEmailAddress => {
    return usernameOrEmailAddress.includes('@')
      ? usernameOrEmailAddress
      : `${usernameOrEmailAddress}@${appDomain}`;
  };

  goToPasswordLogin = () => {
    this.setState(state => ({
      lastStep: this.concat(state.lastStep, mode.SIGNINPASSWORD),
      currentStep: mode.SIGNINPASSWORD,
      mode: mode.SIGNINPASSWORD
    }));
  };

  goToSignUp = async e => {
    e.preventDefault();
    e.stopPropagation();
    const successMode = mode.SIGNUP;
    const check = await this.checkLoggedOutAccounts(successMode);
    if (check === true) {
      this.setState(state => ({
        lastStep: this.concat(state.lastStep, mode.SIGNUP),
        currentStep: mode.SIGNUP,
        mode: mode.SIGNUP
      }));
    }
  };

  goToWaitingApproval = password => {
    this.setState(
      state => ({
        lastStep: this.concat(state.lastStep, mode.SIGNINTOAPPROVE),
        currentStep: mode.SIGNINTOAPPROVE,
        mode: mode.SIGNINTOAPPROVE,
        values: { ...state.values, password }
      }),
      () => {
        this.initLinkDevice(this.state.values.usernameOrEmailAddress);
      }
    );
  };

  obtainEphemeralToken = async ({ username, domain }) => {
    const { status, text } = await linkBegin({ username, domain });
    if (status === 439) {
      throwError(string.errors.tooManyDevices);
    } else if (status === 400) {
      this.goToPasswordLogin();
    } else if (status === 404) {
      this.setState(state => ({
        values: {
          usernameOrEmailAddress: state.values.usernameOrEmailAddress,
          password: ''
        },
        disabledResendLoginRequest: false,
        errorMessage: errorMessages.USERNAME_NOT_AVAILABLE,
        ephemeralToken: undefined,
        hasTwoFactorAuth: undefined
      }));
    } else if (status === 200) {
      const { twoFactorAuth, token } = JSON.parse(text);
      this.setState({
        ephemeralToken: token,
        hasTwoFactorAuth: !!twoFactorAuth
      });
    }
  };

  initLinkDevice = async usernameOrEmailAddress => {
    const [username, domain = appDomain] = usernameOrEmailAddress.split('@');
    if (!this.state.ephemeralToken) {
      await this.obtainEphemeralToken({
        username,
        domain
      });
    }
    if (this.state.hasTwoFactorAuth && !this.state.values.password) {
      this.goToPasswordLogin();
    } else if (this.state.ephemeralToken) {
      const response = await this.sendLoginConfirmationRequest(
        this.state.ephemeralToken
      );
      if (response) {
        this.setState(
          state => ({
            lastStep: this.concat(state.lastStep, mode.SIGNINTOAPPROVE),
            currentStep: mode.SIGNINTOAPPROVE,
            mode: mode.SIGNINTOAPPROVE
          }),
          () => {
            const recipientId =
              domain === appDomain ? username : usernameOrEmailAddress;
            createTemporalAccount({ recipientId });
            socketClient.start({ jwt: this.state.ephemeralToken });
            this.checkLinkStatus();
          }
        );
      } else {
        this.goToPasswordLogin();
      }
    }
  };

  concat = (array, item) => {
    const popItem = array[array.length - 1];
    if (popItem === item) return array;
    return array.concat([item]);
  };

  sendLoginConfirmationRequest = async ephemeralToken => {
    const [
      recipientId,
      domain
    ] = this.state.values.usernameOrEmailAddress.split('@');
    const pcName = await getComputerName();
    const newDeviceData = {
      recipientId,
      domain: domain || appDomain,
      deviceName: pcName || window.navigator.platform,
      deviceFriendlyName: pcName || window.navigator.platform,
      deviceType: DEVICE_TYPE
    };
    if (this.state.hasTwoFactorAuth) {
      // eslint-disable-next-line fp/no-mutation
      newDeviceData.password = hashPassword(this.state.values.password);
    }
    try {
      const { status } = await linkAuth({
        newDeviceData,
        jwt: ephemeralToken
      });
      return status === 200;
    } catch (e) {
      return false;
    }
  };

  handleClickSignInWithPassword = ev => {
    ev.preventDefault();
    ev.stopPropagation();
    this.stopCountdown();
    this.setState({
      popupContent: {
        title: signIn.usePassword.title,
        prefix: signIn.usePassword.prefix,
        strong: signIn.usePassword.strong,
        suffix: signIn.usePassword.suffix,
        cancelButtonLabel: signIn.usePassword.leftButtonLabel,
        confirmButtonLabel: signIn.usePassword.rightButtonLabel
      }
    });
  };

  setPopupContent = popupContent => {
    this.setState({ popupContent });
  };

  dismissPopup = () => {
    this.setState({ popupContent: undefined });
  };

  handleStayLinking = () => {
    this.setState({ popupContent: undefined }, () => {
      this.checkLinkStatus();
    });
  };

  handleCancelLink = () => {
    socketClient.disconnect();
    this.setState(state => ({
      lastStep: this.concat(state.lastStep, mode.SIGNINPASSWORD),
      currentStep: mode.SIGNINPASSWORD,
      mode: mode.SIGNINPASSWORD,
      popupContent: undefined
    }));
  };

  handleClickResendLoginRequest = ev => {
    ev.preventDefault();
    ev.stopPropagation();
    this.setState({ disabledResendLoginRequest: true }, async () => {
      this.stopCountdown();
      const response = await this.sendLoginConfirmationRequest(
        this.state.ephemeralToken
      );
      if (response) {
        this.checkLinkStatus();
        setTimeout(() => {
          this.setState({ disabledResendLoginRequest: false });
        }, 2000);
      }
    });
  };

  checkLinkStatus = async () => {
    if (LINK_STATUS_ATTEMPS === 0) {
      this.stopCountdown();
      confirmWaitingApprovalLogin(shouldKeepWaiting => {
        if (shouldKeepWaiting) {
          // eslint-disable-next-line fp/no-mutation
          LINK_STATUS_ATTEMPS = LINK_STATUS_RETRIES;
          this.checkLinkStatus();
        } else {
          this.setState({ mode: mode.SIGNIN }, () => {
            this.cleanState();
            // eslint-disable-next-line fp/no-mutation
            LINK_STATUS_ATTEMPS = LINK_STATUS_RETRIES;
          });
        }
      });
    } else {
      const { status, body } = await linkStatus();
      switch (status) {
        case rejectedDeviceStatus: {
          this.stopCountdown();
          socketClient.disconnect();
          this.setState(state => ({
            lastStep: this.concat(state.lastStep, mode.DEVICE_NOT_APPROVED),
            currentStep: mode.DEVICE_NOT_APPROVED,
            mode: mode.DEVICE_NOT_APPROVED
          }));
          return;
        }
        case approvedDeviceStastus: {
          this.stopCountdown();
          socketClient.disconnect();
          const remoteData = {
            ...body,
            recipientId: this.state.values.usernameOrEmailAddress
          };
          openCreateKeysLoadingWindow({
            loadingType: 'link-new-device',
            remoteData
          });
          deleteTemporalAccount();
          closeLoginWindow();
          return;
        }
        default: {
          this.linkStatusTimeout = await setTimeout(
            this.checkLinkStatus,
            LINK_STATUS_DELAY
          );
          // eslint-disable-next-line fp/no-mutation
          LINK_STATUS_ATTEMPS--;
        }
      }
    }
  };

  cleanState = () => {
    this.setState({
      values: {
        usernameOrEmailAddress: '',
        password: ''
      },
      disabledResendLoginRequest: false,
      errorMessage: '',
      ephemeralToken: undefined,
      hasTwoFactorAuth: undefined
    });
  };

  defineHeaderClass = () => {
    return this.state.lastStep[this.state.lastStep.length - 1] === mode.SIGNIN
      ? 'invisible'
      : 'visible';
  };
}

export default PanelWrapper;