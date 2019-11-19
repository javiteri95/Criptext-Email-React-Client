import React from 'react';
import PropTypes from 'prop-types';
import string from './../lang';
import './devicenotapproved.scss';

const { deviceNotApproved } = string;

const DeviceNotApproved = props => (
  <div className="device-not-approved-container">{renderContent(props)}</div>
);

const renderContent = props => (
  <div className="device-not-approved-content">
    <div className="content-header">
      <h4>{deviceNotApproved.title}</h4>
    </div>
    <div className="content-message">
      <p>{deviceNotApproved.message}</p>
      <div className="content-icon">
        <div className="icon-warning" />
      </div>
      <p>
        <strong>{deviceNotApproved.warning.strong} </strong>
        &nbsp;
        {deviceNotApproved.warning.text}
      </p>
    </div>
    <div className="cant-access">
      {props.hasTwoFactorAuth ? (
        <span onClick={props.onClickUseRecoveryCode}>
          {deviceNotApproved.sendCodeLabel}
        </span>
      ) : (
        <span onClick={props.onClickSignInWithPassword}>
          {deviceNotApproved.passwordLoginLabel}
        </span>
      )}
    </div>
  </div>
);

renderContent.propTypes = {
  hasTwoFactorAuth: PropTypes.bool,
  onClickUseRecoveryCode: PropTypes.func,
  onClickSignInWithPassword: PropTypes.func
};

export default DeviceNotApproved;
