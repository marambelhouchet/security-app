import React from "react";
import "../styles/SubmitButton.css";

function SubmitButton({ shake, onClick, isLoading, success }) {
  return (
    <button
      className={`submit-button ${shake ? "shake" : ""} ${isLoading ? "loading" : ""} ${success ? "success" : ""}`}
      onClick={onClick}
      disabled={isLoading || success}
    >
      <div className="button-content">
        {isLoading ? (
          <>
            <div className="spinner"></div>
            <span>Sending mail...</span>
          </>
        ) : success ? (
          <div className="success-content">
            <span role="img" aria-label="mail" className="success-icon">✉️</span>
            <span>Mail sent! Check your inbox</span>
          </div>
        ) : (
          <span>Process</span>
        )}
      </div>
    </button>
  );
}

export default SubmitButton;
