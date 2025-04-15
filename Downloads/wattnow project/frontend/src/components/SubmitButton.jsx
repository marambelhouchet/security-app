import React from "react";
import "../styles/SubmitButton.css";

function SubmitButton({ shake, onClick, isLoading, success }) {
  return (
    <button
      className={`submit-button ${shake ? "shake" : ""} ${success ? "success" : ""}`}
      onClick={onClick}
      disabled={isLoading}
    >
      {isLoading ? "Processing..." : success ? "✅ Sent!" : "Process"}
    </button>
  );
}

export default SubmitButton;
