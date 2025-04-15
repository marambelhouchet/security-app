import React, { useState, useEffect, useRef } from "react";
import UploadBox from "./UploadBox";
import SubmitButton from "./SubmitButton";
import "../styles/FormSection.css";

function FormSection() {
  const [language, setLanguage] = useState("en-GB");
  const [emails, setEmails] = useState([]);
  const [newEmail, setNewEmail] = useState("");
  const [model, setModel] = useState("Qwen 2.5 (3B)");
  const [file, setFile] = useState(null);
  const [errors, setErrors] = useState({ email: "", file: "" });
  const [shake, setShake] = useState(false);
  const buttonRef = useRef(null);

  const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const addEmail = () => {
    const email = newEmail.trim();
    if (validateEmail(email)) {
      setEmails([...emails, email]);
      setNewEmail("");
      setErrors({ ...errors, email: "" });
    } else {
      setErrors({ ...errors, email: "Invalid email format" });
    }
  };

  const removeEmail = (emailToRemove) => {
    setEmails(emails.filter((email) => email !== emailToRemove));
  };

  const validate = () => {
    const newErrors = { email: "", file: "" };
    let isValid = true;

    if (!file) {
      newErrors.file = "File is required";
      isValid = false;
    }

    if (emails.some(email => !validateEmail(email))) {
      newErrors.email = "Invalid email(s) detected";
      isValid = false;
    }

    setErrors(newErrors);
    setShake(!isValid);
    return isValid;
  };

  const handleSubmit = async () => {
    if (!validate()) return;

    const formData = new FormData();
    formData.append("file", file);
    formData.append("emails", emails.join(','));
    formData.append("model", model);
    formData.append("language", language.split('-')[0]);

    try {
      const response = await fetch("http://localhost:5004/chat", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      
      if (response.ok) {
        const responseText = data.response || "No response content";
        let alertMessage = `Success! Response: ${responseText}`;
        if (emails.length > 0) {
          alertMessage += `\nEmails sent to: ${emails.join(', ')}`;
        }
        if (data.warning) {
          alertMessage += `\nWarning: ${data.warning}`;
        }
        alert(alertMessage);
      } else {
        alert(`Error: ${data.error || "Request failed"}`);
      }
    } catch (error) {
      alert("Failed to connect to server");
    }
  };

  useEffect(() => {
    const button = buttonRef.current;
    const handleAnimationEnd = () => {
      setShake(false);
    };

    if (shake && button) {
      button.addEventListener("animationend", handleAnimationEnd);
    }

    return () => {
      if (button) {
        button.removeEventListener("animationend", handleAnimationEnd);
      }
    };
  }, [shake]);

  return (
    <div className="form-section">
      {/* Language selection */}
      <div className="form-group">
        <label><b>Language</b></label>
        <select value={language} onChange={(e) => setLanguage(e.target.value)}>
          <option value="en-GB">English 🇬🇧</option>
          <option value="fr-FR">French 🇫🇷</option>
          <option value="ar-AR">Arabic 🇸🇦</option>
        </select>
      </div>

      {/* Email input */}
      <div className="form-group">
        <label><b>Emails for response copy</b></label>
        <div className="email-tags">
          {emails.map((email, index) => (
            <span key={index} className="email-tag">
              {email}
              <button type="button" onClick={() => removeEmail(email)}>×</button>
            </span>
          ))}
        </div>
        <div className="email-input-container">
          <input
            type="email"
            placeholder="you@example.com"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addEmail()}
            className={errors.email ? "error" : ""}
          />
          <button type="button" onClick={addEmail}>Add Email</button>
        </div>
        {errors.email && <p className="error-message">{errors.email}</p>}
      </div>

      {/* Model selection */}
      <div className="form-group">
        <label><b>Model</b></label>
        <select value={model} onChange={(e) => setModel(e.target.value)}>
          <option>Qwen 2.5 (3B)</option>
          <option>qwen2-math (7B)</option>
          <option>qwen2-math(1.5B)</option>
          <option>mistral(7B)</option>
          <option>deepseek-r1(1.5B)</option>
          <option>llama3.2(1B)</option>
        </select>
      </div>

      <UploadBox file={file} setFile={setFile} error={errors.file} />
      {errors.file && <p className="error-message">{errors.file}</p>}

      <SubmitButton
        file={file}
        email={emails}
        model={model}
        language={language}
        shake={shake}
        onClick={handleSubmit}
        buttonRef={buttonRef}
      />
    </div>
  );
}

export default FormSection;
