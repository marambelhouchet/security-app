import React, { useState, useEffect, useRef } from "react";
import UploadBox from "./UploadBox";
import SubmitButton from "./SubmitButton";
import AddTypeModal from "./AddTypeModal";
import "../styles/FormSection.css";

function FormSection() {
  const [language, setLanguage] = useState("en-GB");
  const [emails, setEmails] = useState([]);
  const [newEmail, setNewEmail] = useState("");
  const [model, setModel] = useState("Qwen 2.5 (3B)");
  const [file, setFile] = useState(null);
  const [errors, setErrors] = useState({ email: "", file: "" });
  const [shake, setShake] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuccess, setIsSuccess] = useState(false);
  const [isAddTypeModalOpen, setIsAddTypeModalOpen] = useState(false);
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

    setIsLoading(true);
    setIsSuccess(false);

    const formData = new FormData();
    formData.append("file", file);
    // Join emails with commas but only if there are any
    if (emails.length > 0) {
        formData.append("emails", emails.join(','));
    }
    formData.append("model", model);
    formData.append("language", language.split('-')[0]);

    try {
        const response = await fetch("http://localhost:5004/chat", {
            method: "POST",
            body: formData,
        });

        const data = await response.json();
        
        if (response.ok) {
            setIsSuccess(true);
            console.log("Emails sent to:", emails.join(', '));
            // Reset form after success
            setFile(null);
            setEmails([]);
            setTimeout(() => {
                setIsSuccess(false);
            }, 8000);
        } else {
            throw new Error(data.error || "Request failed");
        }
    } catch (error) {
        console.error("Error:", error);
        setShake(true);
    } finally {
        setIsLoading(false);
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

  const handleAddTypeSuccess = () => {
    // Handle successful type addition if needed
    setIsAddTypeModalOpen(false);
  };

  return (
    <>
      <button
        className="add-type-button"
        onClick={() => setIsAddTypeModalOpen(true)}
        title="Add New Type"
      >
        +
      </button>

      <AddTypeModal
        isOpen={isAddTypeModalOpen}
        onClose={() => setIsAddTypeModalOpen(false)}
        onSave={handleAddTypeSuccess}
      />

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
          isLoading={isLoading}
          success={isSuccess}
          onClick={handleSubmit}
          buttonRef={buttonRef}
        />
      </div>
    </>
  );
}

export default FormSection;
