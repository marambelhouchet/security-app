import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import ReCAPTCHA from "react-google-recaptcha";
import './Signin.css';

const Signin = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [recaptchaToken, setRecaptchaToken] = useState("");
  const navigate = useNavigate();

  const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
  const passwordRegex = /^(?=.*[A-Z]).{8,}$/;

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");
    setMessage("");

    if (!emailRegex.test(email)) {
      setError("Please enter a valid email address.");
      return;
    }

    if (!passwordRegex.test(password)) {
      setError("Password must be at least 8 characters long and contain at least one uppercase letter.");
      return;
    }

    const userData = { email, password, recaptchaToken };
    console.log("Sending data to the backend:", userData);

    try {
      const response = await fetch("http://localhost:3000/signin", {  // Updated URL to match backend route
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(userData),
      });

      // Log response status and body
      const responseBody = await response.text(); // Read the body as text first for logging
      console.log("Response status:", response.status);
      console.log("Response body:", responseBody);

      if (response.ok) {
        const data = JSON.parse(responseBody); // Then parse the JSON after logging
        console.log("Response data:", data);
        localStorage.setItem("userId", data.user.id); // Store userId in localStorage
        setMessage("Login successful!");
        navigate("/home");
      } else {
        const data = JSON.parse(responseBody); // Handle error if response is not ok
        setError(data.message || "Something went wrong! Please try again.");
      }
    } catch (err) {
      console.error("Error during signin:", err);
      setError("Network error. Please try again.");
    }
  };

  return (
    <div className="signin-container">
      <div className="signin-form">
        <h2>Sign In</h2>
        <form onSubmit={handleSubmit}>
          <label>Email:</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
          <label>Password:</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <ReCAPTCHA 
            sitekey={process.env.REACT_APP_SITE_KEY} 
            onChange={(token) => setRecaptchaToken(token)} 
          />
          <button type="submit">Sign In</button>
        </form>
        {message && <p className="success-message">{message}</p>}
        {error && <p className="error-message">{error}</p>}
        <p>Don't have an account? <Link to="/signup">Sign Up</Link></p>
      </div>
      <div className="signin-image-container">
        <img 
          src="https://cdn-icons-png.flaticon.com/512/10826/10826975.png" 
          alt="Signin Illustration" 
        />
      </div>
    </div>
  );
};

export default Signin;
