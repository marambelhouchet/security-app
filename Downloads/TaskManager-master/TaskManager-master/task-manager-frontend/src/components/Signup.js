import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import './Signup.css';
import emailjs from 'emailjs-com';  // Import EmailJS

const Signup = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setMessage('');

    const userData = { name, email, password };

    try {
      const response = await fetch('http://localhost:3000/api/signup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData),
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        sendConfirmationEmail(name, email);  // Send confirmation email
        setName('');
        setEmail('');
        setPassword('');
      } else {
        setError(data.message || 'Signup failed. Please try again.');
      }
    } catch (error) {
      setError('Network error. Please try again.');
    }
  };

  // Function to send confirmation email using EmailJS
  const sendConfirmationEmail = (name, email) => {
    const templateParams = {
      to_name: name,
      to_email: email,
      message: `Hello ${name},\n\nThank you for signing up! We're excited to have you on board.`,
    };

    emailjs
      .send(
        process.env.REACT_APP_EMAILJS_SERVICE_ID, 
        process.env.REACT_APP_EMAILJS_TEMPLATE_ID, 
        templateParams, 
        process.env.REACT_APP_EMAILJS_PUBLIC_KEY
      )
      .then(
        (response) => {
          console.log('Email sent successfully:', response);
        },
        (error) => {
          console.error('Error sending email:', error);
        }
      );
  };

  return (
    <div className="signup-container">
      <div className="signup-form">
        <h2>Sign Up</h2>
        <form onSubmit={handleSubmit}>
          <div>
            <label>Name:</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div>
            <label>Email:</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <label>Password:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button type="submit">Register</button>
        </form>
        {message && <p className="success-message">{message}</p>}
        {error && <p className="error-message">{error}</p>}
        <p>
          Already have an account? <Link to="/signin">Sign In</Link>
        </p>
      </div>
      <div className="signin-image-container">
        <img 
          src="data:image/jpeg;base64,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" 
          alt="Signin Illustration" 
        />
        </div>
    </div>
  );
};

export default Signup;
