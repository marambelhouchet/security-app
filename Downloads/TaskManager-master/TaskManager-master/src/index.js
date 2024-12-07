// src/index.js

import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';  // Make sure this line exists
import App from './App';
import reportWebVitals from './reportWebVitals';  // Import this line

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);

// Call the function to log web vitals
reportWebVitals();
