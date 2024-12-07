import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import Signin from "./components/Signin";  // Relative import
import Signup from "./components/Signup";  // Relative import
import Home from "./components/Home";     // Relative import

function App() {
  return (
    <Router>
      <Routes>
        {/* Default route, it will show Signin when you enter the app */}
        <Route path="/" element={<Signin />} />

        {/* Other routes */}
        <Route path="/signup" element={<Signup />} />
        <Route path="/home" element={<Home />} />

        {/* Optionally, you can use a 404 page */}
        <Route path="*" element={<h1>404 Not Found</h1>} />
      </Routes>
    </Router>
  );
}

export default App;
