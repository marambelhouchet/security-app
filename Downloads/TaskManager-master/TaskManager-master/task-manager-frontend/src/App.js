import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Signup from './components/Signup';  
import Signin from './components/Signin';  
import Home from './components/Home';      
import UserPage from './components/UserPage'; 
import Stats from './components/stats'; 
const App = () => {
  return (
    <Router>
      <Routes>
        <Route path="/signup" element={<Signup />} />
        <Route path="/signin" element={<Signin />} />
        <Route path="/home" element={<Home />} /> 
        <Route path="/user" element={<UserPage />} /> 
        <Route path="/stats" element={<Stats />} />
      </Routes>
    </Router>
  );
};

export default App;
