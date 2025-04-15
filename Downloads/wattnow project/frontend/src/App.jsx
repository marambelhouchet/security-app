import React from "react";
import Navbar from "./components/Navbar";
import FormSection from "./components/FormSection";
import "./index.css";
import image from "./assets/Group-15954-1.png"; // Update with the correct path

function App() {
  return (
    <div className="app">
      <Navbar />
      <div className="content-wrapper">
        <div className="form-title-container">
          <h1 className="title">⚡ Wattnow Energy Assistant</h1>
          <FormSection />
        </div>
        <div className="image-container">
          <img src={image} alt="Decorative" className="decorative-image" />
        </div>
      </div>
    </div>
  );
}

export default App;
