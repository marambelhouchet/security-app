import React from "react";
import logo from "../assets/wattnow-logo-1.png";
import "../styles/Navbar.css";

const Navbar = () => {
    return (
        <nav className="navbar">
            <div className="logo-container">
                <img src={logo} alt="Wattnow Logo" className="navbar-logo" />
            </div>
        </nav>
    );
};

export default Navbar;
