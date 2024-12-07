import React, { useEffect, useState } from "react";
import './user.css';
import { useNavigate } from "react-router-dom"; // Import useNavigate

const UserProfile = () => {
  const [user, setUser] = useState(null);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState("");
  const [updatedUserData, setUpdatedUserData] = useState({
    name: "",
    email: "",
    password: "",
  });

  const [editField, setEditField] = useState(""); // Track which field is being edited
  const navigate = useNavigate(); // Hook for navigation

  useEffect(() => {
    const fetchUserInfo = async () => {
      const userId = localStorage.getItem("userId");

      if (!userId) {
        setError("User not logged in.");
        return;
      }

      try {
        console.log(`Fetching user data for userId: ${userId}`);
        const response = await fetch(`http://localhost:3000/api/users?userId=${userId}`);
        
        if (!response.ok) {
          const data = await response.json();
          setError(data.message || "Error fetching user data.");
          return;
        }

        const data = await response.json();
        setUser(data.user); // Set the user data to the state
        setUpdatedUserData({
          name: data.user.name,
          email: data.user.email,
          password: "", // Password should remain empty initially
        });
        console.log("User data fetched:", data.user);
      } catch (err) {
        setError("Network error. Please try again.");
        console.log("Network error while fetching data:", err);
      }
    };

    fetchUserInfo();
  }, []);

  // Handle changes to the input fields
  const handleChange = (e) => {
    const { name, value } = e.target;
    setUpdatedUserData((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  // Handle form submission for updating user data
  const handleSubmit = async (e, field) => {
    e.preventDefault();
    const userId = localStorage.getItem("userId");

    if (!userId) {
      setError("User not logged in.");
      return;
    }

    const { name, email, password } = updatedUserData;
    let dataToUpdate = {};
    if (field === "name") {
      dataToUpdate = { userId, name };
    } else if (field === "email") {
      dataToUpdate = { userId, email };
    } else if (field === "password") {
      dataToUpdate = { userId, password };
    }

    try {
      const response = await fetch(`http://localhost:3000/api/users`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(dataToUpdate),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error("Error response text:", errorText);
        throw new Error("Error updating profile.");
      }

      const data = await response.json();
      setSuccessMessage(`${field.charAt(0).toUpperCase() + field.slice(1)} updated successfully!`);
      setUser(data.user); // Update user data in state
      setEditField(""); // Exit edit mode after successful update
    } catch (err) {
      setError("Network error. Please try again.");
      console.error("Network error during update:", err);
    }
  };

  // Toggle edit mode for each field
  const toggleEdit = (field) => {
    setEditField(field);
  };

  // Handle logout
  const handleLogout = () => {
    localStorage.removeItem("userId"); // Clear user ID
    navigate("/signin"); // Redirect to the sign-in page
  };

  return (
    <div className="user-profile">
      {error && <p className="error-message">{error}</p>}
      {successMessage && <p className="success-message">{successMessage}</p>}

      {user ? (
        <div>
          <h2>User Profile</h2>

          {/* Name */}
          <div>
            <label>Name:</label>
            {editField === "name" ? (
              <div>
                <input
                  type="text"
                  name="name"
                  value={updatedUserData.name}
                  onChange={handleChange}
                />
                <button onClick={(e) => handleSubmit(e, "name")}>Save</button>
              </div>
            ) : (
              <div>
                <p>{user.name}</p>
                <button onClick={() => toggleEdit("name")}>Change</button>
              </div>
            )}
          </div>

          {/* Email */}
          <div>
            <label>Email:</label>
            {editField === "email" ? (
              <div>
                <input
                  type="email"
                  name="email"
                  value={updatedUserData.email}
                  onChange={handleChange}
                />
                <button onClick={(e) => handleSubmit(e, "email")}>Save</button>
              </div>
            ) : (
              <div>
                <p>{user.email}</p>
                <button onClick={() => toggleEdit("email")}>Change</button>
              </div>
            )}
          </div>

          {/* Password */}
          <div>
            <label>Password:</label>
            {editField === "password" ? (
              <div>
                <input
                  type="password"
                  name="password"
                  value={updatedUserData.password}
                  onChange={handleChange}
                />
                <button onClick={(e) => handleSubmit(e, "password")}>Save</button>
              </div>
            ) : (
              <div>
                <p>********</p>
                <button onClick={() => toggleEdit("password")}>Change</button>
              </div>
            )}
          </div>

          <div className="user-image-container">
            <img 
              src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRhZDkXKCHEW2spAaD4TxJ_1msNi25IEKfZbd6iHmPJrZClZNa59KHGTfJVRuUVOuE58us&usqp=CAU"
              alt="user Illustration" 
            />
          </div>

          {/* Logout Button */}
          <button className="logout-button" onClick={handleLogout}>
            Logout
          </button>
        </div>
      ) : (
        <p>Loading user data...</p>
      )}
    </div>
  );
};

export default UserProfile;
