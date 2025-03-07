import React, { useState } from "react";
import { TextField, Button, Box, Typography, Paper } from "@mui/material";

const Chatbot = () => {
  const [messages, setMessages] = useState([]); // Chat history
  const [input, setInput] = useState(""); // User input
  const [file, setFile] = useState(null); 

  const handleSend = async () => {
    if (input.trim() === "" && !file) return; // Ensure user message or file is present

    setMessages([...messages, { sender: "User", text: input }]);
    setInput("");

    let formData = new FormData();
    formData.append("message", input);
    if (file) {
      formData.append("file", file);
    }
    try {
      const response = await fetch("http://localhost:5004/chat", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();

      if (response.ok) {
        setMessages((prev) => [
          ...prev,
          { sender: "Bot", text: data.response },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          { sender: "Bot", text: `Error: ${data.error}` },
        ]);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        { sender: "Bot", text: "Error connecting to backend" },
      ]);
    }
  };

  const handleFileChange = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile) {
      setFile(uploadedFile);
    }
  };

  return (
    <Box sx={{ width: "60%", margin: "auto", textAlign: "center", mt: 5 }}>
      <Typography variant="h4" sx={{ mb: 2, color: "green", fontWeight: "bold" }}>
        WattNow - AI Assistant
      </Typography>

      {/* Chat Display */}
      <Paper
        sx={{
          height: 350,
          overflowY: "auto",
          p: 3,
          mb: 3,
          backgroundColor: "#f5f5f5",
          borderRadius: "8px",
          boxShadow: "0 2px 5px rgba(0, 0, 0, 0.1)",
          textAlign: "left",
        }}
      >
        {messages.map((msg, index) => (
          <Typography
            key={index}
            sx={{
              color: msg.sender === "User" ? "blue" : "green",
              marginBottom: "12px",
            }}
          >
            <strong>{msg.sender}:</strong> {msg.text}
          </Typography>
        ))}
      </Paper>

      {/* User Input */}
      <TextField
        fullWidth
        variant="outlined"
        placeholder="Type your message..."
        value={input}
        onChange={(e) => setInput(e.target.value)}
        sx={{
          mb: 2,
          backgroundColor: "#fff",
          borderRadius: "8px",
          boxShadow: "0 2px 5px rgba(0, 0, 0, 0.1)",
        }}
      />

      {/* File Upload */}
      <input
        type="file"
        onChange={handleFileChange}
        accept=".json, .csv, .xlsx, .xls"
        style={{ display: "none" }}
        id="file-upload"
      />
      <label htmlFor="file-upload">
        <Button
          variant="outlined"
          color="secondary"
          component="span"
          sx={{
            mb: 2,
            borderRadius: "20px",
            padding: "10px 20px",
            "&:hover": {
              backgroundColor: "#f1f1f1",
            },
          }}
        >
          Upload File
        </Button>
      </label>

      <Button
        variant="contained"
        color="success"
        onClick={handleSend}
        sx={{
          borderRadius: "20px",
          padding: "12px 20px",
          fontWeight: "bold",
          "&:hover": {
            backgroundColor: "green",
          },
        }}
      >
        Send
      </Button>
    </Box>
  );
};

export default Chatbot;
