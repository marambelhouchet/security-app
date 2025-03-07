import React, { useState } from "react";
import {
  TextField,
  Button,
  Box,
  Typography,
  Paper,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
} from "@mui/material";

const Chatbot = () => {
  const metrics = [
    { label: "ROUGE", value: "rouge" },
    { label: "BART", value: "bartscore" },
    { label: "BERT", value: "bertscore" },
    { label: "BLEURT", value: "bleurt" },
    { label: "COMET", value: "comet" },
    { label: "FactCC", value: "factcc" },
  ];

  const models = [
    { label: "Qwen 2.5 3B", value: "qwen2.5:3b" },
    { label: "Deepseek 1.5B", value: "deepseek-r1:1.5b" },
    { label: "Llama 3 1B", value: "llama3.2:1b" },
    { label: "Mistral", value: "mistral:latest" },
  ];

  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [file, setFile] = useState(null);
  const [selectedMetric, setSelectedMetric] = useState("rouge");
  const [selectedModel, setSelectedModel] = useState("qwen2.5:3b");

  const handleSend = async () => {
    if (!input.trim() || !file) {
      setMessages(prev => [...prev, 
        { sender: "Bot", text: "Error: Both message and file are required" }
      ]);
      return;
    }

    const formData = new FormData();
    formData.append("message", input);
    formData.append("metric", selectedMetric);
    formData.append("model", selectedModel);
    formData.append("file", file);

    try {
      const response = await fetch("http://localhost:5000/evaluate", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (data.error) {
        setMessages((prev) => [
          ...prev,
          { sender: "Bot", text: `Error: ${data.error}` },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          { sender: "User", text: input },
          {
            sender: "Bot",
            text: `Model: ${data.model}\nGenerated Text: ${data.generated_text}\nMetric: ${data.metric}\nScore: ${JSON.stringify(data.score)}`,
          },
        ]);
      }
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        { sender: "Bot", text: "Error connecting to backend" },
      ]);
    }
    setInput("");
    setFile(null);
  };

  return (
    <Box sx={{ width: "60%", margin: "auto", textAlign: "center", mt: 5 }}>
      <Typography variant="h4" sx={{ mb: 2, color: "green", fontWeight: "bold" }}>
        WattNow - AI Assistant
      </Typography>
      
      <Paper
        sx={{
          height: 350,
          overflowY: "auto",
          p: 3,
          mb: 3,
          backgroundColor: "#f5f5f5",
          borderRadius: "8px",
        }}
      >
        {messages.map((msg, index) => (
          <Typography key={index} sx={{ color: msg.sender === "User" ? "blue" : "green", marginBottom: "12px" }}>
            <strong>{msg.sender}:</strong> {msg.text}
          </Typography>
        ))}
      </Paper>

      <Box sx={{ display: "flex", gap: 2, justifyContent: "center", mb: 2 }}>
        <FormControl sx={{ width: "180px" }} size="small">
          <InputLabel>Select Model</InputLabel>
          <Select 
            value={selectedModel} 
            onChange={(e) => setSelectedModel(e.target.value)}
            label="Select Model"
          >
            {models.map((model) => (
              <MenuItem key={model.value} value={model.value}>
                {model.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <FormControl sx={{ width: "180px" }} size="small">
          <InputLabel>Select Metric</InputLabel>
          <Select 
            value={selectedMetric} 
            onChange={(e) => setSelectedMetric(e.target.value)}
            label="Select Metric"
          >
            {metrics.map((metric) => (
              <MenuItem key={metric.value} value={metric.value}>
                {metric.label}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
      </Box>

      <TextField
        fullWidth
        variant="outlined"
        placeholder="Type your message..."
        value={input}
        onChange={(e) => setInput(e.target.value)}
        sx={{ mb: 2, backgroundColor: "#fff", borderRadius: "8px" }}
      />

      <input
        type="file"
        onChange={(e) => setFile(e.target.files[0])}
        accept=".txt,.text,.csv,.json"
        style={{ display: "none" }}
        id="file-upload"
      />
      <label htmlFor="file-upload">
        <Button 
          variant="outlined" 
          color="secondary" 
          component="span" 
          sx={{ mb: 2, borderRadius: "20px", padding: "10px 20px" }}
        >
          {file ? file.name : "Upload File (.txt, .csv, .json)"}
        </Button>
      </label>

      <Button
        variant="contained"
        color="success"
        onClick={handleSend}
        sx={{ borderRadius: "20px", padding: "12px 20px", fontWeight: "bold" }}
      >
        Send
      </Button>
    </Box>
  );
};

export default Chatbot;