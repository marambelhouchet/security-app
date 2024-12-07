import React, { useEffect, useState } from "react";
import { Pie } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";

// Registering chart.js components
ChartJS.register(ArcElement, Title, Tooltip, Legend);

const StatsDashboard = () => {
  const [projectsPerDay, setProjectsPerDay] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchProjectsPerDay = async () => {
      try {
        const response = await fetch("http://localhost:3000/stats");

        if (!response.ok) {
          throw new Error("Failed to fetch projects per day.");
        }

        const data = await response.json();
        console.log("Projects Per Day Data:", data);

        setProjectsPerDay(data);
      } catch (err) {
        console.error("Error fetching projects per day:", err);
        setError("Error fetching projects per day. Please try again later.");
      }
    };

    fetchProjectsPerDay();
  }, []);

  if (error) return <p style={{ color: "red" }}>{error}</p>;
  if (!projectsPerDay.length) return <p>Loading stats...</p>;

  // Prepare data for the pie chart
  const pieChartData = {
    labels: projectsPerDay.map((item) => item.day),
    datasets: [
      {
        label: "Projects Per Day",
        data: projectsPerDay.map((item) => item.project_count),
        backgroundColor: [
          "#FF6384", // Red
          "#36A2EB", // Blue
          "#FFCE56", // Yellow
          "#4BC0C0", // Teal
          "#9966FF", // Purple
          "#FF9F40", // Orange
          "#C9CBCF", // Grey
        ],
        hoverBackgroundColor: [
          "#FF6384",
          "#36A2EB",
          "#FFCE56",
          "#4BC0C0",
          "#9966FF",
          "#FF9F40",
          "#C9CBCF",
        ],
      },
    ],
  };

  return (
    <div style={{ maxWidth: "800px", margin: "20px auto" }}>
      <h2>Projects Per Day Dashboard</h2>

      <div
        style={{
          backgroundColor: "#fff",
          padding: "20px",
          borderRadius: "10px",
          boxShadow: "0 4px 8px rgba(0, 0, 0, 0.1)",
          margin: "20px 0",
        }}
      >
        <h3>Projects Per Day</h3>
        <Pie data={pieChartData} />
      </div>
    </div>
  );
};

export default StatsDashboard;
