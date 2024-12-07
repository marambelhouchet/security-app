import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import './HomePage.css';

function HomePage() {
  const [projects, setProjects] = useState([]);
  const [isLoggedIn, setIsLoggedIn] = useState(true);
  const [newProject, setNewProject] = useState({
    name: '',
    description: '',
    deadline: '',
    status: 'Not Started',
  });
  const [newTask, setNewTask] = useState({
    name: '',
    description: '',
    due_time: '',
    assigned_user: '',
    project_id: '',
  });
  const [showTaskForm, setShowTaskForm] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Fetch projects from API
  const fetchProjects = async () => {
    setLoading(true);
    try {
      const userId = localStorage.getItem('userId');
      if (!userId) {
        alert('User ID not found. Please log in again.');
        return;
      }

      const response = await fetch(`http://localhost:3000/api/projects?userId=${userId}`);
      if (!response.ok) {
        const errorData = await response.json();
        alert(`Failed to fetch projects: ${errorData.message}`);
        return;
      }

      const data = await response.json();
      setProjects(data.projects || []);
    } catch (error) {
      alert('Error fetching projects');
    } finally {
      setLoading(false);
    }
  };

  // Format deadline to show only the date (no time)
  const formatDeadline = (date) => {
    const deadlineDate = new Date(date);
    return deadlineDate.toLocaleDateString();  // Format to display only the date
  };

  // Add a new project
  const handleAddProject = async (event) => {
    event.preventDefault();

    if (newProject.name.length < 5 || newProject.description.length < 5) {
      alert('Project name and description must be at least 5 characters long.');
      return;
    }

    try {
      const userId = localStorage.getItem('userId');
      if (!userId) {
        alert('User ID not found. Please log in again.');
        return;
      }

      const response = await fetch('http://localhost:3000/api/projects', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId,
          projectName: newProject.name,
          projectDescription: newProject.description,
          deadline: newProject.deadline,
          status: newProject.status,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        alert(`Error creating project: ${data.message}`);
        return;
      }

      const data = await response.json();
      setProjects((prevProjects) => [...prevProjects, data.project]);
      setNewProject({ name: '', description: '', deadline: '', status: 'Not Started' });
      setShowForm(false); // Close the form after adding the project
    } catch (error) {
      alert('There was an error adding the project.');
    }
  };

  // Add a task to a specific project
  const handleAddTask = async (projectId, event) => {
    event.preventDefault();

    if (!newTask.name || newTask.name.length < 5) {
      alert('Task name is required and must be at least 5 characters long.');
      return;
    }

    if (!newTask.description || newTask.description.length < 5) {
      alert('Task description is required and must be at least 5 characters long.');
      return;
    }

    if (!newTask.due_time) {
      alert('Due time is required.');
      return;
    }

    const userId = localStorage.getItem('userId');
    if (!userId) {
      alert('User not logged in.');
      return;
    }

    const taskWithProjectId = {
      ...newTask,
      project_id: projectId,
      user_id: userId,
    };

    try {
      const response = await fetch('http://localhost:3000/api/tasks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(taskWithProjectId),
      });

      if (!response.ok) {
        const data = await response.json();
        alert(`Error creating task: ${data.message}`);
        return;
      }

      const data = await response.json();
      setProjects((prevProjects) =>
        prevProjects.map((project) =>
          project.id === projectId
            ? { ...project, tasks: [...(project.tasks || []), data.task] }
            : project
        )
      );
    } catch (error) {
      alert('There was an error creating the task.');
    }

    setNewTask({
      name: '',
      description: '',
      due_time: '',
      assigned_user: '',
      project_id: '',
    });
  };

  // Delete a project
  const deleteProject = async (projectId) => {
    const userId = localStorage.getItem('userId');
    if (!userId) {
      alert('User not logged in.');
      return;
    }

    try {
      const response = await fetch('http://localhost:3000/api/delprojects', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, projectId }),
      });

      if (!response.ok) {
        const data = await response.json();
        alert(`Error deleting project: ${data.message}`);
        return;
      }

      setProjects((prevProjects) => prevProjects.filter((project) => project.id !== projectId));
      alert('Project deleted successfully');
    } catch (error) {
      alert('Error deleting project');
    }
  };

  // Delete a task
  const deleteTask = async (taskId, projectId) => {
    const userId = localStorage.getItem('userId');
    if (!userId) {
      alert('User not logged in.');
      return;
    }

    try {
      const response = await fetch('http://localhost:3000/api/deltasks', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ userId, taskId }),
      });

      if (!response.ok) {
        alert('Failed to delete task');
        return;
      }

      setProjects((prevProjects) =>
        prevProjects.map((project) =>
          project.id === projectId
            ? { ...project, tasks: project.tasks.filter((task) => task.id !== taskId) }
            : project
        )
      );
    } catch (error) {
      alert('Failed to delete task');
    }
  };

  useEffect(() => {
    fetchProjects();
  }, []); // Fetch projects only once when the component mounts

  if (loading) {
    return <p>Loading projects...</p>;
  }

  return (
    <div>
      {isLoggedIn ? (
        <div>
          <button onClick={() => setShowForm(!showForm)} className="add-project-button">
            {showForm ? 'Cancel' : 'Add Project'}
          </button>

          <button className="change-info-button" onClick={() => navigate('/user')}>
            Change Info
          </button>
          <button className="stats-button" onClick={() => navigate('/stats')}>
  View Stats
</button>

          {showForm && (
            <div className="add-project-form">
              <h2>Add New Project</h2>
              <form onSubmit={handleAddProject}>
                <input
                  type="text"
                  placeholder="Project Name"
                  value={newProject.name}
                  onChange={(e) => setNewProject({ ...newProject, name: e.target.value })}
                />
                <textarea
                  placeholder="Project Description"
                  value={newProject.description}
                  onChange={(e) => setNewProject({ ...newProject, description: e.target.value })}
                />
                <input
                  type="date"
                  value={newProject.deadline}
                  onChange={(e) => setNewProject({ ...newProject, deadline: e.target.value })}
                />
                <button type="submit">Add Project</button>
              </form>
            </div>
          )}

          <div className="projects-container">
            <h2>Your Projects</h2>
            {projects.length > 0 ? (
              <div className="projects-list">
                {projects.map((project) => (
                  <div key={project.id} className="project-item">
                    <div className="project-title">{project.name}</div>
                    <p>{project.description}</p>
                    <p>Status: {project.status}</p>
                    <p>Deadline: {formatDeadline(project.deadline)}</p> {/* Display only the date */}
                    <div className="project-buttons">
                      <button onClick={() => deleteProject(project.id)}>Delete</button>
                      <button onClick={() => setShowTaskForm(project.id)}>Add Task</button>
                    </div>
                    {showTaskForm === project.id && (
                      <div>
                        <input
                          type="text"
                          placeholder="Task Name"
                          value={newTask.name}
                          onChange={(e) => setNewTask({ ...newTask, name: e.target.value })}
                        />
                        <textarea
                          placeholder="Task Description"
                          value={newTask.description}
                          onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
                        />
                        <input
                          type="datetime-local"
                          value={newTask.due_time}
                          onChange={(e) => setNewTask({ ...newTask, due_time: e.target.value })}
                        />
                        <button onClick={(e) => handleAddTask(project.id, e)}>Add Task</button>
                      </div>
                    )}
                    {/* Tasks */}
                    <div>
                      {project.tasks?.map((task) => (
                        <div key={task.id}>
                          <p>{task.name}</p>
                          <button onClick={() => deleteTask(task.id, project.id)}>Delete Task</button>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <p>No projects available</p>
            )}
          </div>
        </div>
      ) : (
        <p>You need to log in to view the projects.</p>
      )}
    </div>
  );
}

export default HomePage;
