import React, { useState } from 'react';
import '../styles/FormSection.css';

const AddTypeModal = ({ isOpen, onClose, onSave }) => {
  const [typeName, setTypeName] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [language, setLanguage] = useState('en');
  const [error, setError] = useState('');

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file && file.type === 'text/plain') {
      setSelectedFile(file);
      setError('');
    } else {
      setError('Please upload a .txt file');
    }
  };

  const handleSubmit = async () => {
    if (!typeName || !selectedFile) {
        setError('Please fill all fields');
        return;
    }

    const formData = new FormData();
    formData.append('typeName', typeName);
    formData.append('file', selectedFile);
    formData.append('language', language);

    try {
        const response = await fetch('http://localhost:5004/add-type', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Accept': 'application/json'
                // Remove Content-Type header - it will be set automatically for FormData
            },
            body: formData,
        });

        if (response.ok) {
            const data = await response.json();
            console.log('Success:', data);
            onSave();
            onClose();
        } else {
            const errorData = await response.json();
            setError(errorData.error || 'Error saving new type');
        }
    } catch (error) {
        console.error('Error:', error);
        setError('Network error while saving new type');
    }
  };

  if (!isOpen) return null;

  return (
    <>
      <div className="modal-overlay" onClick={onClose} />
      <div className="add-type-modal">
        <h2>Add New Alert Type</h2>
        
        <div className="form-group">
          <label>Type Name</label>
          <input
            type="text"
            value={typeName}
            onChange={(e) => setTypeName(e.target.value)}
            placeholder="Enter type name"
          />
        </div>

        <div className="form-group">
          <label>Language</label>
          <select value={language} onChange={(e) => setLanguage(e.target.value)}>
            <option value="en">English</option>
            <option value="fr">French</option>
          </select>
        </div>

        <div className="type-upload-container" onClick={() => document.getElementById('fileInput').click()}>
          <input
            id="fileInput"
            type="file"
            accept=".txt"
            onChange={handleFileChange}
            style={{ display: 'none' }}
          />
          {selectedFile ? (
            <div>{selectedFile.name}</div>
          ) : (
            <div>Click to upload prompt file (.txt)</div>
          )}
        </div>

        {error && <p className="error-message">{error}</p>}

        <div className="modal-actions">
          <button className="cancel" onClick={onClose}>Cancel</button>
          <button className="save" onClick={handleSubmit}>Save</button>
        </div>
      </div>
    </>
  );
};

export default AddTypeModal;