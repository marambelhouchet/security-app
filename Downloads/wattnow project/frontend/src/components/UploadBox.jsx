import React from "react";
import "../styles/UploadBox.css";

function UploadBox({ file, setFile }) {
  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setFile(e.dataTransfer.files[0]);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  return (
    <div className="upload-box" onDrop={handleDrop} onDragOver={handleDragOver}>
      <div className="upload-icon">📄</div>
      <p className="upload-subtext">Drag and drop or browse files</p>

      <input type="file" id="fileInput" className="hidden-input" onChange={handleFileChange} />
      <label htmlFor="fileInput" className="upload-button">Browse</label>

      {file && <p className="file-name">{file.name}</p>}
    </div>
  );
}

export default UploadBox;
