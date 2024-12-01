# Security App

## Project Overview:
This project is focused on developing a secure web platform using Flask and Python. The goal is to provide a solution where users can securely log in, interact with one another, and protect their data through advanced encryption techniques. The platform integrates state-of-the-art security features that ensure a secure environment for all users.

---

## Key Features

### 1. Authentication and User Management:
- **Login with CAPTCHA:** A CAPTCHA system integrated into the login process to prevent automated bot attacks.  
- **Secure Signup:** Allows users to create accounts, with proper validation for their data to ensure secure registration.  
- **Role Management:** The platform supports two user roles: `admin` and `user`.  
   - **Admins** have special permissions, such as:
     - Adding and removing users.
     - Assigning roles (admin or user).
     - Sending messages to users.
     - Viewing activity logs (audit).

### 2. Customizable User Interface:
- The platform provides a role-specific interface, with admins and users accessing distinct sections tailored to their needs, making the workflow both secure and intuitive.

### 3. Encryption Functionality:
- **AES (Advanced Encryption Standard):** A highly secure symmetric encryption algorithm that ensures data protection.  
- **Image Encryption:** Images are encrypted to protect sensitive visual content.  
- **Matrix Encryption:** A custom-developed encryption method for securing various types of data.  
- **Caesar Cipher:** A classic encryption technique used to demonstrate basic cryptographic principles.  
- **Message Encryption with KEK and DEK:** Ensures secure messaging by using Key Encryption Keys (KEK) and Data Encryption Keys (DEK).  
   - Users must authenticate themselves with their password to decrypt and view messages.

### 4. Secure Messaging:
- Users can send encrypted messages to each other. All messages are encrypted end-to-end and can only be decrypted by the intended recipient after they authenticate with their password.

### 5. Key Vault:
- **Secret Management:** Sensitive information like encryption keys is securely stored in a Key Vault.  
- Users can access secrets by providing the secret name and their password for decryption, ensuring that keys and sensitive data are kept secure.

### 6. Activity Logs and Auditing:
- **Admin Logs:** Admins have access to detailed activity logs, allowing them to monitor and audit the usage of the platform for transparency and enhanced security.

---

## Technical Summary  
The platform incorporates advanced cloud security principles to protect user data, including:  
- **Asymmetric and Symmetric Cryptography:** Both encryption methods are used to secure sensitive information and communication.  
- **Identity Management:** Secure authentication mechanisms are in place to ensure that users' identities are properly validated.  
- **Secret Management:** Encryption keys and other sensitive data are stored securely in a Key Vault.  
- **Audit Logs:** Admins can track platform activity through logs to ensure security and compliance.

