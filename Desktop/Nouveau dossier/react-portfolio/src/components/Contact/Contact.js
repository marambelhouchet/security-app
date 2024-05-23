import React, { useState } from 'react';

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faPhone, faEnvelope, faSquareCheck } from '@fortawesome/free-solid-svg-icons';
import { faLinkedin, faGithub } from '@fortawesome/free-brands-svg-icons';

import '../../styles/Contact/Contact.scss';

const Contact = () => {
    const [formData, setFormData] = useState({
        name: '',
        email: '',
        message: ''
    });

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        fetch('/database.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData),
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            console.log('Success:', data);
            // Clear form fields
            setFormData({
                name: '',
                email: '',
                message: ''
            });
            // Show success message
            alert('Your message has been sent successfully!');
        })
        .catch((error) => {
            console.error('Error:', error);
            // Handle error (e.g., show an error message)
            alert('An error occurred while sending your message. Please try again later.');
        });
    };
    
    

    return (
        <div className="contact" id='contact'>
            <div className="contact__header">
                <h1>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="0"
                        data-aos-offset="200"
                    >
                        C
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="200"
                        data-aos-offset="200"
                    >
                        O
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="400"
                        data-aos-offset="200"
                    >
                        N
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="600"
                        data-aos-offset="200"
                    >
                        T
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="800"
                        data-aos-offset="200"
                    >
                        A
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="1000"
                        data-aos-offset="200"
                    >
                        C
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="1200"
                        data-aos-offset="200"
                    >
                        T
                    </span>
                    <span
                        data-aos="fade-down"
                        data-aos-delay="1400"
                        data-aos-offset="200"
                    >
                        .
                    </span>
                </h1>
            </div>
            <div className="contact__container">
                <div className="contact__details">
                    <div className="contact__form" data-aos="fade-up">
                        <form name="contact" method="post" onSubmit={handleSubmit}>
                            <input type="hidden" name="form-name" value="contact" />
                            <p className="contact__form-group">
                                <label htmlFor="name">Name: </label>
                                <input
                                    type="text"
                                    name="name"
                                    autoComplete="off"
                                    placeholder="Enter name"
                                    value={formData.name}
                                    onChange={handleChange}
                                    required
                                />
                            </p>
                            <p className="contact__form-group">
                                <label htmlFor="email">Email: </label>
                                <input
                                    type="email"
                                    name="email"
                                    autoComplete="off"
                                    placeholder="Enter email"
                                    value={formData.email}
                                    onChange={handleChange}
                                    required
                                />
                            </p>
                            <p className="contact__form-group">
                                <label htmlFor="message">Concern: </label>
                                <textarea
                                    name="message"
                                    id="contact__message"
                                    cols="20"
                                    rows="5"
                                    placeholder="Type your message"
                                    value={formData.message}
                                    onChange={handleChange}
                                    required
                                ></textarea>
                            </p>
                            <button type="submit" className="contact__send-btn">Send</button>
                        </form>
                    </div>
                </div>
                <div className="contact__info" data-aos="fade-up">
                    <h3 className="contact__info-title">Let's Connect</h3>
                    <div className="contact__info-details">
                        <ul>
                            <li>
                                <FontAwesomeIcon icon={faPhone} size="2x" />
                                <p><span>Phone:</span>&nbsp;&nbsp;(+26) 94738768</p>
                            </li>
                            <li>
                                <FontAwesomeIcon icon={faEnvelope} size="2x" />
                                <p><span>Email:&nbsp;&nbsp;</span>marambelhouchet625@gmail.com</p>
                            </li>
                            <li>
                                <FontAwesomeIcon icon={faSquareCheck} size="2x" />
                                <span>FREELANCE</span>
                            </li>
                        </ul>
                    </div>
                    <div className="contact__social">
                        <p className="contact__linkedin">
                            <a href="https://www.linkedin.com/in/maram-belhouchet-4a9b5a252/"><FontAwesomeIcon icon={faLinkedin} size="2x" /></a>
                        </p>
                        <p className='contact__github'>
                            <a href="https://github.com/marambelhouchet" rel="noopener noreferrer" target="_blank"><FontAwesomeIcon icon={faGithub} size="2x" /></a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Contact;
