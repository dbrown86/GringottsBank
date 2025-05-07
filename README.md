# Gringotts Wizarding Bank 🪄

A secure Flask web application simulating the wizarding bank from Harry Potter, where users can manage their magical currency (Galleons) and transfer them between accounts. This web app was designed for a Secure Software Development graduate course at Loyola Marymount University.

![Gringotts Bank Screenshot](static/img/gringotts.gif)

## 🔮 Features

- **Secure User Authentication**: Login system with proper password handling
- **Dashboard View**: See all your accounts and balances 
- **Account Details**: Detailed view of individual account balances
- **Secure Transfers**: Transfer Galleons between your accounts


## 🔒 Security Features

This application implements robust web security measures, such as:

- **CSRF Protection**: All forms are protected against Cross-Site Request Forgery
- **XSS Prevention**: Content Security Policy and HTML escaping prevent Cross-Site Scripting
- **SQL Injection Protection**: Parameterized queries throughout the application
- **User Enumeration Defense**: Constant-time comparisons and consistent responses
- **Secure Password Storage**: Passwords are stored as salted hashes with PBKDF2
- **Secure Session Management**: JWTs stored in HttpOnly cookies
- **Security Headers**: CSP, X-Content-Type-Options, X-Frame-Options
- **Input Validation**: Strict validation on all form inputs
- **Rate Limiting**: Prevents brute force attacks
- **Proper Error Handling**: Custom error pages and appropriate status codes

## 🧙‍♂️ Technical Implementation

### Stack
- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Database**: SQLite
- **Authentication**: JWT tokens stored in cookies

### Code Structure
- `app.py`: Main application file with routes and security implementations
- `user_service.py`: User authentication and management
- `account_service.py`: Account balance and transfer functionality
- `templates/`: HTML templates for the application
- `static/`: CSS, JavaScript, and image assets

## 🚀 Getting Started

### Prerequisites
- Python 3.7 or higher
- pip package manager



## ✨ Acknowledgments

- Inspired by the Harry Potter series by J.K. Rowling
- Flask micro framework for Python
- The wizarding community for entrusting us with their Galleons
- Many thanks to the Headmaster of Secure Coding, Dr. Toal 🧙‍♂️