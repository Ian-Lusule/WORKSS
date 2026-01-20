# MoneyFlow Python

A web-based financial management application migrated from Flutter, using Flask with encrypted file storage.

## Features

- **Secure Authentication**: User registration/login with bcrypt password hashing
- **Expense Tracking**: Add, edit, delete expenses with categories
- **Budget Management**: Create budgets, track progress with alerts
- **Financial Insights**: Charts and analytics for spending patterns
- **Notifications**: In-app alerts for budget limits
- **Reports**: Generate and export financial reports
- **Local Encryption**: All data encrypted with Fernet encryption
- **Responsive UI**: Modern interface with Bootstrap 5 and Chart.js

## Quick Start

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd moneyflow-python

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt