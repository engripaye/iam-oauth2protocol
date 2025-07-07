## OAUTH2 PROTOCOL ##

🔐 Project Overview
Components:
Authorization Server (/auth)

Resource Server (/api)

Client (HTML website)

1. 📁 Project Structure
pgsql
Copy
Edit
iam-oauth2/
├── backend/
│   ├── auth-server/        → OAuth2 Authorization Server
│   └── resource-server/    → Protected Resource Server
└── frontend/
    └── index.html          → Login UI and token usage
