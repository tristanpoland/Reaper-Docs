# Reaper Docs

A secure, authenticated documentation management system built with Rust and Rocket.

## Features

- Markdown document management
- User authentication and authorization
- Role-based access control (Admin/User)
- Document search functionality
- Document metadata (reading time, word count, previews)
- Secure session management
- Admin user management panel

## Prerequisites

- Rust and Cargo
- SQLite3
- A web browser with JavaScript enabled

## Setup

1. Clone the repository
```bash
git clone https://github.com/yourusername/reaper-docs.git
cd reaper-docs
```

2. Create necessary directories
```bash
mkdir docs
mkdir static
```

3. Build and run
```bash
cargo build --release
cargo run
```

The server will start at `http://localhost:8000`

## Initial Login

Default admin credentials:
- Username: `admin`
- Password: `admin`

**Important:** Change these credentials after first login.

## Usage

### User Management

- `/login` - User login
- `/register` - New user registration
- `/profile` - User profile management
- `/admin/users` - User management (admin only)

### Document Management

- `/` - Document list
- `/doc/<path>` - View document
- `/edit/<path>` - Edit document
- `/search?q=<query>` - Search documents

## Security Features

- Password hashing with bcrypt
- Secure session management
- CSRF protection
- Private cookie encryption
- SQL injection protection

## License

MIT
