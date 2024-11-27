use rocket::State;
use rocket::fs::FileServer;
use rocket_dyn_templates::context;
use rocket::form::Form;
use rocket::response::status::NotFound;
use rocket_dyn_templates::Template;
use rocket::http::Status;
use serde::Serialize;
use chrono::Duration;
use uuid::Uuid;
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;
use pulldown_cmark::{Parser, html::push_html, Options};
use chrono::{DateTime, Utc};
use std::sync::Mutex;
use rocket::http::{Cookie, CookieJar};
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::Redirect;
use rusqlite::{params, Connection, Result as SqliteResult};
use bcrypt::{hash, verify, DEFAULT_COST};

#[macro_use]
extern crate rocket;

// Document representation with enhanced metadata
#[derive(Debug, Serialize, Clone)]
struct Document {
    title: String,
    content: String,
    path: String,
    modified: String,
    preview: String,        // First few lines of content
    word_count: usize,      // Number of words in document
    reading_time: usize,    // Estimated reading time in minutes
}

// Search results structure
#[derive(Debug, Serialize)]
struct SearchResults {
    query: String,
    results: Vec<Document>,
}

// App state
struct AppState {
    docs_path: PathBuf,
    index: Mutex<Vec<Document>>,
}

// Form structures
#[derive(FromForm)]
struct DocEdit {
    content: String,
}

#[derive(FromForm)]
struct NewDoc {
    title: String,
}

// User structures
#[derive(Debug, Serialize)]
pub struct User {
    id: i64,
    username: String,
    email: String,
    role: String,
}

#[derive(FromForm)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[derive(FromForm)]
pub struct RegisterForm {
    username: String,
    email: String,
    password: String,
    confirm_password: String,
}

#[derive(FromForm)]
pub struct UserUpdateForm {
    email: String,
    current_password: String,
    new_password: Option<String>,
    role: Option<String>,
}

// Database setup
pub fn init_db() -> SqliteResult<()> {
    let conn = Connection::open("users.db")?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )",
        [],
    )?;
    
    // Add to database setup
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires TIMESTAMP NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )",
        [],
    )?;
    
    // Create admin user if it doesn't exist
    let admin_exists: bool = conn
        .query_row(
            "SELECT 1 FROM users WHERE username = ?",
            params!["admin"],
            |_| Ok(true),
        )
        .unwrap_or(false);

    if !admin_exists {
        let hashed_password = hash("admin", DEFAULT_COST).unwrap();
        conn.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            params!["admin", "admin@example.com", hashed_password, "admin"],
        )?;
    }

    Ok(())
}

// Auth guard
pub struct AuthenticatedUser(User);

#[rocket::async_trait]
#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(cookie) = request.cookies().get_private("session") {
            let conn = match request.guard::<&State<Mutex<Connection>>>().await {
                Outcome::Success(conn) => conn,
                _ => return Outcome::Error((Status::InternalServerError, ())),
            };

            let conn = match conn.lock() {
                Ok(conn) => conn,
                _ => return Outcome::Error((Status::InternalServerError, ())),
            };

            if let Ok(user_id) = conn.query_row(
                "SELECT user_id FROM sessions WHERE token = ? AND expires > datetime('now')",
                params![cookie.value()],
                |row| row.get::<_, i64>(0)
            ) {
                if let Ok(user) = get_user_by_id(&conn, user_id) {
                    return Outcome::Success(AuthenticatedUser(user));
                }
            }
        }
        Outcome::Forward(Status::Unauthorized)
    }
}

// Database helper functions
fn get_user_by_id(conn: &Connection, id: i64) -> SqliteResult<User> {
    conn.query_row(
        "SELECT id, username, email, role FROM users WHERE id = ?",
        params![id],
        |row| {
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                role: row.get(3)?,
            })
        },
    )
}

fn verify_credentials(conn: &Connection, username: &str, password: &str) -> SqliteResult<User> {
    let user: User = conn.query_row(
        "SELECT id, username, email, role, password FROM users WHERE username = ?",
        params![username],
        |row| {
            let stored_hash: String = row.get(4)?;
            if !verify(password, &stored_hash).map_err(|_| rusqlite::Error::InvalidQuery)? {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(User {
                id: row.get(0)?,
                username: row.get(1)?,
                email: row.get(2)?,
                role: row.get(3)?,
            })
        },
    )?;
    Ok(user)
}

// Route handlers
#[get("/login")]
pub fn login_page() -> Template {
    Template::render("login", context! {
        title: "Login",
    })
}

#[post("/login", data = "<form>")]
pub fn login(form: Form<LoginForm>, cookies: &CookieJar<'_>, conn: &State<Mutex<Connection>>) -> Result<Redirect, Status> {
    let conn = conn.lock().map_err(|_| Status::InternalServerError)?;
    let result = verify_credentials(&conn, &form.username, &form.password)
        .map_err(|_| Status::Unauthorized)?;
    
    let token = Uuid::new_v4().to_string();
    let expires = Utc::now() + Duration::hours(24);
    
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)",
        params![token, result.id, expires.to_rfc3339()],
    ).map_err(|_| Status::InternalServerError)?;

    cookies.add_private(Cookie::new("session", token));
    Ok(Redirect::to(uri!(index)))
}

#[get("/register")]
pub fn register_page() -> Template {
    Template::render("register", context! {
        title: "Register"
    })
}


#[post("/register", data = "<form>")]
pub fn register(form: Form<RegisterForm>, conn: &State<Mutex<Connection>>) -> Result<Redirect, Status> {
    if form.password != form.confirm_password {
        return Err(Status::BadRequest);
    }

    let conn = conn.lock().map_err(|_| Status::InternalServerError)?;
    let hashed_password = hash(&form.password, DEFAULT_COST).map_err(|_| Status::InternalServerError)?;

    conn.execute(
        "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
        params![form.username, form.email, hashed_password, "user"],
    )
    .map_err(|_| Status::Conflict)?;

    Ok(Redirect::to(uri!(login_page)))
}


#[get("/logout")]
pub fn logout(cookies: &CookieJar<'_>) -> Result<Redirect, Status> {
    cookies.remove_private(Cookie::named("session"));
    Ok(Redirect::to(uri!(login_page)))
}

#[get("/profile")]
pub fn profile(user: AuthenticatedUser) -> Template {
    Template::render("profile", context! {
        title: "Profile",
        user: user.0
    })
}

#[post("/profile", data = "<form>")]
pub fn update_profile(user: AuthenticatedUser, form: Form<UserUpdateForm>, conn: &State<Mutex<Connection>>) -> Result<Redirect, Status> {
    let conn = conn.lock().map_err(|_| Status::InternalServerError)?;
    
    // Verify current password
    let mut stmt = conn.prepare("SELECT password FROM users WHERE id = ?")
        .map_err(|_| Status::InternalServerError)?;
    
    let current_hash: String = stmt.query_row(params![user.0.id], |row| row.get(0))
        .map_err(|_| Status::InternalServerError)?;
    
    if !verify(&form.current_password, &current_hash).unwrap_or(false) {
        return Err(Status::Unauthorized);
    }

    // Update user information
    let mut query_parts = Vec::new();
    let mut param_values: Vec<String> = Vec::new();

    // Always update email
    query_parts.push("email = ?");
    param_values.push(form.email.clone());

    // Handle password update if provided
    if let Some(ref new_password) = form.new_password {
        if !new_password.is_empty() {
            let hashed_password = hash(new_password, DEFAULT_COST)
                .map_err(|_| Status::InternalServerError)?;
            query_parts.push("password = ?");
            param_values.push(hashed_password);
        }
    }

    // Handle role update if user is admin
    if let Some(ref role) = form.role {
        if user.0.role == "admin" {
            query_parts.push("role = ?");
            param_values.push(role.clone());
        }
    }

    // Build the query
    let query = format!(
        "UPDATE users SET {} WHERE id = ?",
        query_parts.join(", ")
    );

    // Convert parameters to &dyn ToSql
    let params: Vec<&dyn rusqlite::ToSql> = param_values
        .iter()
        .map(|v| v as &dyn rusqlite::ToSql)
        .collect();

    // Add user ID as the last parameter
    let user_id: i64 = user.0.id;
    let mut all_params = params;
    all_params.push(&user_id);

    // Execute the update
    conn.execute(&query, all_params.as_slice())
        .map_err(|_| Status::InternalServerError)?;

    Ok(Redirect::to(uri!(profile)))
}

// Admin routes
#[get("/admin/users")]
pub fn list_users(user: AuthenticatedUser) -> Result<Template, Status> {
    if user.0.role != "admin" {
        return Err(Status::Forbidden);
    }

    let conn = Connection::open("users.db").map_err(|_| Status::InternalServerError)?;
    let mut stmt = conn.prepare("SELECT id, username, email, role FROM users")
        .map_err(|_| Status::InternalServerError)?;

    let users: Result<Vec<User>, _> = stmt.query_map([], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            email: row.get(2)?,
            role: row.get(3)?,
        })
    }).map_err(|_| Status::InternalServerError)?.collect();

    let users = users.map_err(|_| Status::InternalServerError)?;

    Ok(Template::render("admin/users", context! {
        title: "User Management",
        users: users
    }))
}


// Routes

#[get("/")]
async fn index(user: AuthenticatedUser, state: &State<AppState>) -> Template {
    let docs = list_documents(&state.docs_path);
    Template::render("index", context! { 
        docs: docs,
        title: "Documentation Site",
        user: user.0
    })
}

// Modify document viewing to require authentication
#[get("/doc/<path..>")]
async fn view_doc(user: AuthenticatedUser, path: PathBuf, state: &State<AppState>) -> Result<Template, NotFound<String>> {
    let full_path = state.docs_path.join(&path);
    if !full_path.exists() {
        return Err(NotFound(format!("Document not found: {}", path.display())));
    }

    let content = fs::read_to_string(&full_path)
        .map_err(|e| NotFound(e.to_string()))?;
    
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);
    
    let parser = Parser::new_ext(&content, options);
    let mut html = String::new();
    push_html(&mut html, parser);

    Ok(Template::render("document", context! {
        title: path.file_stem().unwrap().to_string_lossy(),
        content: html,
        path: path.display().to_string(),
        user: user.0
    }))
}

// Protect edit functionality
#[get("/edit/<path..>")]
async fn edit_doc(user: AuthenticatedUser, path: PathBuf, state: &State<AppState>) -> Result<Template, NotFound<String>> {
    let full_path = state.docs_path.join(&path);
    let content = fs::read_to_string(&full_path)
        .map_err(|e| NotFound(e.to_string()))?;

    Ok(Template::render("edit", context! {
        title: format!("Editing: {}", path.display()),
        content: content,
        path: path.display().to_string(),
        user: user.0
    }))
}
#[post("/save/<path..>", data = "<form>")]
async fn save_doc(_user: AuthenticatedUser, path: PathBuf, form: Form<DocEdit>, state: &State<AppState>) -> Result<Redirect, NotFound<String>> {
    let full_path = state.docs_path.join(&path);
    fs::write(&full_path, &form.content)
        .map_err(|e| NotFound(e.to_string()))?;
    
    if let Ok(mut index) = state.index.lock() {
        *index = list_documents(&state.docs_path);
    }
    
    Ok(Redirect::to(uri!(index)))
}

#[get("/search?<q>")]
async fn search(user: AuthenticatedUser, q: String, state: &State<AppState>) -> Template {
    let results = search_documents(&q, &state.index.lock().unwrap());
    Template::render("search", context! {
        query: q,
        results: results,
        user: user.0
    })
}


#[post("/new", data = "<form>")]
async fn new_doc(user: AuthenticatedUser, form: Form<NewDoc>, state: &State<AppState>) -> Result<String, Status> {
    let file_name = format!("{}.md", sanitize_filename(&form.title));
    let full_path = state.docs_path.join(&file_name);
    
    if full_path.exists() {
        return Err(Status::Conflict);
    }

    let initial_content = format!(
        "---\ntitle: {}\ndate: {}\nauthor: {}\n---\n\n# {}\n\nStart writing here...",
        form.title,
        chrono::Utc::now().format("%Y-%m-%d"),
        user.0.username,
        form.title
    );

    fs::write(&full_path, initial_content)
        .map_err(|_| Status::InternalServerError)?;

    if let Ok(mut index) = state.index.lock() {
        *index = list_documents(&state.docs_path);
    }

    Ok(file_name)
}

// Helper functions

fn list_documents(docs_path: &Path) -> Vec<Document> {
    WalkDir::new(docs_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
        .map(|entry| {
            let content = fs::read_to_string(entry.path()).unwrap_or_default();
            let modified = entry.metadata()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                .and_then(|m| m.modified())
                .map(|m| DateTime::<Utc>::from(m).format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_default();

            // Generate preview (first 150 chars, skipping headers and empty lines)
            let preview = content.lines()
                .filter(|line| !line.starts_with('#') && !line.is_empty())
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(150)
                .collect::<String>();

            // Calculate word count and reading time
            let word_count = content.split_whitespace().count();
            let reading_time = (word_count as f64 / 200.0).ceil() as usize; // Assuming 200 words per minute

            Document {
                title: entry.path().file_stem().unwrap().to_string_lossy().to_string(),
                content,
                path: entry.path().strip_prefix(docs_path)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string(),
                modified,
                preview,
                word_count,
                reading_time,
            }
        })
        .collect()
}

fn search_documents(query: &str, documents: &[Document]) -> Vec<Document> {
    let query = query.to_lowercase();
    documents
        .iter()
        .filter(|doc| {
            doc.title.to_lowercase().contains(&query) || 
            doc.content.to_lowercase().contains(&query)
        })
        .cloned()
        .collect()
}

// Helper function to sanitize filenames
fn sanitize_filename(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect()
}

#[launch]
fn rocket() -> _ {
    // Initialize database
    init_db().expect("Failed to initialize database");
    
    let docs_path = PathBuf::from("./docs");
    let documents = list_documents(&docs_path);
    
    let app_state = AppState {
        docs_path,
        index: Mutex::new(documents),
    };

    let db_conn = Connection::open("users.db")
        .expect("Failed to open database connection");

    rocket::build()
        .mount("/", routes![
            index,
            view_doc,
            edit_doc,
            save_doc,
            search,
            new_doc,
            login_page,
            login,
            register,
            register_page,
            logout,
            profile,
            update_profile,
            list_users
        ])
        .mount("/static", FileServer::from("static"))
        .manage(app_state)
        .manage(Mutex::new(db_conn))
        .attach(Template::fairing())
}

// Add a helper function to check authentication
fn is_authenticated(cookies: &CookieJar<'_>) -> bool {
    cookies.get("user_id").is_some()
}