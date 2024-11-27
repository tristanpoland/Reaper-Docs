use rocket::State;
use rocket::fs::FileServer;
use rocket_dyn_templates::context;
use rocket::form::Form;
use rocket::response::status::NotFound;
use rocket_dyn_templates::Template;
use rocket::http::Status;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::fs;
use walkdir::WalkDir;
use pulldown_cmark::{Parser, html::push_html, Options};
use chrono::{DateTime, Utc};
use std::sync::Mutex;

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

// Routes

#[get("/")]
async fn index(state: &State<AppState>) -> Template {
    let docs = list_documents(&state.docs_path);
    Template::render("index", context! { 
        docs: docs,
        title: "Documentation Site"
    })
}

#[get("/doc/<path..>")]
async fn view_doc(path: PathBuf, state: &State<AppState>) -> Result<Template, NotFound<String>> {
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
    }))
}

#[get("/edit/<path..>")]
async fn edit_doc(path: PathBuf, state: &State<AppState>) -> Result<Template, NotFound<String>> {
    let full_path = state.docs_path.join(&path);
    let content = fs::read_to_string(&full_path)
        .map_err(|e| NotFound(e.to_string()))?;

    Ok(Template::render("edit", context! {
        title: format!("Editing: {}", path.display()),
        content: content,
        path: path.display().to_string(),
    }))
}

#[post("/save/<path..>", data = "<form>")]
async fn save_doc(path: PathBuf, form: Form<DocEdit>, state: &State<AppState>) -> Result<rocket::response::Redirect, NotFound<String>> {
    let full_path = state.docs_path.join(&path);
    fs::write(&full_path, &form.content)
        .map_err(|e| NotFound(e.to_string()))?;
    
    // Update the index after saving
    if let Ok(mut index) = state.index.lock() {
        *index = list_documents(&state.docs_path);
    }
    
    Ok(rocket::response::Redirect::to(uri!(index)))
}

#[get("/search?<q>")]
async fn search(q: String, state: &State<AppState>) -> Template {
    let results = search_documents(&q, &state.index.lock().unwrap());
    Template::render("search", context! {
        query: q,
        results: results
    })
}

#[post("/new", data = "<form>")]
async fn new_doc(form: Form<NewDoc>, state: &State<AppState>) -> Result<String, Status> {
    let file_name = format!("{}.md", sanitize_filename(&form.title));
    let full_path = state.docs_path.join(&file_name);
    
    if full_path.exists() {
        return Err(Status::Conflict);
    }

    // Create initial content with YAML frontmatter
    let initial_content = format!(
        "---\ntitle: {}\ndate: {}\n---\n\n# {}\n\nStart writing here...",
        form.title,
        chrono::Utc::now().format("%Y-%m-%d"),
        form.title
    );

    fs::write(&full_path, initial_content)
        .map_err(|_| Status::InternalServerError)?;

    // Update the index
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
    let docs_path = PathBuf::from("./docs");
    let documents = list_documents(&docs_path);
    
    let app_state = AppState {
        docs_path,
        index: Mutex::new(documents),
    };

    rocket::build()
        .mount("/", routes![index, view_doc, edit_doc, save_doc, search, new_doc])
        .mount("/static", FileServer::from("static"))
        .manage(app_state)
        .attach(Template::fairing())
}