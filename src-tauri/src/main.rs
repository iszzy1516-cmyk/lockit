#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rand::{rngs::OsRng, RngCore};
use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindow};
use tauri_plugin_shell::process::CommandChild;
#[cfg(not(debug_assertions))]
use tauri_plugin_shell::{process::CommandEvent, ShellExt};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct EmbeddedServer {
    child: Mutex<Option<CommandChild>>,
    exited: Arc<AtomicBool>,
    serving: Arc<AtomicBool>,
    output: Arc<Mutex<String>>,
}

impl EmbeddedServer {
    fn stop(&self) {
        self.serving.store(false, Ordering::Release);
        let child = lock(&self.child).take();
        if let Some(child) = child {
            if let Err(error) = child.kill() {
                eprintln!("Lockit could not stop the embedded server: {error}");
            }
        }
    }

    fn diagnostics(&self) -> String {
        let output = lock(&self.output);
        let output = output.trim();
        if output.is_empty() {
            "The embedded server did not emit any diagnostics.".to_string()
        } else {
            output.to_string()
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn reserve_loopback_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> std::io::Result<()> {
    use std::process::{Command, Stdio};

    let username = std::env::var("USERNAME")
        .map_err(|_| std::io::Error::other("Could not determine the Windows username"))?;
    let account = match std::env::var("USERDOMAIN") {
        Ok(domain) if !domain.is_empty() => format!(r"{domain}\{username}"),
        _ => username,
    };
    let status = Command::new("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{account}:F"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "icacls could not restrict {} to the current user",
            path.display()
        )))
    }
}

fn read_pepper(path: &Path) -> Result<String, Box<dyn Error>> {
    restrict_file(path)?;
    let pepper = fs::read_to_string(path)?.trim().to_string();
    if pepper.len() < 32 {
        return Err(failure(format!(
            "{} must contain at least 32 bytes",
            path.display()
        )));
    }
    Ok(pepper)
}

fn load_or_create_pepper(app_data: &Path) -> Result<String, Box<dyn Error>> {
    let path = app_data.join("share-pepper");
    if path.exists() {
        return read_pepper(&path);
    }

    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let pepper: String = random.iter().map(|byte| format!("{byte:02x}")).collect();

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(&path) {
        Ok(mut file) => {
            let result = (|| -> std::io::Result<()> {
                restrict_file(&path)?;
                file.write_all(pepper.as_bytes())?;
                file.sync_all()
            })();
            if let Err(error) = result {
                let _ = fs::remove_file(&path);
                return Err(error.into());
            }
            Ok(pepper)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_pepper(&path),
        Err(error) => Err(error.into()),
    }
}

fn check_health(port: u16) -> std::io::Result<()> {
    let address = ([127, 0, 0, 1], port).into();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "GET /api/health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = Vec::new();
    stream.take(16 * 1024).read_to_end(&mut response)?;
    let response = String::from_utf8_lossy(&response);
    let healthy = (response.starts_with("HTTP/1.1 200 ") || response.starts_with("HTTP/1.0 200 "))
        && response.contains(r#"{"status":"ok"}"#);
    if healthy {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "Health endpoint returned an invalid response",
        ))
    }
}

fn wait_until_healthy(port: u16, server: &EmbeddedServer) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if server.exited.load(Ordering::Acquire) {
            return Err(failure(format!(
                "The embedded Node server exited before becoming ready.\n{}",
                server.diagnostics()
            )));
        }
        match check_health(port) {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                let message = format!(
                    "The embedded Node server did not become healthy within {} seconds: {error}.\n{}",
                    STARTUP_TIMEOUT.as_secs(),
                    server.diagnostics()
                );
                return Err(failure(message));
            }
        }
    }
}

fn create_main_window(app: &AppHandle, url: WebviewUrl) -> tauri::Result<WebviewWindow> {
    tauri::WebviewWindowBuilder::new(app, "main", url)
        .title("Lockit")
        .inner_size(1100.0, 760.0)
        .min_inner_size(900.0, 600.0)
        .build()
}

#[cfg(not(debug_assertions))]
fn start_embedded(app: &AppHandle) -> Result<(), Box<dyn Error>> {
    let port = reserve_loopback_port()?;
    let origin = format!("http://127.0.0.1:{port}");
    let app_data = app.path().app_data_dir()?;
    fs::create_dir_all(&app_data)?;
    let pepper = load_or_create_pepper(&app_data)?;

    let resources = app.path().resource_dir()?;
    let launcher = resources.join("sidecar.mjs");
    let server_entry = resources.join("server").join("server").join("index.js");
    let public_dir = resources.join("public");
    for (path, description) in [
        (&launcher, "server launcher"),
        (&server_entry, "built server entry"),
    ] {
        if !path.is_file() {
            return Err(failure(format!(
                "The packaged {description} is missing: {}",
                path.display()
            )));
        }
    }
    if !public_dir.join("index.html").is_file() {
        return Err(failure(format!(
            "The packaged web client is missing: {}",
            public_dir.display()
        )));
    }

    let command = app
        .shell()
        .sidecar("node")
        .map_err(|error| {
            failure(format!(
                "Could not resolve the bundled Node sidecar: {error}"
            ))
        })?
        .arg(&launcher)
        .arg(&server_entry)
        .env("PORT", port.to_string())
        .env("LOCKIT_PUBLIC_ORIGIN", &origin)
        .env("LOCKIT_DB_PATH", app_data.join("lockit.db"))
        .env("LOCKIT_SHARE_PEPPER", pepper)
        .env("LOCKIT_PUBLIC_DIR", &public_dir)
        .env("LOCKIT_TRUST_PROXY", "false")
        .env("NODE_ENV", "development");
    let (mut events, child) = command.spawn().map_err(|error| {
        failure(format!(
            "Could not launch the bundled Node sidecar: {error}"
        ))
    })?;

    let server = app.state::<EmbeddedServer>();
    *lock(&server.child) = Some(child);

    let exited = Arc::clone(&server.exited);
    let serving = Arc::clone(&server.serving);
    let output = Arc::clone(&server.output);
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                CommandEvent::Stdout(line) | CommandEvent::Stderr(line) => {
                    let mut output = lock(&output);
                    if output.len() < 16 * 1024 {
                        output.push_str(&String::from_utf8_lossy(&line));
                        if !line.ends_with(b"\n") {
                            output.push('\n');
                        }
                    }
                }
                CommandEvent::Error(error) => {
                    lock(&output).push_str(&format!("Sidecar error: {error}\n"));
                }
                CommandEvent::Terminated(payload) => {
                    exited.store(true, Ordering::Release);
                    if serving.load(Ordering::Acquire) {
                        eprintln!(
                            "Lockit's embedded server stopped unexpectedly (exit code {:?}).",
                            payload.code
                        );
                        app_handle.exit(1);
                    }
                }
                _ => {}
            }
        }
    });

    wait_until_healthy(port, &server)?;
    create_main_window(app, WebviewUrl::External(origin.parse()?))?;
    server.serving.store(true, Ordering::Release);
    if server.exited.load(Ordering::Acquire) {
        server.serving.store(false, Ordering::Release);
        return Err(failure(format!(
            "The embedded Node server stopped during startup.\n{}",
            server.diagnostics()
        )));
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn Error>> {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(EmbeddedServer::default())
        .setup(|app| {
            #[cfg(debug_assertions)]
            create_main_window(app.handle(), WebviewUrl::App("index.html".into()))?;

            #[cfg(not(debug_assertions))]
            if let Err(error) = start_embedded(app.handle()) {
                app.state::<EmbeddedServer>().stop();
                return Err(error);
            }
            Ok(())
        })
        .build(tauri::generate_context!())?;

    app.run(|handle, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            handle.state::<EmbeddedServer>().stop();
        }
    });
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Lockit could not start: {error}");
        std::process::exit(1);
    }
}
