use std::collections::BTreeMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use encoding::{DecoderTrap, Encoding};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use rquickjs::loader::{BuiltinResolver, FileResolver, ModuleLoader, ScriptLoader};
use rquickjs::module::{Declarations, Exports, ModuleDef};
use rquickjs::{Context, Ctx, Runtime};
use rquickjs::{Function, Module};
use serde::ser::Serialize;
use serde_json::Serializer;

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::Builder;

    use super::*;

    #[test]
    fn test_query_env() -> io::Result<()> {
        let mut file = Builder::new().suffix(".bat").tempfile()?;

        file.write("@echo hello=world\r\n".as_bytes())?;
        file.flush()?;

        let envs = query_bat_env(file.path().to_str().unwrap())?;
        let mut r = BTreeMap::new();

        r.insert("hello".to_string(), "world".to_string());
        assert_eq!(envs, r);
        Ok(())
    }

    #[test]
    fn test_query_env_empty() -> io::Result<()> {
        let mut file = Builder::new().suffix(".bat").tempfile()?;

        file.flush()?;

        let envs = query_bat_env(file.path().to_str().unwrap())?;
        let r = BTreeMap::new();

        assert_eq!(envs, r);
        Ok(())
    }

    #[test]
    fn test_query_env_inavaild() -> io::Result<()> {
        let mut file = Builder::new().suffix(".bat").tempfile()?;
        file.write("@echo hello\r\n".as_bytes())?;
        file.flush()?;

        let envs = query_bat_env(file.path().to_str().unwrap())?;
        let r = BTreeMap::new();

        assert_eq!(envs, r);
        Ok(())
    }
}

fn print(msg: String) {
    println!("{msg}")
}

fn query_bat_env(bat: &str) -> io::Result<BTreeMap<String, String>> {
    let mut cmd = Command::new("cmd")
        .args(&["/c", bat])
        .stdout(Stdio::piped())
        .spawn()?;
    let status = cmd.wait()?;

    if !status.success() {
        return Ok(BTreeMap::new());
    }

    let mut content = String::new();

    let out = cmd.stdout.unwrap().read_to_string(&mut content)?;
    if out == 0 {
        return Ok(BTreeMap::new());
    }

    let mut envs = BTreeMap::new();

    for l in content.lines().filter(|l| !l.is_empty()) {
        let env: Vec<String> = l.split("=").map(|s| s.to_string()).collect();
        if env.len() != 2 {
            continue;
        }
        let k = env[0].to_owned();
        let v = env[1].to_owned();

        envs.insert(k, v);
    }

    Ok(envs)
}

fn query_vs_where() -> Result<Vec<String>, Box<dyn Error>> {
    download_vs_where()?;

    let mut vswhere = Command::new(r".\vswhere.exe")
        .args(&["-all", "-format", "json"])
        .stdout(Stdio::piped())
        .spawn()?;

    if !vswhere.wait()?.success() {
        todo!("不成功")
    }

    let mut content = vec![];
    let size = vswhere.stdout.unwrap().read_to_end(&mut content)?;
    assert_ne!(size, 0);

    let content = encoding::all::GBK.decode(content.as_mut(), DecoderTrap::Strict)?;

    let json: serde_json::Value = serde_json::from_str(content.as_str())?;

    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut buffer = vec![];
    let mut serializer = Serializer::with_formatter(&mut buffer, formatter);
    let mut paths = vec![];
    for path in json.as_array().unwrap() {
        paths.push(path["installationPath"].as_str().unwrap().to_string());
    }

    Ok(paths)
}

fn download_vs_where() -> Result<(), Box<dyn Error>> {
    if PathBuf::from("vswhere.exe").exists() {
        return Ok(());
    }
    let mut token = String::new();
    File::open("token.txt")
        .unwrap()
        .read_to_string(&mut token)?;
    let client = reqwest::blocking::Client::new();

    let resp = client
        .get("https://api.github.com/repos/microsoft/vswhere/releases/latest")
        .header(AUTHORIZATION, format!("token {token}"))
        .header(USER_AGENT, "Rust")
        .header(ACCEPT, "application/vnd.github.v3+json")
        .send()?
        .json::<serde_json::Value>()?;

    let vs_where_url = resp["assets"].as_array().ok_or("缺少assets")?[0]
        .as_object()
        .unwrap()["browser_download_url"]
        .as_str()
        .unwrap();

    let mut resp = client.get(vs_where_url).send()?;

    let mut file = File::create("vswhere.exe")?;
    std::io::copy(&mut resp.bytes()?.as_ref(), &mut file)?;
    Ok(())
}

fn query_vs_env() -> Result<(), Box<dyn std::error::Error>> {
    let paths = query_vs_where()?;
    let bat = r".\getvsvarsall.bat";

    let envs = query_bat_env(bat)?;

    let path = &envs["Path"];
    std::env::set_var("Path", path);

    println!("{:?}", which::which("cl.exe"));
    Ok(())
}

struct NativeModule;

impl ModuleDef for NativeModule {
    fn declare<'js>(decl: &Declarations<'js>) -> rquickjs::Result<()> {
        decl.declare("which")?;
        Ok(())
    }

    fn evaluate<'js>(ctx: &Ctx<'js>, exports: &Exports<'js>) -> rquickjs::Result<()> {
        let c = ctx.clone();
        let which_func =
            move |name: String| -> rquickjs::Result<String> {
                // println!("{name:?}");
                if name == "where.exe" {
                    return Ok("where.exe".to_string());
                }
                return match which::which(name) {
                    Ok(target) => Ok(target.to_str().unwrap().to_string()),
                    Err(which::Error::CannotFindBinaryPath) => {
                        // ctx.throw(rquickjs::Value::from("找不到文件"));
                        // Err(Io(std::io::Error::from(NotFound)));
                        Err(c.clone().throw(rquickjs::Value::from_string(
                            rquickjs::String::from_str(c.clone(), "找不到文件")?,
                        )))
                        // Ok(rquickjs::Value::from_exception())
                        // Ok("".to_string())
                    }
                    Err(which::Error::CannotGetCurrentDirAndPathListEmpty) => {
                        Err(rquickjs::Error::Exception)
                    }
                    Err(which::Error::CannotCanonicalize) => Err(rquickjs::Error::Exception),
                };
            };
        exports.export("which", Function::<'js>::new(ctx.clone(), which_func))?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;

    let rt = Runtime::new().unwrap();
    let ctx = Context::full(&rt).unwrap();

    rt.set_loader(
        (
            FileResolver::default().with_path("./scripts"),
            BuiltinResolver::default().with_module("native"),
        ),
        (
            ScriptLoader::default(),
            ModuleLoader::default().with_module("native", NativeModule),
        ),
    );

    ctx.enable_big_num_ext(true);

    let mut content = String::new();
    let size = File::open("main.js")?.read_to_string(&mut content)?;
    assert_ne!(size, 0);

    ctx.with(|ctx| {
        let g = ctx.globals();

        g.set(
            "print",
            Function::new(ctx.clone(), print)
                .unwrap()
                .with_name("print")
                .unwrap(),
        )
        .unwrap();

        let r = match Module::evaluate(ctx.clone(), "main", content) {
            Ok(r) => r,
            Err(rquickjs::Error::Io(e)) => {
                panic!("{e:?}")
            }
            Err(e) => {
                panic!("{e:?}")
            }
        };
        rt.run_gc();
        match r.finish::<()>() {
            Ok(ok) => {}
            Err(e) => {
                // eprintln!("{e:?}")
            }
        }
    });

    disable_raw_mode()?;
    Ok(())
}
