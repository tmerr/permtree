extern crate clap;
extern crate users;

use users::{Users, Groups, UsersCache};
use std::{io, fs, ffi};
use std::path::Path;
use std::os::unix::fs::MetadataExt;

fn parse_args() -> Vec<String> {
    let matches = clap::App::new("permtree")
        .version("0.1")
        .author("Trevor Merrifield <trevorm42@gmail.com")
        .about("list file owners and permissions in a compact tree view")
        .arg(clap::Arg::with_name("directory")
             .required(true)
             .multiple(true)
             .value_delimiter(" "))
        .get_matches();

    matches.values_of("directory")
           .unwrap()
           .map(|v| v.to_owned())
           .collect()
}

#[derive(Debug)]
enum FileKind {
    Directory(Vec<Node>),
    Leaf,
}

#[derive(Debug)]
struct NodeData {
    perms: u32,
    uid: u32,
    gid: u32,
    kind: FileKind,
}

#[derive(Debug)]
struct Node {
    name: ffi::OsString,
    data: io::Result<NodeData>,
}

impl Node {
    fn has_children(&self) -> bool {
        if let Ok(NodeData { kind: FileKind::Directory(ref xs), .. }) = self.data {
            xs.len() > 0
        } else {
            false
        }
    }
}

fn fullperms(metadata: &fs::Metadata) -> u32 {
    metadata.mode() & 0o7777
}

fn compute_node(path: &Path) -> Node {
    let parentname = path.file_name().expect("permtree: error, failed to get file name from path!");
    let mk_error_node = |e| Node {
        name: parentname.to_owned(),
        data: Err(e),
    };
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return mk_error_node(e);
        },
    };
    let parentperms = fullperms(&metadata);
    
    if !metadata.is_dir() {
        return Node {
            name: parentname.to_owned(),
            data: Ok(NodeData {
                perms: parentperms,
                uid: metadata.uid(),
                gid: metadata.gid(),
                kind: FileKind::Leaf,
            }),
        };
    }

    let readdir = match fs::read_dir(path) {
        Ok(r) => r,
        Err(e) => {
            return mk_error_node(e);
        },
    };
    let mut children = vec![];
    for maybe_entry in readdir {
        match maybe_entry {
            Ok(entry) => {
                let node = compute_node(&entry.path());
                let should_push = match node.data {
                    Ok(ref d) => {
                        node.has_children()
                        || ((d.perms, d.uid, d.gid) != (parentperms, metadata.uid(), metadata.gid()))
                    }
                    Err(_) => true,
                };
                if should_push {
                    children.push(node);
                }
            },
            Err(e) => children.push(mk_error_node(e)),
        }
    }
    children.sort_by(|a, b| a.name.cmp(&b.name));
    Node {
        name: parentname.to_owned(),
        data: Ok(NodeData {
            perms: parentperms,
            uid: metadata.uid(),
            gid: metadata.gid(),
            kind: FileKind::Directory(children),
        }),
    }
}

fn display_tree(node: &Node, depth: usize, mut cache: &mut UsersCache) {
    let prefix = "  ".repeat(depth);
    let name = node.name.to_string_lossy();
    if let Ok(ref d) = node.data {
        let usergroup = {
            let username = cache.get_user_by_uid(d.uid)
                                .map(|u| u.name().to_owned())
                                .unwrap_or("UNKNOWN".to_owned());
            let groupname = cache.get_group_by_gid(d.gid)
                                 .map(|g| g.name().to_owned())
                                 .unwrap_or("UNKNOWN".to_owned());
            format!("{}/{} {}/{}", d.uid, username, d.gid, groupname)
        };
        match &d.kind {
            &FileKind::Directory(ref children) => {
                println!("{}+ {:04o} {} {}", prefix, d.perms, usergroup, name);
                for child in children {
                    display_tree(&child, 1 + depth, &mut cache);
                }
            },
            &FileKind::Leaf => println!("  {}{:04o} {} {}", prefix, d.perms, usergroup, name),
        }
    } else {
        println!("      {}{} [error]", prefix, name);
    }
}

fn main() {
    let directories = parse_args();
    let mut paths = vec![];
    for directory in directories {
        let path = Path::new(&directory);
        if let Ok(fullpath) = fs::canonicalize(&path) {
            paths.push(fullpath);
        } else {
            println!(r#"permtree: error: where is "{}"?"#, directory);
            return;
        }
    }
    let root = compute_node(Path::new(paths[0].to_str().unwrap()));

    let mut cache = UsersCache::new();
    display_tree(&root, 0, &mut cache);

    for path in paths.iter() {
        println!("{}", path.display());
    }
}
