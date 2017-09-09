extern crate clap;
extern crate users;

use users::{Users, Groups, UsersCache};
use std::{io, fs, ffi};
use std::path::{Path, PathBuf};
use std::os::unix::fs::MetadataExt;
use std::os::unix::ffi::OsStrExt;

struct Args {
    command_mode: bool,
    directories: Vec<String>,
}

fn parse_args() -> Args {
    let matches = clap::App::new("permtree")
        .version("0.1")
        .author("Trevor Merrifield <trevorm42@gmail.com")
        .about("list file owners and permissions in a compact tree view")
        .arg(clap::Arg::with_name("directory")
             .required(true)
             .multiple(true)
             .value_delimiter(" "))
        .arg(clap::Arg::with_name("commands")
             .help("display as a list of recursive chmods/chowns")
             .long("commands"))
        .get_matches();

    Args {
        command_mode: matches.is_present("commands"),
        directories: matches.values_of("directory")
                            .unwrap()
                            .map(|v| v.to_owned())
                            .collect(),
    }
}

#[derive(Debug, Copy, Clone)]
enum FileKind {
    Directory,
    Leaf,
}

#[derive(Debug)]
struct NodeData {
    override_perms: Option<u32>,
    override_uid: Option<u32>,
    override_gid: Option<u32>,
    kind: FileKind,

    // might fail to list directory contents
    children: io::Result<Vec<Node>>,
}

#[derive(Debug)]
struct Node {
    name: ffi::OsString,

    // might fail to read metadata from the file
    data: io::Result<NodeData>,
}

/// Is this value inherited from the parent or does it need to be explicitly
/// assigned?
fn maybe_override<T: Copy + PartialEq>(parent: T, child: T) -> Option<T> {
    if parent == child {
        None
    } else {
        Some(child)
    }
}

/// Greedily list directory contents
fn ls(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = vec![];
    for maybe_child in fs::read_dir(path)? {
        paths.push(maybe_child?.path().to_owned())
    }
    Ok(paths)
}

/// Used in the build_tree function to pass info to children so they can
/// tell whether they inherit or override.
struct ParentData {
    perms: u32,
    uid: u32,
    gid: u32,
    kind: FileKind,
}

/// Read from the filesystem into an in-memory tree.
fn build_tree(path: &Path, maybe_parent_data: &Option<ParentData>) -> Node {
    Node {
        name: path.file_name()
                  .expect("permtree: error, failed to get file name from path!")
                  .to_owned(),
        data: std::fs::metadata(path).map(|metadata| {
            let perms = metadata.mode() & 0o7777;
            let (override_perms, override_uid, override_gid) = {
                if let &Some(ref parent_data) = maybe_parent_data {
                    (maybe_override(parent_data.perms, perms),
                     maybe_override(parent_data.uid, metadata.uid()),
                     maybe_override(parent_data.gid, metadata.gid()))
                } else {
                    (Some(perms), Some(metadata.uid()), Some(metadata.gid()))
                }
            };
            let kind = if metadata.is_dir() { FileKind::Directory } else { FileKind::Leaf };
            NodeData {
                override_perms,
                override_uid,
                override_gid,
                kind,
                children: {
                    if metadata.is_dir() {
                        let our_data = Some(ParentData {
                            perms,
                            uid: metadata.uid(),
                            gid: metadata.gid(),
                            kind,
                        });
                        ls(path).map(|children| children.iter().map(|child|
                            build_tree(child, &our_data)).collect())
                    } else {
                        Ok(vec![])
                    }
                },
            }
        }),
    }
}

/// Prune away subtrees that have only inherited fields.
fn prune(node: Node) -> Option<Node> {
    match node.data {
        Ok(NodeData { override_perms, override_uid, override_gid, kind, children }) => {
            match children {
                Ok(cs) => {
                    let all_inherited = override_perms.is_none()
                                        && override_uid.is_none()
                                        && override_gid.is_none();
                    let new_children: Vec<_> = cs.into_iter().filter_map(prune).collect();
                    if all_inherited && new_children.is_empty() {
                        None
                    } else {
                        Some(Node {
                            name: node.name,
                            data: Ok(NodeData {
                                override_perms,
                                override_uid,
                                override_gid,
                                kind,
                                children: Ok(new_children),
                            })
                        })
                    }
                }
                Err(e) => Some(Node {
                    name: node.name,
                    data: Ok(NodeData {
                        override_perms,
                        override_uid,
                        override_gid,
                        kind,
                        children: Err(e),
                    }),
                })
            }
        },
        Err(e) => {
            Some(Node {
                name: node.name,
                data: Err(e),
            })
        },
    }
}

/// Perform a preorder traversal of the tree. Apply the `visit`
/// function at each node.
fn preorder_traversal(node: &Node, depth: usize, visit: &mut FnMut(&Node, usize)) {
    visit(node, depth);
    if let Ok(NodeData { children: Ok(ref cs), .. }) = node.data {
        for child in cs.iter() {
            preorder_traversal(child, 1 + depth, visit);
        }
    }
}

/// Print the tree to the terminal.
fn display_tree(root: &Node) {
    let mut output = String::new();
    let mut cache = NameCache::new();
    {
        let mut visit = |node: &Node, depth: usize| {
            for i in 0..depth {
                output.push_str("  ");
            }
            if let Ok(ref data) = node.data {
                output.push_str("[ ");
                if let Some(perms) = data.override_perms {
                    output.push_str(&format!("perms: {:04o}, ", perms));
                }
                if let Some(uid) = data.override_uid {
                    output.push_str(&format!("user: {}, ", cache.display_uid(uid)));
                }
                if let Some(gid) = data.override_gid {
                    output.push_str(&format!("group: {}, ", cache.display_gid(gid)));
                }
                output.push(']');
            } else {
                output.push_str(&" [ error reading metadata ]");
            }
            output.push(' ');
            output.push_str(&node.name.to_string_lossy());
            output.push('\n');
        };
        preorder_traversal(root, 0, &mut visit);
    }
    print!("{}", output);
}

/// Printing characters is hard. Encode everything in hex for now.
fn bash_encode(path: &Vec<ffi::OsString>) -> String {
    let mut result = String::new();
    let mut first = true;
    result.push_str(r#""$(printf ""#);
    for part in path {
        if !first {
            result.push('/');
        }
        for byte in part.as_bytes(){
            result.push_str(&format!("\\x{:02x}", byte));
        }
        first = false;
    }
    result.push_str(r#"")""#);
    result
}

struct NameCache(UsersCache);

impl NameCache {
    fn new() -> NameCache {
        NameCache(UsersCache::new())
    }

    fn display_uid(&mut self, uid: u32) -> String {
        self.0.get_user_by_uid(uid)
              .map(|u| u.name().to_owned())
              .unwrap_or(format!("{}", uid))
    }

    fn display_gid(&mut self, gid: u32) -> String {
        self.0.get_group_by_gid(gid)
              .map(|g| g.name().to_owned())
              .unwrap_or(format!("{}", gid))
    }
}

/// What commands are needed to reproduce this tree of permissions?
fn display_commands(root: &Node) {
    let mut output = String::new();
    let mut path = vec![];
    let mut cache = NameCache::new();
    {
        let mut visit = |node: &Node, depth: usize| {
            if path.len() > depth {
                path.drain(depth..);
            }
            path.push(node.name.to_owned());
            let display_path = bash_encode(&path);
            if let Ok(ref data) = node.data {
                match (data.override_uid, data.override_gid) {
                    (Some(uid), Some(gid)) => {
                        output.push_str(&format!("chown -R {}:{} {}\n",
                                                 cache.display_uid(uid),
                                                 cache.display_gid(gid),
                                                 display_path));
                    },
                    (Some(uid), None) => {
                        output.push_str(&format!("chown -R {} {}\n",
                                                 cache.display_uid(uid),
                                                 display_path));
                    },
                    (None, Some(gid)) => {
                        output.push_str(&format!("chgrp -R {} {}\n",
                                                 cache.display_gid(gid),
                                                 display_path));
                    },
                    (None, None) => (),
                }
                if let Some(perms) = data.override_perms {
                    // an extra leading 0 tells GNU chmod that it's OK to remove
                    // setuid and setgid bits from directories.
                    output.push_str(&format!("chmod -R 0{:04o} {}\n", perms, display_path));
                }
            };
        };
        preorder_traversal(root, 0, &mut visit);
    }
    print!("{}", output);
}

fn main() {
    let args = parse_args();
    let mut paths = vec![];
    for name in args.directories {
        let path = Path::new(&name);
        if let Ok(fullpath) = fs::canonicalize(&path) {
            paths.push(fullpath);
        } else {
            println!(r#"permtree: error: where is "{}"?"#, name);
            return;
        }
    }
    
    for pathbuf in paths.iter() {
        let root = build_tree(&pathbuf, &None);
        if args.command_mode {
            display_commands(&root);
        } else {
            display_tree(&root);
        }
    }
}
