use itertools::Itertools;
use std::collections::BTreeMap;
use std::process::Command;
use strum::{EnumIter, IntoEnumIterator};

pub fn lsof() -> Vec<Process> {
    let stdout = Command::new("lsof")
        .args(["-nP", "-F", "pcTPn0R", "-i"])
        .output()
        .unwrap()
        .stdout;
    parse_lsof_output(&stdout)
}

fn parse_lsof_output(out: &[u8]) -> Vec<Process> {
    let mut processes: Vec<Process> = Vec::new();

    let all_attribute_sets = out.split(|&x| x == b'\n').map(parse_lsof_line);
    let mut process_attributes = Vec::new();
    for attribute_set in all_attribute_sets {
        // New process! Handle the previous one and clear
        if attribute_set.contains_key(&FieldType::Pid) {
            processes.extend(process_set(&process_attributes));
            process_attributes.clear();
        }
        process_attributes.push(attribute_set);
    }
    // Process remaining attributes
    processes.extend(process_set(&process_attributes));

    processes
}

fn process_set(x: &[BTreeMap<FieldType, &str>]) -> Option<Process> {
    let mut attributes = x.iter();

    // Process is always the first
    let process = attributes.next()?;
    let pid = process.get(&FieldType::Pid)?.parse().ok()?;
    let command = process.get(&FieldType::Command)?;

    let ports = attributes
        .flat_map(|set| {
            let network = set.get(&FieldType::Network)?;
            let tcp = *set.get(&FieldType::TcpState)?;
            if tcp == "LISTEN" {
                Some(network.to_string())
            } else {
                None
            }
        })
        .unique()
        .collect();

    Some(Process {
        pid,
        command: command.to_string(),
        ports,
    })
}

#[derive(Debug)]
pub struct Process {
    pub pid: usize,
    pub command: String,
    pub ports: Vec<String>,
}

#[derive(Copy, Clone, EnumIter, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
enum FieldType {
    Pid,
    Command,
    Network,
    TcpState,
}

impl FieldType {
    fn prefix(self) -> &'static str {
        match self {
            FieldType::Pid => "p",
            FieldType::Command => "c",
            FieldType::Network => "n",
            FieldType::TcpState => "TST=",
        }
    }
}

fn parse_lsof_line(line: &[u8]) -> BTreeMap<FieldType, &str> {
    line.split(|&x| x == b'\0')
        .filter_map(parse_lsof_part)
        .collect()
}

fn parse_lsof_part(part: &[u8]) -> Option<(FieldType, &str)> {
    for field in FieldType::iter() {
        let prefix = field.prefix().as_bytes();
        if let Some(part) = part.strip_prefix(prefix) {
            let text = str::from_utf8(part).ok()?;
            return Some((field, text));
        }
    }
    None
}
