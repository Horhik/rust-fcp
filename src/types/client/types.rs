pub use std::ffi::OsStr;
pub use std::net::Ipv4Addr;
pub use std::path::Path;
pub enum NodeIdentifier {
    Name(String),
    Identity(String),
    Addr(Ipv4Addr),
}

pub enum TrustLevel {
    Low,
    Normal,
    High,
}

pub enum VisibilityLevel {
    No,
    NameOnly,
    Yes,
}
pub enum VerbosityPut {
    SimpleProgress,
    ExpectedHashes,
    PutFetchable,
    StartedCompressionANDFinishedCompression,
}
pub enum VerbosityGet {
    SimpleProgress,
    SendingToNetwork,
    CompatibilityMode,
    ExpectedHashes,
    ExpectedMIME,
    ExpectedDataLength,
}

pub enum Retry {
    None,
    Forever,
    Num(i32),
}

pub enum Persistence {
    Connection,
    Reboot,
    Forever,
}

pub enum UploadForm {
    Direct,
    Disk,
    Redirect,
}

pub enum ReturnType {
    Direct,
    None,
    Disk,
}

pub enum NumOrNone {
    None,
    Num(u32),
}

pub enum Priority {
    A, // 0
    B, // 1
    C, // 2
    D, // 3
    E, // 4
    F, // 5
    G, // 6
}
