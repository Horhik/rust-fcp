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

impl FcpRequest for VerbosityPut {
    fn parse(&self) -> String {
        match self {
            VerbosityPut::SimpleProgress => 0.to_string(),
            VerbosityPut::ExpectedHashes => 3.to_string(),
            VerbosityPut::PutFetchable => 8.to_string(),
            VerbosityPut::StartedCompressionANDFinishedCompression => 9.to_string(),
        }
    }
}

#[test]
fn is_berbosity_put_parsing() {
    assert_eq!(default_unwrap::<VerbosityPut>(None), "".to_string());
    assert_eq!(
        default_unwrap::<VerbosityPut>(Some(&VerbosityPut::SimpleProgress)),
        "0".to_string()
    );
    assert_eq!(
        default_unwrap::<VerbosityPut>(Some(&VerbosityPut::ExpectedHashes)),
        "3".to_string()
    );
    assert_eq!(
        default_unwrap::<VerbosityPut>(Some(&VerbosityPut::PutFetchable)),
        "8".to_string()
    );
    assert_eq!(
        default_unwrap::<VerbosityPut>(Some(
            &VerbosityPut::StartedCompressionANDFinishedCompression
        )),
        "9".to_string()
    );
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

impl FcpRequest for Persistence {
    fn parse(&self) -> String {
        match *self {
            Persistence::Connection => "connection".to_string(),
            Persistence::Reboot => "reboot".to_string(),
            Persistence::Forever => "forever".to_string(),
        }
    }
}

#[test]
fn is_persistence_parsing() {
    assert_eq!(
        default_unwrap(Some(&Persistence::Connection)),
        "connection".to_string()
    );
    assert_eq!(
        default_unwrap(Some(&Persistence::Reboot)),
        "reboot".to_string()
    );
    assert_eq!(
        default_unwrap(Some(&Persistence::Forever)),
        "forever".to_string()
    );
    assert_eq!(default_unwrap::<Persistence>(None), "".to_string());
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

pub trait FcpRequest {
    fn parse(&self) -> String;
}
pub fn default_unwrap<T: FcpRequest>(fcp_type: Option<&T>) -> String {
    match fcp_type {
        Some(val) => val.parse(),
        None => String::from(""),
    }
}
