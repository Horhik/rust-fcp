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
    fn convert(&self) -> String {
        match self {
            VerbosityPut::SimpleProgress => 0.to_string(),
            VerbosityPut::ExpectedHashes => 3.to_string(),
            VerbosityPut::PutFetchable => 8.to_string(),
            VerbosityPut::StartedCompressionANDFinishedCompression => 9.to_string(),
        }
    }
}

#[test]
fn is_berbosity_put_converting() {
    assert_eq!(fcp_types_unwrap::<VerbosityPut>(None), "".to_string());
    assert_eq!(
        fcp_types_unwrap::<VerbosityPut>(Some(&VerbosityPut::SimpleProgress)),
        "0".to_string()
    );
    assert_eq!(
        fcp_types_unwrap::<VerbosityPut>(Some(&VerbosityPut::ExpectedHashes)),
        "3".to_string()
    );
    assert_eq!(
        fcp_types_unwrap::<VerbosityPut>(Some(&VerbosityPut::PutFetchable)),
        "8".to_string()
    );
    assert_eq!(
        fcp_types_unwrap::<VerbosityPut>(Some(
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

impl FcpRequest for VerbosityGet {
    fn convert(&self) -> String {
        unimplemented!();
    }
}

pub enum Retry {
    None,
    Forever,
    Num(i32),
}
impl FcpRequest for Retry {
    fn convert(&self) -> String {
        match self {
            Retry::None => "0".to_string(),
            Retry::Forever => "-1".to_string(),
            Retry::Num(num) => num.to_string(),
        }
    }
}

pub enum Persistence {
    Connection,
    Reboot,
    Forever,
}

impl FcpRequest for Persistence {
    fn convert(&self) -> String {
        match *self {
            Persistence::Connection => "connection".to_string(),
            Persistence::Reboot => "reboot".to_string(),
            Persistence::Forever => "forever".to_string(),
        }
    }
}

#[test]
fn is_persistence_converting() {
    assert_eq!(
        fcp_types_unwrap(Some(&Persistence::Connection)),
        "connection".to_string()
    );
    assert_eq!(
        fcp_types_unwrap(Some(&Persistence::Reboot)),
        "reboot".to_string()
    );
    assert_eq!(
        fcp_types_unwrap(Some(&Persistence::Forever)),
        "forever".to_string()
    );
    assert_eq!(fcp_types_unwrap::<Persistence>(None), "".to_string());
}

pub enum UploadForm {
    Direct,
    Disk,
    Redirect,
}
impl FcpRequest for UploadForm {
    fn convert(&self) -> String {
        match *self {
            UploadForm::Direct => "direct".to_string(),
            UploadForm::Disk => "disk".to_string(),
            UploadForm::Redirect => "redirect".to_string(),
        }
    }
}

#[test]
fn is_upload_from_converting() {
    assert_eq!(
        fcp_types_unwrap(Some(&UploadForm::Direct)),
        "direct".to_string()
    );
    assert_eq!(
        fcp_types_unwrap(Some(&UploadForm::Disk)),
        "disk".to_string()
    );
    assert_eq!(
        fcp_types_unwrap(Some(&UploadForm::Redirect)),
        "redirect".to_string()
    );
    assert_eq!(fcp_types_unwrap::<Persistence>(None), "".to_string());
}

pub enum ReturnType {
    Direct,
    None,
    Disk,
}

impl FcpRequest for ReturnType {
    fn convert(&self) -> String {
        unimplemented!();
    }
}

pub enum NumOrNone {
    None,
    Num(u32),
}
impl FcpRequest for NumOrNone {
    fn convert(&self) -> String {
        unimplemented!();
    }
}

impl FcpRequest for Vec<String> {
    fn convert(&self) -> String {
        unimplemented!();
    }
}
impl FcpRequest for Box<Path> {
    fn convert(&self) -> String {
        unimplemented!();
    }
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

impl FcpRequest for Priority {
    fn convert(&self) -> String {
        match *self {
            Priority::A => "0".to_string(),
            Priority::B => "1".to_string(),
            Priority::C => "2".to_string(),
            Priority::D => "3".to_string(),
            Priority::E => "4".to_string(),
            Priority::F => "5".to_string(),
            Priority::G => "6".to_string(),
        }
    }
}
#[test]
fn is_priority_converting() {
    assert_eq!(fcp_types_unwrap(Some(&Priority::A)), "0".to_string());
    assert_eq!(fcp_types_unwrap(Some(&Priority::B)), "1".to_string());
    assert_eq!(fcp_types_unwrap(Some(&Priority::C)), "2".to_string());
    assert_eq!(fcp_types_unwrap(Some(&Priority::D)), "3".to_string());
    assert_eq!(fcp_types_unwrap(Some(&Priority::E)), "4".to_string());
    assert_eq!(fcp_types_unwrap(Some(&Priority::F)), "5".to_string());
    assert_eq!(fcp_types_unwrap(Some(&Priority::G)), "6".to_string());
    assert_eq!(fcp_types_unwrap::<Priority>(None), "".to_string());
}

impl FcpRequest for u32 {
    fn convert(&self) -> String {
        self.to_string()
    }
}
impl FcpRequest for i64 {
    fn convert(&self) -> String {
        self.to_string()
    }
}
impl FcpRequest for u64 {
    fn convert(&self) -> String {
        self.to_string()
    }
}
impl FcpRequest for String {
    fn convert(&self) -> String {
        self.to_string()
    }
}
impl FcpRequest for &String {
    fn convert(&self) -> String {
        self.to_string()
    }
}

impl FcpRequest for bool {
    fn convert(&self) -> String {
        if *self {
            "true".to_string()
        } else {
            "false".to_string()
        }
    }
}

pub trait FcpRequest {
    fn convert(&self) -> String;

    fn fcp_wrap(&self, prefix: &str, postfix: &str) -> String {
        format!("{}{}{}", prefix, self.convert(), postfix)
    }
}
pub fn fcp_types_unwrap<T: FcpRequest>(fcp_type: Option<&T>) -> String {
    match fcp_type {
        Some(val) => val.convert(),
        None => String::from(""),
    }
}
pub fn to_fcp_unwrap<T: FcpRequest>(prefix: &str, fcp_type: &Option<T>, postfix: &str) -> String {
    match fcp_type {
        Some(val) => val.fcp_wrap(&prefix, &postfix),
        None => String::from(""),
    }
}
