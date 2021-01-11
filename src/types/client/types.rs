use std::ffi::OsStr;
use std::net::Ipv4Addr;
use std::path::Path;
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

pub struct ClientHello {
    message_name: String,
    name: String,
    expected_version: f32,
}
// TODO not implemented ListPeer
pub struct ListPeer {
    message_name: String,
    node_identifier: NodeIdentifier,
    with_volatile: Option<bool>,
    with_metadata: Option<bool>,
}
pub struct ListPeers {
    message_name: String,
    with_volatile: Option<bool>,
    with_metadata: Option<bool>,
}

pub struct ListPeerNotes {
    message_name: String,
    node_identifier: NodeIdentifier,
}
pub struct AddPeer {
    message_name: String,
    trust: TrustLevel,
    visibility: VisibilityLevel,
    file: Option<String>,
    url: Option<String>,
    raw: Option<String>,
}
pub struct ModifyPeer {
    message_name: String,
    node_identifier: NodeIdentifier,
    allow_local_addresses: Option<bool>,
    is_disabled: Option<bool>,
    is_listen_only: Option<bool>,
    is_burst_only: Option<bool>,
    ignore_source_port: Option<bool>,
}
pub struct ModifyPeerNote {
    message_name: String,
    node_text: String,
    peer_note_type: i32,
}
pub struct RemovePeer {
    message_name: String,
    node_identifier: NodeIdentifier,
}

pub struct GetNode {
    message_name: String,
    identifier: Option<bool>,
    give_opennet_ref: Option<bool>,
    with_private: Option<bool>,
    with_volatile: Option<bool>,
}

pub struct GenerateSSK {
    message_name: String,
    identifier: Option<String>,
}

pub struct ClientPut {
    message_name: String,
    uri: String, //TODO create key type
    content_type: Option<String>,
    identifier: Option<String>,
    verbosity: Option<VerbosityPut>,
    max_retries: Option<Retry>,
    priority_class: Option<i8>,
    get_chk_only: Option<bool>,
    global: Option<bool>,
    dont_compress: Option<bool>,
    codecs: Option<Vec<String>>,
    client_token: Option<String>,
    persistence: Option<Box<OsStr>>,
    early_encode: Option<bool>,
    upload_ffrom: Option<UploadForm>,
    data_length: u64,
    filename: String,
    target_uri: Option<String>, // cloning  uri if does not exists
    file_hash: Option<String>,  //TODO SHAA256 type
    binary_blob: Option<bool>,
    fork_on_cacheable: Option<bool>,
    extra_inserts_single_block: Option<u32>,
    extra_inserts_splitfile_header_block: Option<u32>,
    compatibility_mode: Option<String>, //TODO create enum???
    local_request_only: Option<bool>,
    override_splitfile_crypto_key: Option<String>, //key in hex
    real_time_flag: Option<String>,
    metadata_threshold: Option<i64>,
    data: Option<String>, // Data fromdirect
}

pub struct ClientGet {
    message_name: String,
    ignore_ds: Option<bool>,
    ds_only: Option<bool>,
    uri: String, //FIXME freenet uri type
    identifier: String,
    verbosity: Option<VerbosityGet>,
    max_size: Option<u32>,
    max_retries: Option<NumOrNone>,
    priority_class: Option<Priority>,
    persistence: Option<Persistence>,
    client_token: Option<String>,
    global: Option<bool>,
    return_type: Option<ReturnType>,
    binary_blob: Option<bool>,
    filter_data: Option<bool>,
    allowed_mime_types: Option<Vec<String>>,
    filename: Option<Box<Path>>,
    temp_filename: Option<Box<Path>>,
    real_time_flag: Option<bool>,
    initial_metadata_data_length: u64,
}

pub struct Disconnect {
    message_name: String,
}

pub struct Shutdown {
    message_name: String,
}
