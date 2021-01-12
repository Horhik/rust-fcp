use super::types::*;

impl ClientHello {
    fn new(name: String, exp_ver: f32) -> Self {
        ClientHello {
            name: name,
            expected_version: exp_ver,
        }
    }
}

impl FcpRequest for ClientHello {
    fn convert(&self) -> String {
        return format!(
            "ClientHello\n\
             Name={}\n\
             ExpectedVersion={}\n\
             EndMessage\n\n",
            self.name, self.expected_version
        );
    }
}

pub struct ClientHello {
    name: String,
    expected_version: f32,
}

#[test]
fn client_hello_converts() {
    let hello = ClientHello::new("user name".to_string(), 2.0);
    assert_eq!(
        hello.convert(),
        "ClientHello\nName=user name\nExpectedVersion=2\nEndMessage\n\n"
    );
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
    uri: String, //TODO create key type
    data_length: u64,
    filename: String,
    content_type: Option<&'static String>,
    identifier: Option<&'static String>,
    verbosity: Option<&'static VerbosityPut>,
    max_retries: Option<&'static Retry>,
    priority_class: Option<&'static Priority>,
    get_chk_only: Option<&'static bool>,
    global: Option<&'static bool>,
    dont_compress: Option<&'static bool>,
    codecs: Option<&'static String>, // TODO turn into vec and add implementation
    client_token: Option<&'static String>,
    persistence: Option<&'static Persistence>,
    target_filename: Option<&'static String>, // TODO create filename type (&'static not PATH, ONLY SLASHES)
    early_encode: Option<&'static bool>,
    upload_ffrom: Option<&'static UploadForm>,
    target_uri: Option<&'static String>, // cloning  uri if does not exists
    file_hash: Option<&'static String>,  //TODO SHAA256 type
    binary_blob: Option<&'static bool>,
    fork_on_cacheable: Option<&'static bool>,
    extra_inserts_single_block: Option<&'static u32>,
    extra_inserts_splitfile_header_block: Option<&'static u32>,
    compatibility_mode: Option<&'static String>, //TODO create enum???
    local_request_only: Option<&'static bool>,
    override_splitfile_crypto_key: Option<&'static String>, //key in hex
    real_time_flag: Option<&'static String>,
    metadata_threshold: Option<&'static i64>,
    data: Option<&'static String>, // Data fromdirect
}
impl FcpRequest for ClientPut {
    fn convert(&self) -> String {
        let content_type = to_fcp_unwrap("ContentType=", self.content_type, "\n");
        let identifier = to_fcp_unwrap("Identifier=", self.identifier, "\n");
        let verbosity = to_fcp_unwrap("=", self.verbosity, "\n");
        let max_retries = to_fcp_unwrap("=", self.max_retries, "\n");
        let priority_class = to_fcp_unwrap("=", self.priority_class, "\n");
        let get_chk_only = to_fcp_unwrap("=", self.get_chk_only, "\n");
        let global = to_fcp_unwrap("=", self.global, "\n");
        let dont_compress = to_fcp_unwrap("=", self.dont_compress, "\n");
        let codecs = to_fcp_unwrap("=", self.codecs, "\n");
        let client_token = to_fcp_unwrap("=", self.client_token, "\n");
        let persistence = to_fcp_unwrap("=", self.persistence, "\n");
        let target_filename = to_fcp_unwrap("=", self.target_filename, "\n");
        let early_encode = to_fcp_unwrap("=", self.early_encode, "\n");
        let upload_ffrom = to_fcp_unwrap("=", self.upload_ffrom, "\n");
        let target_uri = to_fcp_unwrap("=", self.target_uri, "\n");
        let file_hash = to_fcp_unwrap("=", self.file_hash, "\n");
        let binary_blob = to_fcp_unwrap("=", self.binary_blob, "\n");
        let fork_on_cacheable = to_fcp_unwrap("=", self.fork_on_cacheable, "\n");
        let extra_inserts_single_block = to_fcp_unwrap("=", self.extra_inserts_single_block, "\n");
        let extra_inserts_splitfile_header_block =
            to_fcp_unwrap("=", self.extra_inserts_splitfile_header_block, "\n");
        let compatibility_mode = to_fcp_unwrap("=", self.compatibility_mode, "\n");
        let local_request_only = to_fcp_unwrap("=", self.local_request_only, "\n");
        let override_splitfile_crypto_key =
            to_fcp_unwrap("=", self.override_splitfile_crypto_key, "\n");
        let real_time_flag = to_fcp_unwrap("=", self.real_time_flag, "\n");
        let metadata_threshold = to_fcp_unwrap("=", self.metadata_threshold, "\n");
        let data = to_fcp_unwrap("=", self.data, "\n");

        format!(
            "ClientPut\n\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 {}\
                 EndMessage\n\
                 {}\
                 ",
            format!("URI={}\n", self.uri),
            format!("DataLength={}\n", self.data_length),
            format!("Filename={}\n", self.filename),
            content_type,
            identifier,
            verbosity,
            max_retries,
            priority_class,
            get_chk_only,
            global,
            dont_compress,
            codecs,
            client_token,
            persistence,
            target_filename,
            early_encode,
            upload_ffrom,
            target_uri,
            file_hash,
            binary_blob,
            fork_on_cacheable,
            extra_inserts_single_block,
            extra_inserts_splitfile_header_block,
            compatibility_mode,
            local_request_only,
            override_splitfile_crypto_key,
            real_time_flag,
            metadata_threshold,
            data,
            // to_fcp_unwrap("Verbosity", self.verbosity, "\n"),
        )
    }
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
