use super::types::*;
use regex::Regex;

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
    identifier: Option<&'static String>,
}

impl FcpRequest for GenerateSSK {
    fn convert(&self) -> String {
        let identifier = to_fcp_unwrap("Identifier=", self.identifier, "\n");
        format!(
            "GenerateSSK\n\
                 {}\
                 EndMessage\n\n",
            identifier
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct SSK {
    sign_key: String,
    decrypt_key: String,
    settings: Option<String>,
}
#[derive(Debug, PartialEq)]
pub struct USK {
    ssk: SSK,
    index: i32,
}

#[derive(Debug, PartialEq)]
pub struct SSKKeypair {
    insert_uri: SSK,
    request_uri: SSK,
    identifier: String,
}

impl FcpParser<SSKKeypair> for SSKKeypair {
    fn parse(plain: &str) -> Option<SSKKeypair> {
        let reg = Regex::new(
            r"^SSKKeypair\nIdentifier=(.*)\nInsertURI=(.*)\nRequestURI=(.*)\nEndMessage",
        )
        .unwrap();
        println!("{:?}", reg);
        let res = reg.captures(plain).unwrap();
        let identifier = res[1].to_string();
        let insert_uri = SSK::parse(&res[2]).unwrap();
        let request_uri = SSK::parse(&res[3]).unwrap();
        return Some(SSKKeypair {
            insert_uri: insert_uri,
            request_uri: request_uri,
            identifier: identifier,
        });
    }
}

//SSK@Rgt0qM8D24DltliV2-JE9tYLcrgGAKeDwkz41I3JBPs,p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU,AQECAAE/
//SSK@uKTwaQIXNgsCYKLekb51t3pZ6A~PTP7nuCxRVZEMtCQ,p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU,AQACAAE/
/*
 SSKKeypair
 Identifier=34
 InsertURI=SSK@Rgt0qM8D24DltliV2-JE9tYLcrgGAKeDwkz41I3JBPs,p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU,AQECAAE/
 RequestURI=SSK@uKTwaQIXNgsCYKLekb51t3pZ6A~PTP7nuCxRVZEMtCQ,p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU,AQACAAE/
 EndMessage
*/
#[test]
fn is_keypair_parsing() {
    let parsed = SSKKeypair::parse("SSKKeypair\n\
                                    Identifier=name\n\
                                    InsertURI=SSK@Rgt0qM8D24DltliV2-JE9tYLcrgGAKeDwkz41I3JBPs,p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU,AQECAAE/\n\
                                    RequestURI=SSK@uKTwaQIXNgsCYKLekb51t3pZ6A~PTP7nuCxRVZEMtCQ,p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU,AQACAAE/\n\
                                    EndMessage\n");
    assert_eq!(
        SSKKeypair {
            insert_uri: SSK {
                sign_key: "Rgt0qM8D24DltliV2-JE9tYLcrgGAKeDwkz41I3JBPs".to_string(),
                decrypt_key: "p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU".to_string(),
                settings: Some("AQECAAE".to_string())
            },
            request_uri: SSK {
                sign_key: "uKTwaQIXNgsCYKLekb51t3pZ6A~PTP7nuCxRVZEMtCQ".to_string(),
                decrypt_key: "p~c8c7FXcJjhcf2vA-Xm0Mjyw1o~xn7L2-T8zlBA1IU".to_string(),
                settings: Some("AQACAAE".to_string()),
            },
            identifier: "name".to_string(),
        },
        parsed.unwrap()
    )
}

trait FcpParser<T> {
    fn parse(palin: &str) -> Option<T>;
}
impl FcpParser<SSK> for SSK {
    fn parse(plain: &str) -> Option<SSK> {
        let reg1 = Regex::new(r".*?SSK@([a-zA-z0-9~-]*),([a-zA-Z0-9-~]*),([A-Z]*)").unwrap();
        //let reg2 = Regex::new(r"^.*?\w{3}@(.*),(.*)/").unwrap();
        let reg2 = Regex::new(r".*?SSK@([a-zA-z0-9~-]*),([a-zA-Z0-9-~]*)").unwrap();
        match reg1.captures(plain) {
            Some(reg) => Some(SSK {
                sign_key: reg[1].to_string(),
                decrypt_key: reg[2].to_string(),
                settings: Some(reg[3].to_string()),
            }),
            None => match reg2.captures(plain) {
                Some(reg) => Some(SSK {
                    sign_key: reg[1].to_string(),
                    decrypt_key: reg[2].to_string(),
                    settings: None,
                }),
                None => None,
            },
        }
    }
}

#[test]
fn is_ssk_parsing() {
    // SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM/
    // SSK@BnHXXv3Fa43w~~iz1tNUd~cj4OpUuDjVouOWZ5XlpX0,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM,AQABAAE
    let ssk = SSK::parse("SSK@AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM/").unwrap();
    let ssk2 = SSK::parse("SSK@BnHXXv3Fa43w~~iz1tNUd~cj4OpUuDjVouOWZ5XlpX0,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM,AQABAAE").unwrap();

    assert_eq!(
        ssk,
        SSK {
            sign_key: "AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: None
        }
    );
    assert_eq!(
        ssk2,
        SSK {
            sign_key: "BnHXXv3Fa43w~~iz1tNUd~cj4OpUuDjVouOWZ5XlpX0".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: Some("AQABAAE".to_string()),
        }
    );
}

impl FcpRequest for SSK {
    fn convert(&self) -> String {
        unimplemented!();
    }
}

#[test]
fn is_ssk_converting() {
    assert_eq!(SSK {
            sign_key: "AKTTKG6YwjrHzWo67laRcoPqibyiTdyYufjVg54fBlWr".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: None
        }.convert(), "SSK@BnHXXv3Fa43w~~iz1tNUd~cj4OpUuDjVouOWZ5XlpX0,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM,AQABAAE");
    assert_eq!(SSK {
            sign_key: "BnHXXv3Fa43w~~iz1tNUd~cj4OpUuDjVouOWZ5XlpX0".to_string(),
            decrypt_key: "AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM".to_string(),
            settings: Some("AQABAAE".to_string()),
        }.convert(), "SSK@BnHXXv3Fa43w~~iz1tNUd~cj4OpUuDjVouOWZ5XlpX0,AwUSJG5ZS-FDZTqnt6skTzhxQe08T-fbKXj8aEHZsXM,AQABAAE")
}

impl SSKKeypair {
    /*
    fn parse(plain: String) -> Self {
        let lines = plain.lines();
        let insert_uri = lines.next().unwrap_or("");
        let request_uri = lines.next().unwrap_or("");
        let identifier = lines.next().unwrap_or("");
    }
    */
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
