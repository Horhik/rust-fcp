pub mod traits;
use traits::*;
use regex::Regex;

#[derive(Debug, PartialEq)]
pub struct SSK {
    pub sign_key: String,
    pub decrypt_key: String,
    pub settings: Option<String>,
}
#[derive(Debug, PartialEq)]
pub struct USK {
    pub ssk: SSK,
    pub index: i32,
}

#[derive(Debug, PartialEq)]
pub struct SSKKeypair {
    pub insert_uri: SSK,
    pub request_uri: SSK,
    pub identifier: String,
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

