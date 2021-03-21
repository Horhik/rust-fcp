pub mod traits;
use regex::Regex;
use traits::*;

use rusqlite::types::ToSqlOutput;
use rusqlite::{Result, ToSql, types::{FromSql, ValueRef, FromSqlResult, FromSqlError}};

#[derive(Debug, PartialEq)]
pub struct SSK {
    pub sign_key: String,
    pub decrypt_key: String,
    pub settings: Option<String>,
}

impl ToSql for SSK {
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.convert()))
    }
}

impl FromSql for SSK{
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self>{
        match SSK::parse(value.as_str()?) {
            Some(res) => Ok(res),
            None => Err(FromSqlError::InvalidType)
        }
    }
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
    /// return the data directly to the client via an AllData message, once we have all of it. (For persistent requests, the client will get a DataFound message but must send a GetRequestStatus to ask for the AllData).
    Direct,
    ///  write the data to disk. If you download to disk, you have to do a TestDDARequest.
    None,
    /// don't return the data at all, just fetch it to the node and tell the client when we have finished.
    Disk,
}

impl FcpRequest for ReturnType {
    fn convert(&self) -> String {
        match self {
            ReturnType::Direct => "direct".to_string(),
            ReturnType::Disk => "disk".to_string(),
            ReturnType::None => "none".to_string(),
        }
    }
}
