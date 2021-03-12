
pub trait FcpRequest {
    fn convert(&self) -> String;

    fn fcp_wrap(&self, prefix: &str, postfix: &str) -> String {
        format!("{}{}{}", prefix, self.convert(), postfix)
    }
}


pub trait FcpParser<T> {
    fn parse(palin: &str) -> Option<T>;
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


