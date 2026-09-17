//! The request surface: what a method answers with, who it answers, and how
//! much of it one caller gets.

use manapds::xrpc::{Error, Status};

#[test]
fn an_error_falls_back_to_the_name_of_its_status() {
    let error = Error::new(Status::MethodNotImplemented);
    assert_eq!(error.name(), "MethodNotImplemented");
    assert_eq!(error.message(), "Method Not Implemented");
}

#[test]
fn a_lexicon_name_is_what_the_client_branches_on() {
    let error = Error::invalid_request("Token has expired").named("ExpiredToken");
    assert_eq!(error.status(), Status::InvalidRequest);
    assert_eq!(error.name(), "ExpiredToken");
    assert_eq!(error.message(), "Token has expired");
}

#[test]
fn a_fault_on_this_side_is_never_described() {
    let error = Error::internal("the database is on fire");
    assert_eq!(error.name(), "InternalServerError");
    assert_eq!(error.message(), "Internal Server Error");
}
