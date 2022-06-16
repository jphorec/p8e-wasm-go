use p8e_attributes::{contract, function};
use proto::hello::{Hello, HelloResponse};
use protobuf::Message;

mod proto;

#[function(name = "test-record", invoked_by = "OWNER")]
fn greet_me(
    #[input(name = "proposedRecord")] proposed: proto::hello::Hello,
    #[record(name = "existingRecord")] existing: Hello,
    #[record(name = "existingOptionalRecord", optional = true)] existing_optional: Hello,
) -> HelloResponse {
    let mut response = HelloResponse::new();
    // response.request = request;
    response.response = format!(
        "Hi (proposed: {}, existing: {}, existing_optional: {})",
        proposed.name, existing.name, existing_optional.name
    );
    response
}

contract!();
