use p8e_attributes::{p8e_contract, p8e_function, p8e_scope_specification};
use proto::hello::{Hello, HelloResponse};
use protobuf::Message;

mod proto;

#[p8e_function(name = "test-record", invoked_by = "OWNER")]
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

#[p8e_function(name = "test-record-2", invoked_by = "OWNER")]
fn greet_me_2(
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

p8e_contract!(
    scope_specifications = ["auto_loan"],
    participants = [Participants::OWNER, Participants::SERVICER]
);

p8e_scope_specification!(
    uuid = "a361e9f9-d693-43ea-bb7b-e0e122960436",
    name = "",
    description = "",
    party = "OWNER",
    website_url = ""
);
