// This file is generated by rust-protobuf 3.0.3. Do not edit
// .proto file is parsed by protoc 3.17.3
// @generated

// https://github.com/rust-lang/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![allow(unused_attributes)]
#![cfg_attr(rustfmt, rustfmt::skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unused_results)]
#![allow(unused_mut)]

//! Generated file from `wasm.proto`

/// Generated files are compatible only with the same version
/// of protobuf runtime.
const _PROTOBUF_VERSION_CHECK: () = ::protobuf::VERSION_3_0_3;

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:io.provenance.scope.encryption.EncryptRequest)
pub struct EncryptRequest {
    // message fields
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.EncryptRequest.uuid)
    pub uuid: ::protobuf::MessageField<super::util::UUID>,
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.EncryptRequest.payload)
    pub payload: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.EncryptRequest.owner_public_key)
    pub owner_public_key: ::std::vec::Vec<u8>,
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.EncryptRequest.audience_public_key)
    pub audience_public_key: ::std::vec::Vec<::std::vec::Vec<u8>>,
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.EncryptRequest.metadata)
    pub metadata: ::std::collections::HashMap<::std::string::String, ::std::string::String>,
    // special fields
    // @@protoc_insertion_point(special_field:io.provenance.scope.encryption.EncryptRequest.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a EncryptRequest {
    fn default() -> &'a EncryptRequest {
        <EncryptRequest as ::protobuf::Message>::default_instance()
    }
}

impl EncryptRequest {
    pub fn new() -> EncryptRequest {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(5);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::util::UUID>(
            "uuid",
            |m: &EncryptRequest| { &m.uuid },
            |m: &mut EncryptRequest| { &mut m.uuid },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "payload",
            |m: &EncryptRequest| { &m.payload },
            |m: &mut EncryptRequest| { &mut m.payload },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "owner_public_key",
            |m: &EncryptRequest| { &m.owner_public_key },
            |m: &mut EncryptRequest| { &mut m.owner_public_key },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_vec_simpler_accessor::<_, _>(
            "audience_public_key",
            |m: &EncryptRequest| { &m.audience_public_key },
            |m: &mut EncryptRequest| { &mut m.audience_public_key },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_map_simpler_accessor::<_, _, _>(
            "metadata",
            |m: &EncryptRequest| { &m.metadata },
            |m: &mut EncryptRequest| { &mut m.metadata },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<EncryptRequest>(
            "EncryptRequest",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for EncryptRequest {
    const NAME: &'static str = "EncryptRequest";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.uuid)?;
                },
                18 => {
                    self.payload = is.read_bytes()?;
                },
                26 => {
                    self.owner_public_key = is.read_bytes()?;
                },
                34 => {
                    self.audience_public_key.push(is.read_bytes()?);
                },
                42 => {
                    let len = is.read_raw_varint32()?;
                    let old_limit = is.push_limit(len as u64)?;
                    let mut key = ::std::default::Default::default();
                    let mut value = ::std::default::Default::default();
                    while let Some(tag) = is.read_raw_tag_or_eof()? {
                        match tag {
                            10 => key = is.read_string()?,
                            18 => value = is.read_string()?,
                            _ => ::protobuf::rt::skip_field_for_tag(tag, is)?,
                        };
                    }
                    is.pop_limit(old_limit);
                    self.metadata.insert(key, value);
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.uuid.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if !self.payload.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.payload);
        }
        if !self.owner_public_key.is_empty() {
            my_size += ::protobuf::rt::bytes_size(3, &self.owner_public_key);
        }
        for value in &self.audience_public_key {
            my_size += ::protobuf::rt::bytes_size(4, &value);
        };
        for (k, v) in &self.metadata {
            let mut entry_size = 0;
            entry_size += ::protobuf::rt::string_size(1, &k);
            entry_size += ::protobuf::rt::string_size(2, &v);
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(entry_size) + entry_size
        };
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.uuid.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        if !self.payload.is_empty() {
            os.write_bytes(2, &self.payload)?;
        }
        if !self.owner_public_key.is_empty() {
            os.write_bytes(3, &self.owner_public_key)?;
        }
        for v in &self.audience_public_key {
            os.write_bytes(4, &v)?;
        };
        for (k, v) in &self.metadata {
            let mut entry_size = 0;
            entry_size += ::protobuf::rt::string_size(1, &k);
            entry_size += ::protobuf::rt::string_size(2, &v);
            os.write_raw_varint32(42)?; // Tag.
            os.write_raw_varint32(entry_size as u32)?;
            os.write_string(1, &k)?;
            os.write_string(2, &v)?;
        };
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> EncryptRequest {
        EncryptRequest::new()
    }

    fn clear(&mut self) {
        self.uuid.clear();
        self.payload.clear();
        self.owner_public_key.clear();
        self.audience_public_key.clear();
        self.metadata.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static EncryptRequest {
        static instance: ::protobuf::rt::Lazy<EncryptRequest> = ::protobuf::rt::Lazy::new();
        instance.get(EncryptRequest::new)
    }
}

impl ::protobuf::MessageFull for EncryptRequest {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("EncryptRequest").unwrap()).clone()
    }
}

impl ::std::fmt::Display for EncryptRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncryptRequest {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:io.provenance.scope.encryption.EncryptResponse)
pub struct EncryptResponse {
    // message fields
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.EncryptResponse.dime)
    pub dime: ::protobuf::MessageField<super::encryption::DIME>,
    // special fields
    // @@protoc_insertion_point(special_field:io.provenance.scope.encryption.EncryptResponse.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a EncryptResponse {
    fn default() -> &'a EncryptResponse {
        <EncryptResponse as ::protobuf::Message>::default_instance()
    }
}

impl EncryptResponse {
    pub fn new() -> EncryptResponse {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::encryption::DIME>(
            "dime",
            |m: &EncryptResponse| { &m.dime },
            |m: &mut EncryptResponse| { &mut m.dime },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<EncryptResponse>(
            "EncryptResponse",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for EncryptResponse {
    const NAME: &'static str = "EncryptResponse";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.dime)?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.dime.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.dime.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> EncryptResponse {
        EncryptResponse::new()
    }

    fn clear(&mut self) {
        self.dime.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static EncryptResponse {
        static instance: EncryptResponse = EncryptResponse {
            dime: ::protobuf::MessageField::none(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for EncryptResponse {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("EncryptResponse").unwrap()).clone()
    }
}

impl ::std::fmt::Display for EncryptResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for EncryptResponse {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:io.provenance.scope.encryption.DecryptRequest)
pub struct DecryptRequest {
    // message fields
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.DecryptRequest.dime)
    pub dime: ::protobuf::MessageField<super::encryption::DIME>,
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.DecryptRequest.private_key)
    pub private_key: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:io.provenance.scope.encryption.DecryptRequest.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a DecryptRequest {
    fn default() -> &'a DecryptRequest {
        <DecryptRequest as ::protobuf::Message>::default_instance()
    }
}

impl DecryptRequest {
    pub fn new() -> DecryptRequest {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(2);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_message_field_accessor::<_, super::encryption::DIME>(
            "dime",
            |m: &DecryptRequest| { &m.dime },
            |m: &mut DecryptRequest| { &mut m.dime },
        ));
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "private_key",
            |m: &DecryptRequest| { &m.private_key },
            |m: &mut DecryptRequest| { &mut m.private_key },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<DecryptRequest>(
            "DecryptRequest",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for DecryptRequest {
    const NAME: &'static str = "DecryptRequest";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    ::protobuf::rt::read_singular_message_into_field(is, &mut self.dime)?;
                },
                18 => {
                    self.private_key = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if let Some(v) = self.dime.as_ref() {
            let len = v.compute_size();
            my_size += 1 + ::protobuf::rt::compute_raw_varint64_size(len) + len;
        }
        if !self.private_key.is_empty() {
            my_size += ::protobuf::rt::bytes_size(2, &self.private_key);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if let Some(v) = self.dime.as_ref() {
            ::protobuf::rt::write_message_field_with_cached_size(1, v, os)?;
        }
        if !self.private_key.is_empty() {
            os.write_bytes(2, &self.private_key)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> DecryptRequest {
        DecryptRequest::new()
    }

    fn clear(&mut self) {
        self.dime.clear();
        self.private_key.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static DecryptRequest {
        static instance: DecryptRequest = DecryptRequest {
            dime: ::protobuf::MessageField::none(),
            private_key: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for DecryptRequest {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("DecryptRequest").unwrap()).clone()
    }
}

impl ::std::fmt::Display for DecryptRequest {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for DecryptRequest {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

#[derive(PartialEq,Clone,Default,Debug)]
// @@protoc_insertion_point(message:io.provenance.scope.encryption.DecryptResponse)
pub struct DecryptResponse {
    // message fields
    // @@protoc_insertion_point(field:io.provenance.scope.encryption.DecryptResponse.payload)
    pub payload: ::std::vec::Vec<u8>,
    // special fields
    // @@protoc_insertion_point(special_field:io.provenance.scope.encryption.DecryptResponse.special_fields)
    pub special_fields: ::protobuf::SpecialFields,
}

impl<'a> ::std::default::Default for &'a DecryptResponse {
    fn default() -> &'a DecryptResponse {
        <DecryptResponse as ::protobuf::Message>::default_instance()
    }
}

impl DecryptResponse {
    pub fn new() -> DecryptResponse {
        ::std::default::Default::default()
    }

    fn generated_message_descriptor_data() -> ::protobuf::reflect::GeneratedMessageDescriptorData {
        let mut fields = ::std::vec::Vec::with_capacity(1);
        let mut oneofs = ::std::vec::Vec::with_capacity(0);
        fields.push(::protobuf::reflect::rt::v2::make_simpler_field_accessor::<_, _>(
            "payload",
            |m: &DecryptResponse| { &m.payload },
            |m: &mut DecryptResponse| { &mut m.payload },
        ));
        ::protobuf::reflect::GeneratedMessageDescriptorData::new_2::<DecryptResponse>(
            "DecryptResponse",
            fields,
            oneofs,
        )
    }
}

impl ::protobuf::Message for DecryptResponse {
    const NAME: &'static str = "DecryptResponse";

    fn is_initialized(&self) -> bool {
        true
    }

    fn merge_from(&mut self, is: &mut ::protobuf::CodedInputStream<'_>) -> ::protobuf::Result<()> {
        while let Some(tag) = is.read_raw_tag_or_eof()? {
            match tag {
                10 => {
                    self.payload = is.read_bytes()?;
                },
                tag => {
                    ::protobuf::rt::read_unknown_or_skip_group(tag, is, self.special_fields.mut_unknown_fields())?;
                },
            };
        }
        ::std::result::Result::Ok(())
    }

    // Compute sizes of nested messages
    #[allow(unused_variables)]
    fn compute_size(&self) -> u64 {
        let mut my_size = 0;
        if !self.payload.is_empty() {
            my_size += ::protobuf::rt::bytes_size(1, &self.payload);
        }
        my_size += ::protobuf::rt::unknown_fields_size(self.special_fields.unknown_fields());
        self.special_fields.cached_size().set(my_size as u32);
        my_size
    }

    fn write_to_with_cached_sizes(&self, os: &mut ::protobuf::CodedOutputStream<'_>) -> ::protobuf::Result<()> {
        if !self.payload.is_empty() {
            os.write_bytes(1, &self.payload)?;
        }
        os.write_unknown_fields(self.special_fields.unknown_fields())?;
        ::std::result::Result::Ok(())
    }

    fn special_fields(&self) -> &::protobuf::SpecialFields {
        &self.special_fields
    }

    fn mut_special_fields(&mut self) -> &mut ::protobuf::SpecialFields {
        &mut self.special_fields
    }

    fn new() -> DecryptResponse {
        DecryptResponse::new()
    }

    fn clear(&mut self) {
        self.payload.clear();
        self.special_fields.clear();
    }

    fn default_instance() -> &'static DecryptResponse {
        static instance: DecryptResponse = DecryptResponse {
            payload: ::std::vec::Vec::new(),
            special_fields: ::protobuf::SpecialFields::new(),
        };
        &instance
    }
}

impl ::protobuf::MessageFull for DecryptResponse {
    fn descriptor() -> ::protobuf::reflect::MessageDescriptor {
        static descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::MessageDescriptor> = ::protobuf::rt::Lazy::new();
        descriptor.get(|| file_descriptor().message_by_package_relative_name("DecryptResponse").unwrap()).clone()
    }
}

impl ::std::fmt::Display for DecryptResponse {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        ::protobuf::text_format::fmt(self, f)
    }
}

impl ::protobuf::reflect::ProtobufValue for DecryptResponse {
    type RuntimeType = ::protobuf::reflect::rt::RuntimeTypeMessage<Self>;
}

static file_descriptor_proto_data: &'static [u8] = b"\
    \n\nwasm.proto\x12\x1eio.provenance.scope.encryption\x1a\nutil.proto\x1a\
    \x10encryption.proto\"\xca\x02\n\x0eEncryptRequest\x12-\n\x04uuid\x18\
    \x01\x20\x01(\x0b2\x19.io.provenance.scope.UUIDR\x04uuid\x12\x18\n\x07pa\
    yload\x18\x02\x20\x01(\x0cR\x07payload\x12(\n\x10owner_public_key\x18\
    \x03\x20\x01(\x0cR\x0eownerPublicKey\x12.\n\x13audience_public_key\x18\
    \x04\x20\x03(\x0cR\x11audiencePublicKey\x12X\n\x08metadata\x18\x05\x20\
    \x03(\x0b2<.io.provenance.scope.encryption.EncryptRequest.MetadataEntryR\
    \x08metadata\x1a;\n\rMetadataEntry\x12\x10\n\x03key\x18\x01\x20\x01(\tR\
    \x03key\x12\x14\n\x05value\x18\x02\x20\x01(\tR\x05value:\x028\x01\"K\n\
    \x0fEncryptResponse\x128\n\x04dime\x18\x01\x20\x01(\x0b2$.io.provenance.\
    scope.encryption.DIMER\x04dime\"k\n\x0eDecryptRequest\x128\n\x04dime\x18\
    \x01\x20\x01(\x0b2$.io.provenance.scope.encryption.DIMER\x04dime\x12\x1f\
    \n\x0bprivate_key\x18\x02\x20\x01(\x0cR\nprivateKey\"+\n\x0fDecryptRespo\
    nse\x12\x18\n\x07payload\x18\x01\x20\x01(\x0cR\x07payloadb\x06proto3\
";

/// `FileDescriptorProto` object which was a source for this generated file
fn file_descriptor_proto() -> &'static ::protobuf::descriptor::FileDescriptorProto {
    static file_descriptor_proto_lazy: ::protobuf::rt::Lazy<::protobuf::descriptor::FileDescriptorProto> = ::protobuf::rt::Lazy::new();
    file_descriptor_proto_lazy.get(|| {
        ::protobuf::Message::parse_from_bytes(file_descriptor_proto_data).unwrap()
    })
}

/// `FileDescriptor` object which allows dynamic access to files
pub fn file_descriptor() -> &'static ::protobuf::reflect::FileDescriptor {
    static generated_file_descriptor_lazy: ::protobuf::rt::Lazy<::protobuf::reflect::GeneratedFileDescriptor> = ::protobuf::rt::Lazy::new();
    static file_descriptor: ::protobuf::rt::Lazy<::protobuf::reflect::FileDescriptor> = ::protobuf::rt::Lazy::new();
    file_descriptor.get(|| {
        let generated_file_descriptor = generated_file_descriptor_lazy.get(|| {
            let mut deps = ::std::vec::Vec::with_capacity(2);
            deps.push(super::util::file_descriptor().clone());
            deps.push(super::encryption::file_descriptor().clone());
            let mut messages = ::std::vec::Vec::with_capacity(4);
            messages.push(EncryptRequest::generated_message_descriptor_data());
            messages.push(EncryptResponse::generated_message_descriptor_data());
            messages.push(DecryptRequest::generated_message_descriptor_data());
            messages.push(DecryptResponse::generated_message_descriptor_data());
            let mut enums = ::std::vec::Vec::with_capacity(0);
            ::protobuf::reflect::GeneratedFileDescriptor::new_generated(
                file_descriptor_proto(),
                deps,
                messages,
                enums,
            )
        });
        ::protobuf::reflect::FileDescriptor::new_generated_2(generated_file_descriptor)
    })
}
