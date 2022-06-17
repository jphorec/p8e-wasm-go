use core::panic;
use darling::{FromMeta, ToTokens};
use p8e_helpers::Participants;
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use serde::Serialize;
use std::{error::Error, str::FromStr};
use syn::{
    parse::{Parse, ParseStream, Parser},
    parse_macro_input,
    punctuated::Punctuated,
    token::Comma,
    Attribute, AttributeArgs, Ident, ItemFn, Lit, LitStr, Meta, NestedMeta, PatType, Path,
    PathSegment, Signature, Token,
};

#[derive(Debug, Serialize, Clone)]
struct P8eFunctionDetails {
    name: String,
    invoked_by: Participants,
    parameters: Vec<P8eInputOrRecord>,
}

#[derive(Debug, FromMeta, Serialize, Clone)]
struct P8eRecordArgs {
    name: String,
    optional: Option<bool>,
}

#[derive(Debug, FromMeta, Serialize, Clone)]
struct P8eInputArgs {
    name: String,
}

#[derive(Debug, Serialize, Clone)]
enum RecordType {
    Existing,
    Proposed,
}

impl From<String> for RecordType {
    fn from(record_type: String) -> Self {
        match record_type.as_str() {
            "record" => Self::Existing,
            "input" => Self::Proposed,
            _ => panic!("Unsupported p8e function annotation type"),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
struct P8eInputOrRecord {
    record_type: RecordType,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    optional: Option<bool>,
    r#type: String,
}

impl P8eInputOrRecord {
    fn from_nested_meta(
        record_type: RecordType,
        args: Vec<NestedMeta>,
        param_type: String,
    ) -> Self {
        match record_type {
            RecordType::Proposed => match P8eInputArgs::from_list(&args) {
                Ok(a) => Self {
                    record_type: RecordType::Proposed,
                    name: a.name,
                    optional: None,
                    r#type: param_type,
                },
                Err(e) => panic!("Error parsing input annotation: {}", e),
            },
            RecordType::Existing => match P8eRecordArgs::from_list(&args) {
                Ok(a) => Self {
                    record_type: RecordType::Existing,
                    name: a.name,
                    optional: a.optional,
                    r#type: param_type,
                },
                Err(e) => panic!("Error parsing record annotation: {}", e),
            },
        }
    }
}
#[derive(Debug, FromMeta)]
struct P8eFunctionArgs {
    name: String,
    invoked_by: Participants,
}

fn attribute_name(attr: &&Attribute) -> String {
    let segment = attr.path.segments.first().unwrap();
    segment.ident.to_string()
}

fn attribute_args(attr: &Attribute, param_type: String) -> P8eInputOrRecord {
    let param_tokens: TokenStream = match attr.tokens.clone().into_iter().nth(0).unwrap() {
        quote::__private::TokenTree::Group(group) => group.stream(),
        _ => panic!("p8e function attribute should be of the form #[record(name = \"<record_name>\")] or #[input(name = \"<input_name>\")]")
    }.into();
    let parser = Punctuated::<NestedMeta, Comma>::parse_terminated;
    let param_attr_args = match parser.parse(param_tokens) {
        Ok(args) => args,
        Err(e) => panic!("Error parsing attribute args {}", e),
    }
    .iter()
    .cloned()
    .collect::<Vec<NestedMeta>>();

    let attribute_name = attribute_name(&attr);

    P8eInputOrRecord::from_nested_meta(
        RecordType::from(attribute_name),
        param_attr_args,
        param_type,
    )
}

fn arg_type(typed: &PatType) -> String {
    match typed.ty.as_ref() {
        syn::Type::Path(path) => {
            // todo: make each argument a void pointer to some binary and auto-hydrate using `parse_from_bytes` or some
            // sort of impl that has to be present for any given argument...

            // todo: differentiate between existing/proposed records
            // todo: allow existing records to be optional (not present in the function spec on chain, but provided to the function)
            let type_name = path
                .path
                .segments
                .iter()
                .map(|el| el.ident.to_string())
                .collect::<Vec<String>>()
                .join("::");
            type_name
        }
        _ => panic!("Unsupported p8e function argument type {:?}", typed.ty),
    }
}

/**
 * Extract input/record information from function parameters, returning the function minus these annotations.
 *
 * Returns the de-sugared function and the list of input/record details in-order
 */
fn consume_param_attribute(fun: ItemFn) -> (ItemFn, Vec<P8eInputOrRecord>) {
    let (args, record_details): (Vec<syn::FnArg>, Vec<P8eInputOrRecord>) = fun.sig.inputs.iter().map(|arg| match arg {
        syn::FnArg::Typed(typed) => {
            let (attrs, other_attrs): (Vec<&Attribute>, Vec<&Attribute>) = typed.attrs.iter().partition(|attr| {
                let attribute_name = attribute_name(attr);
                attribute_name == "input" || attribute_name == "record"
            });

            if attrs.len() == 0 {
                panic!("All p8e function args must be annotated with either #[input(name = \"<input_name>\")] or #[record(name = \"<record_name>\")]");
            }
            if attrs.len() > 1 {
                panic!("P8e function args must be annotated with ONLY ONE #[input(name = \"<input_name>\")] or #[record(name = \"<record_name>\")]");
            }

            let attribute = attrs.first().unwrap(); // have exactly one so this is safe

            let param_type = arg_type(typed);
            let attribute_details = attribute_args(attribute, param_type);

            // match typed.pat.as_ref() {
            //     syn::Pat::Ident(ident) => {
            //         // todo: this is the name of the argument... should we enforce that this is the proposed/existing record name, and have attribute
            //         // to tag the different types?
            //         println!("argument name {:#?}", ident.ident.to_string());
            //     }
            //     _ => panic!("Unsupported p8e function argument type {:?}", typed.pat),
            // }

            (syn::FnArg::Typed(syn::PatType {
                attrs: other_attrs.iter().cloned().cloned().collect(),
                ..typed.to_owned()
            }), attribute_details)
        }
        _ => panic!("Unsupported argument type"),
    }).unzip();

    let sig = Signature {
        inputs: Punctuated::from_iter(args),
        ..fun.sig
    };

    (ItemFn { sig, ..fun }, record_details)
}

fn wrapper_function(
    function: ItemFn,
    params: Vec<P8eInputOrRecord>,
) -> quote::__private::TokenStream {
    let function_name = function.sig.ident;
    let wrapper_function_name = format_ident!("__p8e_entrypoint_{}", function_name);

    let wrapper_params = params.iter().flat_map(|param| {
        let data_name = format_ident!("{}_data", param.name);
        let len_name = format_ident!("{}_len", param.name);
        vec![quote!(#data_name: *const u8), quote!(#len_name: usize)]
    });

    let wrapper_marshal = params.iter().map(|param| {
        let param_type = syn::parse_str::<Path>(param.r#type.as_str()).unwrap();
        let data_name = format_ident!("{}_data", param.name);
        let len_name = format_ident!("{}_len", param.name);
        // todo: some more generic impl that can be used for compatability w/ other data types or proto libs?
        quote!(
            <#param_type>::parse_from_bytes(unsafe { std::slice::from_raw_parts(#data_name, #len_name) }).unwrap()
        )
    });

    quote!(
        #[no_mangle]
        pub extern "C" fn #wrapper_function_name(#(#wrapper_params),*) -> *const u8 {
            let response = #function_name(#(#wrapper_marshal),*);
            let response_bytes = response.write_to_bytes().unwrap();
            let buf_len: i32 = response_bytes.len().try_into().unwrap();
            let dst_ptr = unsafe {
                let mut dst_ptr = p8e_helpers::p8e_allocate(buf_len + 4);
                let mut dst_data_ptr = dst_ptr.offset(4);
                let src_ptr = &response_bytes[0] as *const u8;
                std::ptr::copy_nonoverlapping(buf_len.to_le_bytes().as_ptr(), dst_ptr, 4);
                std::ptr::copy_nonoverlapping(src_ptr, dst_data_ptr, buf_len.try_into().unwrap());
                dst_ptr
            };
            dst_ptr
        }
    )
}

/**
 * This attribute allows tagging and processing a function as being a p8e contract function.
 *
 * - name: The name of the record produced by this function's output
 * - invoked_by: the party type that is responsible for supplying any proposed records in order for this function to execute
 */
#[proc_macro_attribute]
pub fn p8e_function(attr: TokenStream, item: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(attr as AttributeArgs);
    let item_clone = item.clone();
    let item_args = parse_macro_input!(item_clone as ItemFn);

    // todo: do we need some sort of context argument that we always pass in first to these functions?

    let function_name = item_args.sig.ident.to_string();

    let (attribute_stripped_function, param_attributes) = consume_param_attribute(item_args);
    let function_stream = attribute_stripped_function.to_token_stream();

    let args = match P8eFunctionArgs::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(e.write_errors()),
    };

    // if let Some(map) = DEPS.lock().unwrap().as_mut() {
    //     map.push(P8eFunctionDetails {
    //         name: function_name,
    //         parameters: param_attributes.clone(),
    //     });
    // } else {
    //     panic!("Adding functions after `p8e_record!` invocation");
    // }
    let functions_string = serde_json::to_string(&P8eFunctionDetails {
        name: function_name.clone(),
        invoked_by: args.invoked_by,
        parameters: param_attributes.clone(),
    })
    .unwrap();
    let functions_length: i32 = functions_string.len().try_into().unwrap();

    let function_json_ident = format_ident!("__P8E_FUNCTION_{}", function_name);
    let function_json_length_ident = format_ident!("__P8E_FUNCTION_LENGTH_{}", function_name);

    let wrapper = wrapper_function(attribute_stripped_function, param_attributes);

    quote!(
        #function_stream
        #wrapper
        #[no_mangle]
        pub static #function_json_ident: &'static str = #functions_string;
        #[no_mangle]
        pub static #function_json_length_ident: i32 = #functions_length;
    )
    .into()
}

#[derive(Debug, Serialize)]
struct P8eContractDetails {
    scope_specifications: Vec<String>,
    participants: Vec<Participants>,
}

impl Parse for P8eContractDetails {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        // Parse the argument name

        let mut scope_specifications: Vec<String> = vec![];
        let mut participants: Vec<Participants> = vec![];

        while !input.is_empty() {
            let arg_name: Ident = input.parse()?;

            // Parse (and discard the span of) the `=` token
            let _: Token![=] = input.parse()?;

            // todo: revisit this if darling crate ever implements nice parsing of enum values on rhs of attribute
            // todo: allow for string versions of participants as well? ... maybe just go back to pure darling way of having
            // individual 'partcipant'/'scope_specification' values that get merged into one... though that wouldn't allow for the
            // enum-like syntax... but I could just do some validation on the produced values that they are legit
            let lookahead = input.lookahead1();
            match arg_name.to_string().as_str() {
                "scope_specifications" => {
                    let group = input.parse::<proc_macro2::Group>()?;
                    let parser = Punctuated::<NestedMeta, Comma>::parse_terminated;
                    let scope_spec_list = match parser.parse(group.stream().into()) {
                        Ok(args) => args,
                        Err(e) => panic!("Error parsing attribute args {}", e),
                    }.iter().map(|str| -> Result<String, syn::Error> {
                        if let NestedMeta::Lit(Lit::Str(s)) = str {
                            Ok(s.value())
                        } else {
                            Err(syn::Error::new_spanned(str, "unsupported scope specification syntax"))
                        }
                    }).collect::<Result<Vec<String>, syn::Error>>().unwrap();
                    scope_specifications.extend(scope_spec_list)
                },
                "participants" => {
                    let group = input.parse::<proc_macro2::Group>()?;
                    let parser = Punctuated::<NestedMeta, Comma>::parse_terminated;
                    let participants_list: Vec<Participants> = match parser.parse(group.stream().into()) {
                        Ok(args) => args,
                        Err(e) => panic!("Error parsing attribute args {}", e),
                    }.iter().map(|path| -> Result<Participants, syn::Error> {
                        match path {
                            NestedMeta::Meta(Meta::Path(Path {  segments, .. })) => {
                                if let PathSegment { ident, ..} = segments.last().unwrap() {
                                    ident.to_string().try_into().map_err(|_| syn::Error::new_spanned(path, "unsupported participant {}"))
                                } else {
                                    Err(syn::Error::new_spanned(path, "unsupported participant"))
                                }
                            },
                            _ => Err(syn::Error::new_spanned(path, "unsupported participant syntax"))
                        }
                    }).collect::<Result<Vec<Participants>, syn::Error>>().unwrap();
                    participants.extend(participants_list)
                },
                "scope_specification" => {
                    if lookahead.peek(LitStr) {
                        let scope_spec = input.parse::<LitStr>()?;
                        scope_specifications.push(scope_spec.value());
                    }
                },
                "participant" => {
                    let path = input.call(Path::parse_mod_style)?;
                    match path.segments.last().unwrap() {
                        PathSegment { ident, ..} => {
                            participants.push(ident.to_string().try_into().map_err(|_| syn::Error::new_spanned(path, "unsupported participant {}"))?);
                        }
                        _ => return Err(syn::Error::new_spanned(arg_name, "unsupported participant"))
                    }
                },
                _ => return Err(syn::Error::new_spanned(
                    arg_name,
                    "unsupported p8e_contract attribute, expected `participant` or `scope_specification`",
                ))
            }

            if input.lookahead1().peek(Token![,]) {
                let _: Token![,] = input.parse()?;
            }
        }

        Ok(Self {
            scope_specifications,
            participants,
        })
    }
}

/**
 * This defines the top-level contract metadata needed for contract execution
 */
#[proc_macro]
pub fn p8e_contract(input: TokenStream) -> TokenStream {
    let contract_details = parse_macro_input!(input as P8eContractDetails);

    let contract_string = serde_json::to_string(&contract_details).unwrap();
    let contract_length: i32 = contract_string.len().try_into().unwrap();

    quote!(
        #[no_mangle]
        pub static __P8E_CONTRACT: &'static str = #contract_string;
        #[no_mangle]
        pub static __P8E_CONTRACT_LENGTH: i32 = #contract_length;
    )
    .into()
}

#[derive(Debug, FromMeta, Serialize)]
struct P8eScopeSpecification {
    uuid: P8eUuid,
    name: String,
    description: String,
    #[darling(multiple, rename = "party")]
    parties_involved: Vec<Participants>,
    website_url: Option<String>,
    icon_url: Option<String>,
}

#[derive(Debug)]
struct P8eUuid {
    value: String,
}

impl FromMeta for P8eUuid {
    fn from_string(value: &str) -> darling::Result<Self> {
        uuid::Uuid::from_str(value)
            .map(|uuid| P8eUuid {
                value: uuid.to_string(),
            })
            .map_err(|e| darling::Error::custom(e.to_string()))
    }
}

impl Serialize for P8eUuid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.value.as_str())
    }
}

/**
 * This ties all the p8e_record annotated function details together for export
 */
#[proc_macro]
pub fn p8e_scope_specification(input: TokenStream) -> TokenStream {
    let attr_args = parse_macro_input!(input as AttributeArgs);
    let scope_spec_details = match P8eScopeSpecification::from_list(&attr_args) {
        Ok(v) => v,
        Err(e) => return TokenStream::from(e.write_errors()),
    };

    let scope_spec_string = serde_json::to_string(&scope_spec_details).unwrap();
    let scope_spec_length: i32 = scope_spec_string.len().try_into().unwrap();

    let ident_uuid = scope_spec_details.uuid.value.replace("-", "_");
    let scope_spec_json_ident = format_ident!("__P8E_SCOPE_SPEC_{}", ident_uuid);
    let scope_spec_json_length_ident = format_ident!("__P8E_SCOPE_SPEC_LENGTH_{}", ident_uuid);

    quote!(
        #[no_mangle]
        pub static #scope_spec_json_ident: &'static str = #scope_spec_string;
        #[no_mangle]
        pub static #scope_spec_json_length_ident: i32 = #scope_spec_length;
    )
    .into()
}
