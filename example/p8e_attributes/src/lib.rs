use core::panic;
use std::sync::Mutex;

use darling::{FromMeta, ToTokens};
use proc_macro::{Span, TokenStream};
use quote::{format_ident, quote};
use serde::Serialize;
use syn::{
    parse::Parser, parse_macro_input, punctuated::Punctuated, token::Comma, Attribute,
    AttributeArgs, Ident, ItemFn, NestedMeta, PatType, Path, Signature,
};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref DEPS: Mutex<Option<Vec<P8eFunctionDetails>>> = Mutex::new(Some(Default::default()));
}

#[derive(Debug, Serialize, Clone)]
struct P8eFunctionDetails {
    name: String,
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

// #[derive(Debug, FromMeta)]
// struct P8eParticipantsArgs {
//     #[darling(multiple, rename = "role")]
//     roles: Vec<String>, // todo: vec of party type enum? Is that a thing in macros?
// }
// // todo: participants annotation (one per project??? Are we limiting contracts to be own wasm files?)
// #[proc_macro_attribute]
// pub fn participants(attr: TokenStream, item: TokenStream) -> TokenStream {
//     item
// }

// #[derive(Debug, FromMeta)]
// struct P8eScopeSpecificationArgs {
//     name: String,
// }
// // todo: scope specification annotation (again, one per project??? signifies which scope specs a contract operates against)
// // actually... lets just let each of these accept one scope spec maybe
// #[proc_macro_attribute]
// pub fn scope_specification(attr: TokenStream, item: TokenStream) -> TokenStream {
//     item
// }

// #[derive(Debug, FromMeta)]
// struct P8eScopeSpecificationDefinitionArgs {
//     uuid: String,
//     name: String,
//     description: String,
//     website_url: String,
//     icon_url: String,
//     #[darling(multiple, rename = "party")]
//     parties: Vec<String>, // todo: make this an enum???
// }
// // todo: scope specification definition annotation, multiple per project regardless
// #[proc_macro_attribute]
// pub fn scope_specification_definition(attr: TokenStream, item: TokenStream) -> TokenStream {
//     item
// }

#[derive(Debug, FromMeta)]
struct P8eFunctionArgs {
    name: String,
    invoked_by: String, // todo: make this an enum???
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

    println!("stuff: {:#?}", record_details);

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
pub fn function(attr: TokenStream, item: TokenStream) -> TokenStream {
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

    if let Some(map) = DEPS.lock().unwrap().as_mut() {
        map.push(P8eFunctionDetails {
            name: function_name,
            parameters: param_attributes.clone(),
        });
    } else {
        panic!("Adding functions after `p8e_record!` invocation");
    }

    let wrapper = wrapper_function(attribute_stripped_function, param_attributes);

    println!("found record marked {:?}", args.name);
    quote!(
        #function_stream
        #wrapper
    )
    .into()
}

/**
 * This ties all the p8e_record annotated function details together for export
 *
 * todo: can we do without this somehow? Either by some automagic injection of the gathered
 * function specifications, or by having each function just export its own static details
 * prefixed with __P8E_FUNCTION_...?
 *
 * todo: more than just a list of function names, need actual structure
 * todo: determine if this will just end up as a json stringified version of a vector of some nice struct
 */
#[proc_macro]
pub fn contract(_input: TokenStream) -> TokenStream {
    let map = DEPS.lock().unwrap().take();

    if let Some(map) = map {
        // let elems = map.iter().map(|fun| serde_json::to_string(fun).unwrap());
        let functions_string = serde_json::to_string(&map).unwrap();
        let functions_length: i32 = functions_string.len().try_into().unwrap();
        println!("functions_length {}", functions_length);

        quote!(
            #[no_mangle]
            pub static __P8E_FUNCTIONS: &'static str = #functions_string;
            #[no_mangle]
            pub static __P8E_FUNCTIONS_LENGTH: i32 = #functions_length;
        )
        .into()
    } else {
        panic!("`p8e_contract!` invoked twice");
    }
}
