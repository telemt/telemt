//! Proxy Defs

// Apply strict linting to proxy production code while keeping test builds noise-tolerant.
#![cfg_attr(test, allow(warnings))]
#![cfg_attr(not(test), forbid(clippy::undocumented_unsafe_blocks))]
#![cfg_attr(
	not(test),
	deny(
		clippy::unwrap_used,
		clippy::expect_used,
		clippy::panic,
		clippy::todo,
		clippy::unimplemented,
		clippy::correctness,
		clippy::option_if_let_else,
		clippy::or_fun_call,
		clippy::branches_sharing_code,
		clippy::single_option_map,
		clippy::useless_let_if_seq,
		clippy::redundant_locals,
		clippy::cloned_ref_to_slice_refs,
		unsafe_code,
		clippy::await_holding_lock,
		clippy::await_holding_refcell_ref,
		clippy::debug_assert_with_mut_call,
		clippy::macro_use_imports,
		clippy::cast_ptr_alignment,
		clippy::cast_lossless,
		clippy::ptr_as_ptr,
		clippy::large_stack_arrays,
		clippy::same_functions_in_if_condition,
		trivial_casts,
		trivial_numeric_casts,
		unused_extern_crates,
		unused_import_braces,
		rust_2018_idioms
	)
)]
#![cfg_attr(
	not(test),
	allow(
		clippy::use_self,
		clippy::redundant_closure,
		clippy::too_many_arguments,
		clippy::doc_markdown,
		clippy::missing_const_for_fn,
		clippy::unnecessary_operation,
		clippy::redundant_pub_crate,
		clippy::derive_partial_eq_without_eq,
		clippy::type_complexity,
		clippy::new_ret_no_self,
		clippy::cast_possible_truncation,
		clippy::cast_possible_wrap,
		clippy::significant_drop_tightening,
		clippy::significant_drop_in_scrutinee,
		clippy::float_cmp,
		clippy::nursery
	)
)]

pub mod adaptive_buffers;
pub mod client;
pub mod direct_relay;
pub mod handshake;
pub mod masking;
pub mod middle_relay;
pub mod relay;
pub mod route_mode;
pub mod session_eviction;

pub use client::ClientHandler;
#[allow(unused_imports)]
pub use handshake::*;
#[allow(unused_imports)]
pub use masking::*;
#[allow(unused_imports)]
pub use relay::*;
