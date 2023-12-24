use std::env;
use std::fs::File;
use std::path::PathBuf;
use std::time::Duration;

pub fn main() {
    cc::Build::new()
        .file("netcode.c")
        .include("c")
        .include("windows")
        .define("NETCODE_ENABLE_TESTS", Some("0"))
        .define("NDEBUG", Some("0"))
        .compile("libnetcode.a");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let private_path = out_path.join("private_bindings.rs");

    //Do some basic dependecy management
    let targets = vec![&private_path];
    let source = vec!["rust/build.rs", "netcode.c", "netcode.h"]
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    let newest_source = source
        .iter()
        .map(|v| {
            File::open(v)
                .and_then(|f| f.metadata())
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| panic!("Source file {:?} not found", v))
        })
        .max()
        .unwrap();

    let oldest_target = targets
        .iter()
        .filter_map(|v| {
            File::open(v)
                .and_then(|f| f.metadata())
                .and_then(|m| m.modified())
                .ok()
        })
        .min()
        .unwrap_or(newest_source - Duration::from_secs(1));

    if newest_source > oldest_target {
        let include = env::var("INCLUDE").unwrap_or_else(|_| "".to_string());
        let sodium_include = env::var("SODIUM_LIB_DIR").unwrap_or_else(|_| "windows".to_string());

        // small hack: set this when building on linux to avoid libclang failures
        let forego_includes = env::var("NETCODE_FOREGO_INCLUDES").is_ok();

        let mut binding_builder = bindgen::Builder::default()
            .header("netcode.c")
            .clang_arg("-Ic");
        if !forego_includes {
            println!("Adding sodium and include paths");
            binding_builder = binding_builder
                .clang_arg(format!("-I{}", sodium_include))
                .clang_arg(format!("-I{}", include))
        } else {
            println!("Foregoing sodium/include paths")
        }

        let private_bindings = binding_builder
            .allowlist_function("netcode_log_level")
            .allowlist_function("netcode_write_packet")
            .allowlist_function("netcode_read_packet")
            .allowlist_function("netcode_read_connect_token")
            .allowlist_function("netcode_decrypt_challenge_token")
            .allowlist_function("netcode_read_challenge_token")
            .allowlist_function("netcode_replay_protection_reset")
            .allowlist_function("free")
            .allowlist_function("netcode_generate_connect_token")
            .allowlist_function("netcode_init")
            //.allowlist_function("netcode_client_create_internal")
            .allowlist_function("netcode_client_create")
            .allowlist_function("netcode_client_connect")
            .allowlist_function("netcode_client_update")
            .allowlist_function("netcode_client_state")
            .allowlist_function("netcode_client_receive_packet")
            .allowlist_function("netcode_client_free_packet")
            .allowlist_function("netcode_client_destroy")
            .allowlist_function("netcode_client_free_packet")
            .allowlist_function("netcode_client_send_packet")
            .allowlist_function("netcode_term")
            .allowlist_type("netcode_network_simulator_t")
            .allowlist_type("netcode_address_t")
            .allowlist_function("netcode_network_simulator_create")
            .allowlist_function("netcode_network_simulator_destroy")
            .allowlist_function("netcode_network_simulator_update")
            .allowlist_function("netcode_network_simulator_send_packet")
            .allowlist_function("netcode_network_simulator_receive_packets")
            .allowlist_function("netcode_parse_address")
            .allowlist_function("netcode_address_to_string")
            .allowlist_var("NETCODE_MAX_ADDRESS_STRING_LENGTH")
            .allowlist_var("NETCODE_CONNECTION_NUM_PACKETS")
            .allowlist_var("NETCODE_CLIENT_STATE_CONNECTED")
            .allowlist_var("NETCODE_CLIENT_STATE_DISCONNECTED")
            .allowlist_var("NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE")
            .allowlist_var("NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST")
            .allowlist_var("NETCODE_LOG_LEVEL_DEBUG")
            .allowlist_var("NETCODE_PACKET_SEND_RATE")
            .allowlist_var("NETCODE_CONNECT_TOKEN_BYTES")
            .generate()
            .expect("Unable to generate bindings");

        private_bindings
            .write_to_file(&private_path)
            .expect("Couldn't write bindings!");
    }
}
