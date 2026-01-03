// Protocol definitions for OstrichPKI gRPC services
//
// Generated from proto files using tonic-build

pub mod ca {
    pub mod v1 {
        tonic::include_proto!("ostrich.ca.v1");
    }
}

pub use ca::v1::*;
