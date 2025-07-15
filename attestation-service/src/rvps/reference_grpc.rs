// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

const METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUE: ::grpcio::Method<
    super::reference::ReferenceValueQueryRequest,
    super::reference::ReferenceValueQueryResponse,
> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/reference.ReferenceValueProviderService/QueryReferenceValue",
    req_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
    resp_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
};

const METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUES: ::grpcio::Method<
    super::reference::ReferenceValuesQueryRequest,
    super::reference::ReferenceValueQueryResponse,
> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/reference.ReferenceValueProviderService/QueryReferenceValues",
    req_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
    resp_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
};

const METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_REGISTER_REFERENCE_VALUE: ::grpcio::Method<
    super::reference::ReferenceValueRegisterRequest,
    super::reference::ReferenceValueRegisterResponse,
> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/reference.ReferenceValueProviderService/RegisterReferenceValue",
    req_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
    resp_mar: ::grpcio::Marshaller {
        ser: ::grpcio::pb_ser,
        de: ::grpcio::pb_de,
    },
};

#[derive(Clone)]
pub struct ReferenceValueProviderServiceClient {
    client: ::grpcio::Client,
}

impl ReferenceValueProviderServiceClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        ReferenceValueProviderServiceClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn query_reference_value_opt(
        &self,
        req: &super::reference::ReferenceValueQueryRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<super::reference::ReferenceValueQueryResponse> {
        self.client.unary_call(
            &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUE,
            req,
            opt,
        )
    }

    pub fn query_reference_value(
        &self,
        req: &super::reference::ReferenceValueQueryRequest,
    ) -> ::grpcio::Result<super::reference::ReferenceValueQueryResponse> {
        self.query_reference_value_opt(req, ::grpcio::CallOption::default())
    }

    pub fn query_reference_value_async_opt(
        &self,
        req: &super::reference::ReferenceValueQueryRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<
        ::grpcio::ClientUnaryReceiver<super::reference::ReferenceValueQueryResponse>,
    > {
        self.client.unary_call_async(
            &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUE,
            req,
            opt,
        )
    }

    pub fn query_reference_value_async(
        &self,
        req: &super::reference::ReferenceValueQueryRequest,
    ) -> ::grpcio::Result<
        ::grpcio::ClientUnaryReceiver<super::reference::ReferenceValueQueryResponse>,
    > {
        self.query_reference_value_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn query_reference_values_opt(
        &self,
        req: &super::reference::ReferenceValuesQueryRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<super::reference::ReferenceValueQueryResponse> {
        self.client.unary_call(
            &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUES,
            req,
            opt,
        )
    }

    pub fn query_reference_values(
        &self,
        req: &super::reference::ReferenceValuesQueryRequest,
    ) -> ::grpcio::Result<super::reference::ReferenceValueQueryResponse> {
        self.query_reference_values_opt(req, ::grpcio::CallOption::default())
    }

    pub fn query_reference_values_async_opt(
        &self,
        req: &super::reference::ReferenceValuesQueryRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<
        ::grpcio::ClientUnaryReceiver<super::reference::ReferenceValueQueryResponse>,
    > {
        self.client.unary_call_async(
            &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUES,
            req,
            opt,
        )
    }

    pub fn query_reference_values_async(
        &self,
        req: &super::reference::ReferenceValuesQueryRequest,
    ) -> ::grpcio::Result<
        ::grpcio::ClientUnaryReceiver<super::reference::ReferenceValueQueryResponse>,
    > {
        self.query_reference_values_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn register_reference_value_opt(
        &self,
        req: &super::reference::ReferenceValueRegisterRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<super::reference::ReferenceValueRegisterResponse> {
        self.client.unary_call(
            &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_REGISTER_REFERENCE_VALUE,
            req,
            opt,
        )
    }

    pub fn register_reference_value(
        &self,
        req: &super::reference::ReferenceValueRegisterRequest,
    ) -> ::grpcio::Result<super::reference::ReferenceValueRegisterResponse> {
        self.register_reference_value_opt(req, ::grpcio::CallOption::default())
    }

    pub fn register_reference_value_async_opt(
        &self,
        req: &super::reference::ReferenceValueRegisterRequest,
        opt: ::grpcio::CallOption,
    ) -> ::grpcio::Result<
        ::grpcio::ClientUnaryReceiver<super::reference::ReferenceValueRegisterResponse>,
    > {
        self.client.unary_call_async(
            &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_REGISTER_REFERENCE_VALUE,
            req,
            opt,
        )
    }

    pub fn register_reference_value_async(
        &self,
        req: &super::reference::ReferenceValueRegisterRequest,
    ) -> ::grpcio::Result<
        ::grpcio::ClientUnaryReceiver<super::reference::ReferenceValueRegisterResponse>,
    > {
        self.register_reference_value_async_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F)
    where
        F: ::futures::Future<Output = ()> + Send + 'static,
    {
        self.client.spawn(f)
    }
}

pub trait ReferenceValueProviderService {
    fn query_reference_value(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: super::reference::ReferenceValueQueryRequest,
        sink: ::grpcio::UnarySink<super::reference::ReferenceValueQueryResponse>,
    );
    fn query_reference_values(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: super::reference::ReferenceValuesQueryRequest,
        sink: ::grpcio::UnarySink<super::reference::ReferenceValueQueryResponse>,
    );
    fn register_reference_value(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: super::reference::ReferenceValueRegisterRequest,
        sink: ::grpcio::UnarySink<super::reference::ReferenceValueRegisterResponse>,
    );
}

pub fn create_reference_value_provider_service<
    S: ReferenceValueProviderService + Send + Clone + 'static,
>(
    s: S,
) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s.clone();
    builder = builder.add_unary_handler(
        &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUE,
        move |ctx, req, resp| instance.query_reference_value(ctx, req, resp),
    );
    let mut instance = s.clone();
    builder = builder.add_unary_handler(
        &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_QUERY_REFERENCE_VALUES,
        move |ctx, req, resp| instance.query_reference_values(ctx, req, resp),
    );
    let mut instance = s;
    builder = builder.add_unary_handler(
        &METHOD_REFERENCE_VALUE_PROVIDER_SERVICE_REGISTER_REFERENCE_VALUE,
        move |ctx, req, resp| instance.register_reference_value(ctx, req, resp),
    );
    builder.build()
}
