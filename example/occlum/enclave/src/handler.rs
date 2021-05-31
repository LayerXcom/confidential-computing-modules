use occlum_rpc_types::hello_world::{greeter_server::Greeter, HelloReply, HelloRequest};
use tonic::{Request, Response, Status};
use tracing::info;

#[derive(Default, Debug)]
pub(crate) struct MyGreeter {}

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        info!("Got a request from {:?}", request.remote_addr());

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}
