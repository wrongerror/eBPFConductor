use bpfman_api::v1::bpfman_client::BpfmanClient;
use log::debug;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast;
use tokio::task::{JoinHandle, JoinSet};

use agent_api::select_channel;
use agent_api::v1::agent_server::AgentServer;

use crate::managers::prog::ProgManager;
use crate::progs::types::ShutdownSignal;
use crate::Args;

pub(crate) mod http;
pub(crate) mod rpc;

pub(crate) async fn serve(args: Args) -> anyhow::Result<()> {
    let (shutdown_tx, shutdown_rx1) = broadcast::channel(32);
    let shutdown_handle = tokio::spawn(shutdown_handler(shutdown_tx.clone()));

    let channel = select_channel(args.bpfman_socket_path).unwrap();
    let bpf_client = BpfmanClient::new(channel);
    let prog_manager = ProgManager::new(shutdown_tx.clone()).await?;
    let agent_service = rpc::AgentService::new(prog_manager.clone(), bpf_client);
    let service = AgentServer::new(agent_service);

    let mut listeners: Vec<_> = Vec::new();
    let rpc_handler = rpc::serve(&args.agent_socket_path, service, shutdown_rx1).await?;
    listeners.push(rpc_handler);
    let shutdown_rx2 = shutdown_tx.subscribe();
    let http_server = http::serve(
        args.metrics_addr,
        prog_manager.registry_manager.clone(),
        shutdown_rx2,
    )
    .await?;
    listeners.push(http_server);

    let (_, res) = tokio::join!(join_listeners(listeners), shutdown_handle);
    if let Some(e) = res.err() {
        return Err(e.into());
    }

    Ok(())
}

async fn join_listeners(listeners: Vec<JoinHandle<()>>) {
    for listener in listeners {
        match listener.await {
            Ok(()) => {}
            Err(e) => eprintln!("Error = {e:?}"),
        }
    }
}

pub(crate) async fn shutdown_handler(shutdown_tx: broadcast::Sender<ShutdownSignal>) {
    let mut joinset = JoinSet::new();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();
    joinset.spawn(async move {
        sigint.recv().await;
        debug!("Received SIGINT");
    });

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    joinset.spawn(async move {
        sigterm.recv().await;
        debug!("Received SIGTERM");
    });

    joinset.join_next().await;
    shutdown_tx.send(ShutdownSignal::All).unwrap();
}
