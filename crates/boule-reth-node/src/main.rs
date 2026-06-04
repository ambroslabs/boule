//! Entry point for the boule custom reth EL node (Option A, #777).
//!
//! Same CLI surface as stock reth, but launches [`BouleNode`] — the
//! `NodeBuilder`-composed node that applies boule's registry writes as system
//! calls. See [`boule_reth_node`] for the pipeline.

use boule_reth_node::node::BouleNode;
use reth_ethereum::cli::interface::Cli;

fn main() {
    Cli::parse_args()
        .run(async move |builder, _| {
            let handle = builder.node(BouleNode::default()).launch().await?;
            handle.wait_for_node_exit().await
        })
        .unwrap();
}
