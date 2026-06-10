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
