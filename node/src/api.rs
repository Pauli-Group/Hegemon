use std::net::SocketAddr;

use crate::error::NodeResult;
use crate::test_utils::LegacyNode;

pub async fn serve(_service: LegacyNode, _addr: Option<SocketAddr>) -> NodeResult<()> {
    Ok(())
}
