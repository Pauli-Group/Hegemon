# Hegemon 0.10.1: the existing public testnet, not the newer Bitcoin80 chain.
[CmdletBinding()]
param(
    [switch]$Mine,
    [string]$DataDir = (Join-Path ([Environment]::GetFolderPath('UserProfile')) '.hegemon-testnet'),
    [ValidateRange(1, 65535)][int]$RpcPort = 9944,
    [ValidateRange(1, 65535)][int]$Port = 30333,
    [switch]$Status,
    [switch]$Help
)
$ErrorActionPreference = 'Stop'
$expectedGenesis = '0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59'

if ($Help) {
    Write-Output 'Hegemon 0.10.1 public testnet launcher'
    Write-Output 'Usage: testnet-start.cmd [-Mine] [-DataDir PATH] [-RpcPort PORT] [-Port PORT]'
    Write-Output '       testnet-start.cmd -Status [-RpcPort PORT]'
    Write-Output 'Default: relay, persistent %USERPROFILE%\.hegemon-testnet, loopback HTTP RPC.'
    Write-Output '-Mine requires HEGEMON_MINER_ADDRESS set to your existing public receive address.'
    Write-Output '-Status reads the running local node; it does not start one.'
    Write-Output 'See TESTNET-README.txt for chain checks and mining setup.'
    exit 0
}
if ($Status) {
    $requests = @(
        @{ jsonrpc = '2.0'; id = 1; method = 'system_health'; params = @() },
        @{ jsonrpc = '2.0'; id = 2; method = 'chain_getHeader'; params = @() },
        @{ jsonrpc = '2.0'; id = 3; method = 'chain_getBlockHash'; params = @(0) },
        @{ jsonrpc = '2.0'; id = 4; method = 'hegemon_miningStatus'; params = @() },
        @{ jsonrpc = '2.0'; id = 5; method = 'system_version'; params = @() }
    )
    $body = ConvertTo-Json -InputObject $requests -Depth 8 -Compress
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:$RpcPort/" -Method Post `
        -ContentType 'application/json' -Body $body -TimeoutSec 15
    Write-Output "Expected testnet genesis: $expectedGenesis"
    ConvertTo-Json -InputObject $response -Depth 12
    $genesis = $response | Where-Object { $_.id -eq 3 }
    if ($genesis.error -or $genesis.result -ne $expectedGenesis) {
        throw 'The local RPC did not return the expected testnet genesis. Keep mining disabled and check the selected binary and data directory.'
    }
    exit 0
}

$binary = Join-Path $PSScriptRoot 'hegemon-node-windows-x86_64.exe'
if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Place hegemon-node-windows-x86_64.exe from this release beside the launcher.'
}
if ([string]::IsNullOrWhiteSpace($DataDir)) {
    throw '-DataDir must identify a persistent node directory.'
}
if ($Mine -and [string]::IsNullOrWhiteSpace($env:HEGEMON_MINER_ADDRESS)) {
    throw 'Set HEGEMON_MINER_ADDRESS to your existing public receive address before -Mine.'
}

# Restore the caller's process environment after the node exits.
$names = @('HEGEMON_SEEDS', 'HEGEMON_MINE', 'HEGEMON_BOOTSTRAP_AUTHORING', 'NO_COLOR', 'RUST_LOG')
$saved = @{}
foreach ($name in $names) { $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    $env:HEGEMON_SEEDS = 'hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333'
    $env:HEGEMON_MINE = if ($Mine) { '1' } else { '0' }
    $env:HEGEMON_BOOTSTRAP_AUTHORING = '0'
    if ([string]::IsNullOrEmpty($env:NO_COLOR)) { $env:NO_COLOR = '1' }
    if ([string]::IsNullOrEmpty($env:RUST_LOG)) { $env:RUST_LOG = 'hegemon_node=info,consensus=info,network=info' }
    Write-Output "Hegemon 0.10.1 testnet; mining=$($env:HEGEMON_MINE); data=$DataDir; RPC=http://127.0.0.1:$RpcPort"
    Write-Output "Seeds: $($env:HEGEMON_SEEDS)"
    Write-Output "Expected genesis: $expectedGenesis"
    if ($Mine) { Write-Output 'Mining requires synchronized system time and a verified canonical chain.' }
    & $binary --dev --base-path $DataDir --rpc-methods safe --rpc-port $RpcPort --port $Port --name HegemonTestnet
    $nodeExitCode = $LASTEXITCODE
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process') }
}
exit $nodeExitCode
