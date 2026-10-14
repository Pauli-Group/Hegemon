@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Hegemon 0.10.3: existing public testnet. Quote paths at the call site.
rem Keep argument handling outside parenthesized blocks; preserve literal !.
set "launcher_binary=%~dp0hegemon-node-windows-x86_64.exe"
set "launcher_data_dir="
if defined USERPROFILE set "launcher_data_dir=%USERPROFILE%\.hegemon-testnet"
set "launcher_rpc_raw=9944"
set "launcher_port_raw=30333"
set "launcher_mine=0"
set "launcher_status="
set "launcher_help="
set "launcher_status_created="
set "launcher_status_dir="
set "launcher_expected_genesis=0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59"

:parse_arguments
if "%~1"=="" goto arguments_parsed
if /i "%~1"=="-Mine" goto argument_mine
if /i "%~1"=="-Status" goto argument_status
if /i "%~1"=="-Help" goto argument_help
if /i "%~1"=="-DataDir" goto argument_data_dir
if /i "%~1"=="-RpcPort" goto argument_rpc_port
if /i "%~1"=="-Port" goto argument_port
echo Unknown argument. Use -Help for usage. 1>&2
exit /b 2

:argument_mine
set "launcher_mine=1"
shift
goto parse_arguments
:argument_status
set "launcher_status=1"
shift
goto parse_arguments
:argument_help
set "launcher_help=1"
shift
goto parse_arguments
:argument_data_dir
set "launcher_value_kind=data_dir"
goto argument_value
:argument_rpc_port
set "launcher_value_kind=rpc_port"
goto argument_value
:argument_port
set "launcher_value_kind=port"
:argument_value
if "%~2"=="" goto missing_argument_value
if /i "%~2"=="-Mine" goto missing_argument_value
if /i "%~2"=="-Status" goto missing_argument_value
if /i "%~2"=="-Help" goto missing_argument_value
if /i "%~2"=="-DataDir" goto missing_argument_value
if /i "%~2"=="-RpcPort" goto missing_argument_value
if /i "%~2"=="-Port" goto missing_argument_value
set "launcher_required_value=%~2"
set launcher_required_value | "%SystemRoot%\System32\findstr.exe" /r /i /c:"^launcher_required_value=[ 	]*$" >nul
if not errorlevel 1 goto missing_argument_value
if "%launcher_value_kind%"=="data_dir" set "launcher_data_dir=%~2"
if "%launcher_value_kind%"=="rpc_port" set "launcher_rpc_raw=%~2"
if "%launcher_value_kind%"=="port" set "launcher_port_raw=%~2"
shift
shift
goto parse_arguments

:arguments_parsed
rem Validate by removing decimal digits before any arithmetic or URL use.
set "launcher_port_input=%launcher_rpc_raw%"
call :validate_port
if errorlevel 1 goto invalid_port
set "launcher_rpc_port=%launcher_valid_port%"
set "launcher_port_input=%launcher_port_raw%"
call :validate_port
if errorlevel 1 goto invalid_port
set "launcher_port=%launcher_valid_port%"
if defined launcher_help goto show_help
if defined launcher_status goto show_status
if not defined launcher_data_dir goto invalid_directory
rem Inspect environment output, without interpolating the path or payout.
set launcher_data_dir | "%SystemRoot%\System32\findstr.exe" /r /i /c:"^launcher_data_dir=[ 	]*$" >nul
if not errorlevel 1 goto invalid_directory
if not exist "%launcher_binary%" goto missing_binary
if "%launcher_mine%"=="0" goto start_node
if not defined HEGEMON_MINER_ADDRESS goto missing_payout
set HEGEMON_MINER_ADDRESS | "%SystemRoot%\System32\findstr.exe" /r /i /c:"^HEGEMON_MINER_ADDRESS=[ 	]*$" >nul
if not errorlevel 1 goto missing_payout

:start_node
set "HEGEMON_SEEDS=hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
set "HEGEMON_MINE=%launcher_mine%"
set "HEGEMON_BOOTSTRAP_AUTHORING=0"
if not defined NO_COLOR set "NO_COLOR=1"
if not defined RUST_LOG set "RUST_LOG=hegemon_node=info,consensus=info,network=info"
rem Escape trailing backslashes for the executable's Windows argv parser.
set "launcher_data_argument=%launcher_data_dir%"
set "launcher_data_tail=%launcher_data_dir%"
:escape_data_tail
if not "%launcher_data_tail:~-1%"=="\" goto node_arguments_ready
set "launcher_data_argument=%launcher_data_argument%\"
set "launcher_data_tail=%launcher_data_tail:~0,-1%"
goto escape_data_tail
:node_arguments_ready
echo Hegemon 0.10.3 testnet; mining=%HEGEMON_MINE%; data="%launcher_data_dir%"; RPC=http://127.0.0.1:%launcher_rpc_port%
echo Seeds: %HEGEMON_SEEDS%
echo Expected genesis: %launcher_expected_genesis%
if "%launcher_mine%"=="1" echo Mining requires synchronized system time and a verified canonical chain.
"%launcher_binary%" --dev --base-path "%launcher_data_argument%" --rpc-methods safe --rpc-port %launcher_rpc_port% --port %launcher_port% --name HegemonTestnet
set "launcher_node_exit=%errorlevel%"
endlocal & exit /b %launcher_node_exit%

:invalid_port
echo -RpcPort and -Port require decimal integers from 1 through 65535. 1>&2
exit /b 2
:missing_argument_value
echo -DataDir, -RpcPort, and -Port each require a value before another switch. 1>&2
exit /b 2
:invalid_directory
echo -DataDir must identify a persistent node directory. 1>&2
exit /b 2
:missing_binary
echo Place hegemon-node-windows-x86_64.exe from this release beside the launcher. 1>&2
exit /b 2
:missing_payout
echo Set HEGEMON_MINER_ADDRESS to your existing public receive address before -Mine. 1>&2
exit /b 2

:show_help
echo Hegemon 0.10.3 public testnet launcher
echo Usage: testnet-start.cmd [-Mine] [-DataDir PATH] [-RpcPort PORT] [-Port PORT]
echo        testnet-start.cmd -Status [-RpcPort PORT]
echo Default: relay, persistent user-profile .hegemon-testnet, loopback HTTP RPC.
echo -Mine requires HEGEMON_MINER_ADDRESS set to your existing public receive address.
echo -Status reads the running local node; it does not start one.
echo Quote paths containing spaces or command-shell punctuation.
echo See TESTNET-README.txt for chain checks and mining setup.
exit /b 0

:show_status
set "launcher_curl=%SystemRoot%\System32\curl.exe"
if not exist "%launcher_curl%" goto missing_curl
if not defined TEMP goto status_failed
set "launcher_status_dir=%TEMP%\hegemon-status-%RANDOM%-%RANDOM%"
rem A successful mkdir owns this directory; never reuse a pre-existing one.
mkdir "%launcher_status_dir%" 2>nul
if errorlevel 1 goto status_failed
set "launcher_status_created=1"
"%launcher_curl%" --disable --noproxy "*" --proto =http --fail --silent --show-error --max-time 15 --header "Content-Type: application/json" --data "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system_health\",\"params\":[]},{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"chain_getHeader\",\"params\":[]},{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"chain_getBlockHash\",\"params\":[0]},{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"hegemon_miningStatus\",\"params\":[]},{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"system_version\",\"params\":[]}]" --output "%launcher_status_dir%\batch.json" "http://127.0.0.1:%launcher_rpc_port%/"
if errorlevel 1 goto status_failed
echo Expected testnet genesis: %launcher_expected_genesis%
type "%launcher_status_dir%\batch.json"
echo.
"%launcher_curl%" --disable --noproxy "*" --proto =http --fail --silent --show-error --max-time 15 --header "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"chain_getBlockHash\",\"params\":[0]}" --output "%launcher_status_dir%\genesis.json" "http://127.0.0.1:%launcher_rpc_port%/"
if errorlevel 1 goto status_failed
rem Compare entire response bytes, allowing each compact JSON member order.
rem Extra fields, errors, duplicate keys, multiline data, and suffixes reject.
<nul set /p "={"id":3,"jsonrpc":"2.0","result":"%launcher_expected_genesis%"}" > "%launcher_status_dir%\expected.json"
"%SystemRoot%\System32\fc.exe" /b "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" >nul
if not errorlevel 1 goto status_verified
<nul set /p "={"id":3,"result":"%launcher_expected_genesis%","jsonrpc":"2.0"}" > "%launcher_status_dir%\expected.json"
"%SystemRoot%\System32\fc.exe" /b "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" >nul
if not errorlevel 1 goto status_verified
<nul set /p "={"jsonrpc":"2.0","id":3,"result":"%launcher_expected_genesis%"}" > "%launcher_status_dir%\expected.json"
"%SystemRoot%\System32\fc.exe" /b "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" >nul
if not errorlevel 1 goto status_verified
<nul set /p "={"jsonrpc":"2.0","result":"%launcher_expected_genesis%","id":3}" > "%launcher_status_dir%\expected.json"
"%SystemRoot%\System32\fc.exe" /b "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" >nul
if not errorlevel 1 goto status_verified
<nul set /p "={"result":"%launcher_expected_genesis%","id":3,"jsonrpc":"2.0"}" > "%launcher_status_dir%\expected.json"
"%SystemRoot%\System32\fc.exe" /b "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" >nul
if not errorlevel 1 goto status_verified
<nul set /p "={"result":"%launcher_expected_genesis%","jsonrpc":"2.0","id":3}" > "%launcher_status_dir%\expected.json"
"%SystemRoot%\System32\fc.exe" /b "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" >nul
if not errorlevel 1 goto status_verified
echo Local RPC did not return the expected testnet genesis. Keep mining disabled and check the selected binary and data directory. 1>&2
goto status_failed

:status_verified
set "launcher_status_exit=0"
goto status_cleanup
:status_failed
echo Status failed; verify the local node, HTTP RPC, and testnet genesis before mining. 1>&2
set "launcher_status_exit=1"
if not defined launcher_status_created exit /b 1
:status_cleanup
del /q "%launcher_status_dir%\batch.json" "%launcher_status_dir%\genesis.json" "%launcher_status_dir%\expected.json" 2>nul
rmdir "%launcher_status_dir%" 2>nul
endlocal & exit /b %launcher_status_exit%
:missing_curl
echo -Status requires the built-in curl.exe available on Windows 10 1803 and newer. 1>&2
exit /b 2

:validate_port
if not defined launcher_port_input exit /b 1
set "launcher_port_invalid=%launcher_port_input:0=%"
set "launcher_port_invalid=%launcher_port_invalid:1=%"
set "launcher_port_invalid=%launcher_port_invalid:2=%"
set "launcher_port_invalid=%launcher_port_invalid:3=%"
set "launcher_port_invalid=%launcher_port_invalid:4=%"
set "launcher_port_invalid=%launcher_port_invalid:5=%"
set "launcher_port_invalid=%launcher_port_invalid:6=%"
set "launcher_port_invalid=%launcher_port_invalid:7=%"
set "launcher_port_invalid=%launcher_port_invalid:8=%"
set "launcher_port_invalid=%launcher_port_invalid:9=%"
if defined launcher_port_invalid exit /b 1
:trim_port_zeroes
if not "%launcher_port_input:~0,1%"=="0" goto port_length_checked
set "launcher_port_input=%launcher_port_input:~1%"
if not defined launcher_port_input exit /b 1
goto trim_port_zeroes
:port_length_checked
if not "%launcher_port_input:~5,1%"=="" exit /b 1
set /a launcher_valid_port=%launcher_port_input% >nul
if %launcher_valid_port% LSS 1 exit /b 1
if %launcher_valid_port% GTR 65535 exit /b 1
exit /b 0
