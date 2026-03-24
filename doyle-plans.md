# Doyle Plans

*A collection of the thoughts of William Doyle to be presented to Pierre-Luc for his consideration and potentual integration into the Hegemon proposal.*

## Host chain fail-over

We need to decide on how we wish to develop Hegemon. Do we want to build things slow and steady? Or do we want to make Hegemon public fast while increasing the chances of something going wrong? If I'm being honest I think we want to take the latter approch but with an important caviaot which is; if we make it clear that we expect Hegemon to fail in production BUT that we have system in place so that these failures only result in precalculated and preunderstod damages, users may be willing to tollerate these failues in return for high speed development. 

**Find a way to make it safe to fail in production**

This is not terribly difficult in a world where other blockchains exist. 

### What Should Failure Look Like? 

When Hegemon is working correctly the network processes transactions of the Hegemon asset in a quantum secure and privacy preserving way. When Hegemon is not working the Hegemon asset can be withdrawn to a host chain where it can be transacted in a quantum vulnerable and transparent manner. 

## Addresses

Ideally addresses should be bech32 encoded merkle roots. This merkle tree would contain the public keys needed but it would also contain the id of an NFT on the host chain. Any account holding the NFT on the host chain would be able to withdraw tokens from the Hegemon account to the host chain. This NFT could itself be stored in a one time use quantum secure smart contract account (PQSCA) on the host chain such that a quantum secure signature is still needed when withdrawing to the host chain. By keeping the authority with the NFT instead of the PQSCA directly, we allow the PQSCA to be changed without modifying the Hegemon merkleroot. 