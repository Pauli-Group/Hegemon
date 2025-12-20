// Auto-generated Poseidon constants (NUMS).
//
// Generation scheme:
// - Field modulus: 18446744069414584321 (Goldilocks)
// - Round constants: SHA-256(domain || round_be32 || pos_be32 || counter_be32)
// - MDS: Cauchy matrix with x/y from SHA-256(domain || label || counter_be32)
//
// Domains:
// - round constants: hegemon-poseidon-round-constants-v1
// - MDS seeds: hegemon-poseidon-mds-v1

use crate::constants::{POSEIDON_ROUNDS, POSEIDON_WIDTH};

pub const NUMS_DOMAIN_ROUND_CONSTANTS: &[u8] = b"hegemon-poseidon-round-constants-v1";
pub const NUMS_DOMAIN_MDS: &[u8] = b"hegemon-poseidon-mds-v1";

pub const MDS_X_SEEDS: [u64; 3] = [
    0x2a3af9cbe3a17cc9,
    0xd4b516ba82c1e8ea,
    0x7afac776daede1b6,
];

pub const MDS_Y_SEEDS: [u64; 3] = [
    0x9fd54d3ae78d39db,
    0x42c34aa97cc5c724,
    0xefce20d912251ed0,
];

pub const MDS_MATRIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] = 
[
    [0x5d80c0aae9349251, 0x363dc1882ff020a7, 0x4beb1e524871f0d0],
    [0x58e089990fa63791, 0x0ea4ac8319e46eb1, 0x4094490d1c632eaa],
    [0x6ab16a64861ac16a, 0xd6aea38e5b7144ae, 0xc4c4517fa118c2a3],
]
;

pub const ROUND_CONSTANTS: [[u64; POSEIDON_WIDTH]; POSEIDON_ROUNDS] = 
[
    [0x3ed482724d32dff1, 0x1e18a1ef3d6d8b70, 0x546400b4a2032649],
    [0xd9d7ec93263c6cb4, 0x92c9065c93201825, 0x7138d910ff66095e],
    [0xe3c6dda2ac6a4513, 0x2bb682389bd01fb6, 0x351817560b510cab],
    [0x3ee19548e439aaa9, 0x3a5341636d2508c4, 0xe18197dfbe5848be],
    [0x21da05fca93f9adf, 0xece1913f898a35c0, 0x5e50b916fbeddd9b],
    [0xb79dc2d9af83f052, 0xdb384aa89a217251, 0x482600633086ec7c],
    [0x092a0d41ae86fa9a, 0x0ff9ef097da4f8d0, 0x71aa99e62e40b063],
    [0xcd3751da650a4f95, 0x7901addf0005f857, 0xe85aed47e461d938],
    [0x945ab5c43b2a2834, 0x2035fb44084d451f, 0x659de6ae08c27f27],
    [0x37d99e83c7b4dab7, 0x2ff1a17370667a98, 0x449828cb301c1b4e],
    [0xa117f76f1ec9d242, 0x795f010a44d3475a, 0x52dbbd460c8e3c06],
    [0xf88c195028c21943, 0x36e412153720b9b4, 0x7c5759a246b54097],
    [0xa52eeda15a2db2d0, 0x7b11b3da15181cf8, 0xf2a12b52773cd426],
    [0xcb8321381a41d9d7, 0xc78ac65dbdb41406, 0x27cacd0b57bcba68],
    [0x75b09d20b9bcc45c, 0xa05d90c91c209a68, 0xb620957d8914f530],
    [0x95c6055ce8d2b439, 0x4873059ec41c4909, 0x930746776d1826d2],
    [0xa12a9d09e83f5747, 0xffbbae7e1bf46e75, 0xac03b4c4bae8d52d],
    [0x8dd13a2c781f81e0, 0x8a23bd970d3977f6, 0xb704a54da04fdec0],
    [0xa006a651db71bfc2, 0xc388df6dfa811c20, 0x73e879081281867c],
    [0x1297b2077f2f3eb3, 0x32940c8bfea5e983, 0x14d732077dcde274],
    [0xb52f017dd1b4ab84, 0x1bb299ec9a3bd2a7, 0xb1e0d3d58c191577],
    [0x0121c5ba73dede41, 0xaab51b4e99646cb9, 0x26fffc4ed69792cd],
    [0x9aa9a316329691b5, 0x3d5fd0c349b82d83, 0xff381d3983f15bf2],
    [0x8cffdb5887533c0b, 0xf6428e28c9e228cd, 0xa9ff535573df0302],
    [0x3643dff99e41aee8, 0x7dec4cb1d3388d98, 0x633fa15dfe1a5a60],
    [0x6c0203ebceb4389e, 0x54fdf5339b165055, 0x189bd28e459c00f3],
    [0x3ad5996b337ac19c, 0x3acbc1b9d88e91b0, 0xbbaed93037ea7119],
    [0xbce6daa5483d40b5, 0xc694fc7c1360d4e7, 0x99ba037b663729ec],
    [0x9efa37cc2cf72b98, 0x6ee0c8d2d1f95c76, 0x68d6d85bfdff7f40],
    [0x33545c9add2fc4f2, 0xa2e71202a794fb8f, 0x04f66d323875f229],
    [0x3d0b114dd0f563ec, 0xd112ec4b0b629203, 0xe180abe414838eef],
    [0x3f417badee8a3b33, 0x44ec5daba2e75a5f, 0x5fef4cbe8f1bf6d6],
    [0x3a2977eff978d9ce, 0x3683bdb2d5ab9570, 0x223a4ca9a65cad10],
    [0x234398805aeca2b0, 0xc503e5d945a796bb, 0xdbded41038ba6148],
    [0xd45a3472d2876bc1, 0xa8b1fb56acf95c33, 0x4007075db914c15d],
    [0x40558fa5abac1cf0, 0x05ca4f531db0b549, 0x2589a489e51271d6],
    [0x75dcc0981434105f, 0xf48985ed036284b1, 0xe48e3f06e54a6643],
    [0xdfdbaee72e4bed94, 0x711bc88403cd3c59, 0xaf15c9fe69baaaab],
    [0x60aa9c0b961ce13b, 0xed24368e0e70514c, 0xb7e411b8cc0e6149],
    [0xa68c91c370d66237, 0x5e2ddd632f88d79c, 0xa2b51dd94352a057],
    [0x69a5efce1c761a85, 0x998a36b41a9e4fdb, 0x0e906de297ae885c],
    [0xa6da4acb09b5a26d, 0xdcdbc7e7b695641c, 0x951b848dbb34c457],
    [0xf9fbbb629d30d0ef, 0x4bec6a55caaf90fd, 0x57aaaab36713ddad],
    [0x6d71e6c8df97f6fc, 0xb6aa848fc51be958, 0xd2f71019ee39ca03],
    [0x439d0325fc0660e7, 0xecec0738a47440ef, 0xcdf16d15bc644afd],
    [0xea97ea67cead4d88, 0xafd6b300f0239d33, 0x5313c8ae6ef1dbdd],
    [0x6b49be9e81b14391, 0x70493aa4eccc5b49, 0x66bf8f5db16d391c],
    [0x4b1760c8e98b0584, 0x49407cf492603980, 0x142f0b835a491bf4],
    [0xe6540cc09ebce66b, 0x0dde5ff3f20d7410, 0xcaae280540c477a6],
    [0xbd62a4c10ad88261, 0x92be8a91bfde3d7f, 0xf04ab49af69e6ec8],
    [0xec400dda0603a9a4, 0x96fb1d679a13a075, 0x650790b85adee5eb],
    [0x586049e267caec6c, 0x2666cf5c4bd942e1, 0x009e9578c0fa13ac],
    [0xfe3eccb6fc81cb28, 0xd4fe58ce171212c3, 0x3d9fc7530ab0f08e],
    [0xb3f72dbb590c78e2, 0x10d38a2a097d3e48, 0xd51efd4ec1ec6773],
    [0xff9121e769f0d337, 0xbdd4b00c6ac9054b, 0xd760924b0815f3cb],
    [0x9f6eb8ec0f9349ad, 0x5823090facf4013d, 0x90724d37ae6a36c2],
    [0x45c83ffe93839180, 0x419d1c544bd95dbd, 0xf88fc7d88ac4d10c],
    [0xcafab024bd30e08f, 0x700a0c5f61ad04e2, 0x1919ad08ae8e45cf],
    [0xaeedf87406f5471b, 0x7eb872d43f4cde81, 0x9e6af2785c355e51],
    [0xbc564381c7942430, 0x55f52d552c9cdfaa, 0xd0ccc75b6d85428a],
    [0x29230f43f1262943, 0x5d2992985553b72c, 0x516dc839ee031af6],
    [0x790172121a1d3893, 0xd310f29425592804, 0xe6f46d9ba3f2a3a3],
    [0x529b48dc89cbcff8, 0x11cd3dc43685c471, 0x3114e34e9a39720a],
]
;
