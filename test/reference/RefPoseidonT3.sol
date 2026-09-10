// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @title Circomlib-compatible Poseidon hash for two inputs
/// @notice T3 is a width-three state: zero capacity element plus two inputs.
/// @dev Uses circomlib's optimized constants and sparse partial-round matrices
///      over the BN254 scalar field. This is original Poseidon, not Poseidon2.
///      Round-specific diagonal basis changes normalize one coefficient in
///      each linear row without changing the permutation over the field.
///      Sparse lanes are canonicalized first, then reduced every fifth round:
///      four raw additions are overflow-safe because 5F is less than 2^256.
library RefPoseidonT3 {
    function hash(uint256[2] calldata) external pure returns (uint256) {
        assembly {
            let F := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            let state1 :=
                addmod(calldataload(0x04), 0xf1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864, F)
            let state2 :=
                addmod(calldataload(0x24), 0x8dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5, F)
            let scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 :=
                add(
                    0xec1ed6b0aa3700feff44e0a759f2b4c262fe2ee50c9768b71a7803d01ac5ef3,
                    add(state1, mulmod(state2, 0x301731d10f24f12067c346bbe953202fe02e434fe495c487fabc79f3cff2b9cd, F))
                )
            let scratch1 :=
                add(
                    0x1d5aaddd134eada14035ba6bf430139076ccd3bb9f5cec3cedbfba8f1547b587,
                    add(state1, mulmod(state2, 0xb38d34031cec5835cd0104c9c2ae6f112d30f022ebbe4785a2d8d98af0b9ebf, F))
                )
            let scratch2 :=
                add(
                    0x6ad2e6e37b641d198e7da14347b3c2e5f7ad4db75a76204507975ad8674d6ab,
                    add(state1, mulmod(state2, 0x1ae1fd406791c24e98e7cd57b218b58936a25881503ebdf589b9ccaaf86cb65, F))
                )
            let state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 :=
                add(
                    0x2eb6970a3ad1a1d216cb2de2816fed4c76bd123843edbbd06b21efe5f3cb21e0,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x1a6771d8a275c38d6fef5ea22a4feb75e4288bbd9c3a7f2824ee57351b235ed0, F)
                        ),
                        mulmod(scratch2, 0x2a35aa6c718d8f90f626e1a996e5ca03c1126c485e13af53d6e6a763527c9437, F)
                    )
                )
            state1 :=
                add(
                    0x9089a5b851d5e9ff40f301517b6c667a00f714cfb76dfd6e0ad9f1afd47ac73,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x15e06ce664c1e12e230d7e3f144e9c28d31103be7a16c4ed2715add26b641141, F)
                        ),
                        mulmod(scratch2, 0x1178528f2cdc1b48bbec1ad104058fe38060f66165b3d6018381df5f59454dea, F)
                    )
                )
            state2 :=
                add(
                    0x1fcc541d2587562dc61433ca4158bfc56b4e826d5ef1bdbc34d65e478383226a,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0x432b4b7c49af4468d98d173eea5406b3369cf2177c68b728e1fd268460e8529, F)
                        ),
                        mulmod(scratch2, 0x688cd4f68b0972d2df4ceb0c552e5a1996e8cb3fb10fabd46ba3a1874860f24, F)
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 := mulmod(mulmod(scratch0, scratch0, F), state0, F)
            scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 :=
                add(
                    0x6a4aa398f9b18b75c7e9df65bcfe499c55769b2f2a88edacd75b5eef4b338b8,
                    add(
                        add(state0, mulmod(state1, 0x2a11d92ba0f6532b1bbf772c056ba4613da8297a47509c2fca022892937df027, F)),
                        mulmod(state2, 0xf13856dfa71006b7873a3cb51b9d6ec9747274ca88275f83113c93cb574c40a, F)
                    )
                )
            scratch1 :=
                add(
                    0x1877b4efdadc7654549b692888831cb6c9f27940d5580488e67930078d678437,
                    add(
                        add(state0, mulmod(state1, 0x153207a1aea7d6d99b1d2e32066540feff8b7f215fc033ec81acd8d61954d4c7, F)),
                        mulmod(state2, 0x1cfa0c07daeacef91af779e76b5ae1b3f23c51091dfb2498e31baa25a5ad9d49, F)
                    )
                )
            scratch2 :=
                add(
                    0x112abdd33a135dbfc8724e4ef884287a22ef981515b36e59c22bae97dbe4e43,
                    add(
                        add(state0, mulmod(state1, 0x2cb0a1b70732f1fb62d1c685d8bd7efb2eb4a37ebb357bf1c5014ee113ff9ff2, F)),
                        mulmod(state2, 0xf6e7769354ae24f67def967a87db573def50485f0016722be62a5fa2fd20655, F)
                    )
                )
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 :=
                add(
                    0x7303431b8a75ed9a047ca5c50d8a82f1b37b6e583301cd77e02906aae19fac2,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x2a11d92ba0f6532b1bbf772c056ba4613da8297a47509c2fca022892937df027, F)
                        ),
                        mulmod(scratch2, 0xf13856dfa71006b7873a3cb51b9d6ec9747274ca88275f83113c93cb574c40a, F)
                    )
                )
            state1 :=
                add(
                    0x1a8f0ce3babe0a7f39f00e89ead8130b1954e8674c835f343e9c302f29bd6647,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x1883ae33581bd8d9257f5b2c8f59a1cce43cae13952d73773b8d3e54171cf812, F)
                        ),
                        mulmod(scratch2, 0x1a58e034fbab70d3a6075287c806cde350a3d3ab97d2f63d7ab781a4162d0f7d, F)
                    )
                )
            state2 :=
                add(
                    0x28f052a980f2257270aad6c459be27f4452a6e11b2846264213d140e93231878,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0xdea2b5c7dca6a116476c8e9f324dd68945fb8e9883d746511b5d059e3074019, F)
                        ),
                        mulmod(scratch2, 0x24bf4aded329da4ecb0c92fda18ea0ee89436b726016d0b38a7954f1664047bc, F)
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x13ac827f4d4f4d52674ce6b00fc2829013988c32eec59cdf7ffe0d8e44c50ba2
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x26b6edb8c54b2f9d9437ff31346b7ac58d6b5687e612a78e0f9e6d97c13f226c, F)),
                    mulmod(state2, 0x6e5e87573f024c3a8779b71478837052615966bc9240cfa912e2fe93435f8cd, F)
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x33888f0512f59bd08d79ab91f87cc7449a4ca2a990087fc16335a0e10e12ab7, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x290702469821b6a3838c2d1bd70c6f841a9ecac213b0a4d1b3d2d2f1f23a05fc, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x27619f25e27d1de7df17db69a7b60cfaf1e15e601597c1ddbaa1314f5792b3be
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2692f7684ff63d86d96a88f199ef9d61c7d4bc077b122e66c03671e7ddbac3e6, F)),
                    mulmod(scratch2, 0x5177da51dc609f68d5959c2c5bc5fc024b4a13c3bd7f2789d4119076efceeb2, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x1ecab58ff3efcc432a9146c0ad8c1f777caa41802536f8a9b62899de203d19da, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x764a5bcf27cfcae3e1936d335d7331f017e64b97018e9660e13a8c00a620e7a, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2bc3f8fbfc19beb0a913762ff205a17181a42da7f0ff866cbc71412ea916a9c7
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xb3397881334c2f9ff5185d4daf6d35998d3a21753c44783e884e06481ba28b9, F)),
                    mulmod(state2, 0x2fef2c31a1d96d21bdf31c8c7e601d558dfd259398c154943db174c88318616a, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xa6b93cf5f863a052db0c39280fd14c828302b1b183bd500952bec9b03fee9f2, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x140c0089ab89ff81beb73f98dd4eabe62cff599c4e0d2e4635970b94794381a7, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1d64bf1b7d73927515fa2e39282fe34d342b0d3eb14d00f40cefc912374477aa
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x29ddc63e295bc348db792f4a6c2004e49714e2ab49306f1c49be670abaeb2d68, F)),
                    mulmod(scratch2, 0x1387357bf22253c03010942d0a6db67ad2bd2c5a8b63ceee6cd94e657cfcf58a, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x1a94e1ef2d1150c8f9f92a55fbea29f9bf2d51df7dce6560cac921810b6ba110, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2f4f241e6eb0a804d26bc7621bc94cda5e93386b36aea9851cf1c99cf1d103e1, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2cd09725e8ec5877da430726aef2a124e0dcc2cecda04c043395f83ddc29a2cf
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1ae8cd4784fe69e0675a0359a37056dbd9945f15a0fd0fb3fa4aad7a781cca44, F)),
                    mulmod(state2, 0x20a67263e4f5da60a4fbe73ef5cd82877a69be7fa1c2305050064f7c755541d0, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xb7b74e991bbc8cb6f9f2c4373090c4251cf4d16b3ec89bf8dfcaaab62762549, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x967a212c415621c868de6bc7c9021473ae1d1c74b2e6a31ab1f149e3dce7033, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xa7d691d3a64476c08eae541abb8fecd53e1f8bbb6540288be89b9a0218b273a
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x3578cf6c92ff554137ed06f8c5c1e380d86ff14899bf69bed0aa7e1c5740b4e, F)),
                    mulmod(scratch2, 0x1ab040ca42e8486b9f11afb2bad0a8ff3d0bbfb1dad7d3408abfb1dc92a1eea7, F)
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x2d32a67e8a0d4156166b9e556ce3c3f8c3a7a653563774333c8f9d05d4957da1, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x2bfb076880547a9ac1214538cfa4c1669ab1ee14c7d5f29094be814e07cb35e9, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x28a9b24d4706b38393663a888a9fbcc85bdea8670e41fd09bf08fc30c0f80946
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xe88d5cd39b3c568c4b0a60fa931710d11970f04c1560d3aea46fb00edf88d9, F)),
                    mulmod(state2, 0x28141741bb8473b45bc736d183abdcfbbe2944f29ecc7ebc99d83a2072a9599a, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x236e3af25ded076cd5fc6c07533a43d5b2d6738b89df3a16b69271ab988161a0, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x17bb6d591f29048a22e2846247450b3867b6ac8d5683bcb99fc4be724f71a5db, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1a40dc8b3191d4d2ae43c90b50c77d575a7d841651f6c08d71c4e1d0b7aad6c9
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xa55d56205ddc2e2b28cb8faa3d20303259e27a3bee06e1f8eb2367b56c1caa2, F)),
                    mulmod(scratch2, 0x76f1ef2e3c5cd0d5251bc0e90e42181c584d527289272556fd2b79f730b7c1e, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2ed8cb5649e3efa28726801007354f9a4323298c3f2ba18e4abee7aaafdfc054, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1569ff1fdefb6b2c02bbe8c8b5f039df7d62b37f76316821325e690d4b5b24b, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2b25b8cee07ac1fb9be1ea575c89ea2c073e6b32b3af40cba625bf127d9f008f
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xf99c74ff13cff3dc507f0b9062badbef6d21f09af023d0c749fd44c37d2633d, F)),
                    mulmod(state2, 0x98b4447fd1eac10f5dca3eb9273b3276b3994424e1c0fdae2bd94298f3615c9, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x428d58eea66289feb653e61fdf975188272924a640be2127bb6f6d5a4b82dde, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xfa183e2cf3877ca3c92e63ead6f578525ca0ce595de406d4007948a2d505503, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2276d4f68795d3dae3a558d3df64e7140b5fabfda8cc440bd7c10f6febcd1ce2
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x205101ce4cf78a54ee983404adb0c9381239c5b49d1cd4c571eda7784c77deb6, F)),
                    mulmod(scratch2, 0x37583d69c1edadc82bfb1bc9d349d89360588a8f9995f6c47471af12c0f6184, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x426ab36558a00d48b97520e8e1fb6f64862bfa650fc1af85f3d127b537889e6, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2144faa9c3d4f334da0b0be14abbc3c149dd867811e6c2d343952a84bf834bc, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xea9cbaeb12a59fba22bbeea7b191590065825d41415ca978d0d42aed15c25fb
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x14ed31639475411fefd724919caa6e3635625b77a0809e1a6c1514f8f9fc32a0, F)),
                    mulmod(state2, 0x26f259b5774bb8d13793852d4300bd72edc67e8c2683b2136eb81ab2118028c5, F)
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x89a976f70e2ba415bd76496fa3e59ffc5720115b37c80db5e14d864c8542557, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0xaf049fb4ac75f1f17a1b922774263562c4f7812dd0c6292b2f0e63010b77d2a, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2ab1770646a9b3cca3bcb1e0600d772b760500b23a0d8f5fd6a749e9d5f23054
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x23f72aa19427186f949136b1925a2d68f1b4c8ae4a957ae4ad3dd80adf8fee98, F)),
                    mulmod(scratch2, 0x27dfaec5f9fe93484bdd8c897f1f88264b61d01b7c5243ec9a9f015fe5b50779, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x20ccb7046d5c9899dacebb9cf4b5a07eb3221c6b7be3b3e72417c93d67b39dc8, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1c36cb0ada6ce01f3f0d637472f1d8c1a811e3b62fd257996b55a3fc5585c3b, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x20a43fc11aef6eb80b6a91e69d14a0fe5a70a964fc4b263e7265316f5014531d
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xa446b756014cada513678284c1dd4a7af024a9b48037462cb4d5763f1999ecd, F)),
                    mulmod(state2, 0x1da8a44bfc0edde778840b5e982cdc6aa1aee79554028d6eb5f04bdb50642f6, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2b982df1166216ec2bc4d1969929ab7a95db79f0e7cfae8ceaa781b91306c074, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x182314a57d2f2665292a0bbc12c36c4dca889e96be5bcb636377135a7a965712, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2adf272349889ac925bfba0a3cc1b42342087b0d06c7220532248bee4ed22d54
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xbd9c7a5a3a58b6474810c6110f9d637405f59df6a97d8ec820cfe66d1de6399, F)),
                    mulmod(scratch2, 0x2e2bf766641bab87f6aacd082a3a38245eeabd5645105af6d1aa138191f1173f, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x278691f5b8fc27cb84a2ba40535295d8b0425392929c7da515efe6ad885807be, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2266ce692d783cd0bfcb1def613a3db4e2657e67912e21cffbc8ec87128adf48, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x11a2ce78c1c74748f8a7925ae72666710a739e0dc1069b0c482a2a536875242
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x795f6e20683fde735bf7ceab0cf99b9c9ea26d6308f1893997b27bb785989c4, F)),
                    mulmod(state2, 0x551ae36a1e517edcf0edcb20b0dc97b9b3fdce6543d7405632e19c3c2fdb5a3, F)
                )
            scratch1 := add(state1, mulmod(state0, 0x38f60bfbbaaa735c185be5479650691d40d60eef6250d60aac5fc34efa6d79, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xcea94fcb618eb69ed2d9355dd12ce1eb5a8b6949a7cf16bffe7e0755ef6ba6b, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xf551884ade865cce466adb8c28c4975b48aa9ff2704c65ed1f261e6ad04ac31
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x11fc7d6ccd1154916577c4f92576a9049cbcbcea6aed2412f5a7abf1ade944a2, F)),
                    mulmod(scratch2, 0x2bcdae8242d9fc4e63a2e53b3e6d1fe9169571f6b42d0c835be8d0421ffd29f0, F)
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x1a54851e6caba0102d09ee56d77410e0409651c07948cf2719ca0b4d4f763798, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0xb1ca945080e51b3a5d78e1d50e38592199df9a267ddbbc82d0848ee6820107d, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x8dddb79af88ad4cc89a6b98c5161fb9fa84ab9685085d46d6d7f32d2dc40305
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1fca6dc116943f7646ea1f630e21862388d9b4efc68b9e0971ffc0440f081d83, F)),
                    mulmod(state2, 0x51b67c6550e23a7e60a1d38ec818e042dfb53176e4919bcd62f73e086fd80b4, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xb66b6851492c12baf097bbbd9e64b435abdd6b270371778a2911d8f42439729, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x10b29f33669897673a42e8ba09563b31fa30647a0824eb8af12feb74da4b090d, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2638d156f3c636dbf84d90b7dc6c80829217a709ccf55070c0d04abb14a09541
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x22c4686749f8544cf65332fc7031abbb3ae587feb3ca38fe1e672d3bc0935898, F)),
                    mulmod(scratch2, 0x2b4393cb26512e442c01b112ef0c5957497b9f49e74f9afa1861cc276c6f3dcc, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2fea110f4ed6f219af61895274d9da07290a71825bbdb14d2b2d9366e89ee2a2, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1efa23f6904d4138a828e88444fca9dcae144e41f3cf311e179f5e3dfed9a77, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1b28eba6a33a0b4ffef38ea5eb784e8970916bfaf4b4be0bf0791f0d6cb8b341
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xe7a3bd1124b7ea38965b939fec6771a0eb8d532f2d4257792d7b9f7783785c8, F)),
                    mulmod(state2, 0x135c322ef46a98d52a00b0cd146036d77861c4cc395585806c5871bc8a4a0520, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x15113e6c2181c324f9cb70b894f901040d1fe8af1a85668ac0dc6bd21cf2b174, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2e34c32bc91503a73838aabde3cd25aad9dcea6ac2f928d21f56deae1baf3ff4, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xa4f6dc268156b07e5da854536791540a7418367a3ddbd61283094aee0b78c13
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x18989dbfbd816b021b42ba25bb60b2f5035c1dac9045c896c77c2b7cdef97d05, F)),
                    mulmod(scratch2, 0x78ff72eeb194b7a8549f98a8e317064d4fda99411a715c026a20f3b6a382826, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2693bbab972377173743ea5c34ff129ae9cf87f44a52b8054dc479e6b83f5b7d, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2558d18c115098c19472f0f41f3e314f0b2f177692e3e7eae6ab4aa4a1768c2a, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1cfe79b4efe2f4d519e2b3b97fecf84a9f269a89f8edc0fed7ae5c9ccc9fa612
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x9105181316e9dcfaba552843d4146693e116b75f136756c38c25681508e66cc, F)),
                    mulmod(state2, 0x23421d1401a0edbce0e2fbf25c94a6b0c3934efa1bd30afd5c19a4f54d50de99, F)
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0xfb5089df3c99f39883c3e89c0c73d3348fd83a6ea48c2c2d1803f2eec580a49, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x24bfbec049d312cbee91bb8e33ac64fcb3be097cd19162c270c2f9ce878e2f63, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x107de28929daeff4ab5f04ef39c8a583887cacae5ba56d63889d9ae5b8e6c624
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2c2c7ee4f67f4af62efe5de98280e30d9730f246d43449dd5c8523801fcd8ea, F)),
                    mulmod(scratch2, 0x1dc610517d9428c7e232e4f69598b7680be52190fd7e8caa58cfc305d158e0a2, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0xb2397c74565bcd8e171fd971eb7e06eb004554135f7301ae5be7e675bfac1a7, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x3a2da33f0164298372286a8b2116108ddfaf7980a1b05bf80b4f6c2c34ab608, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x8758efd7ac47ad6efa5285bf005b9bbe14eddc6122644cf9116fa3e51fb32e1
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2edf8fe0021cefab0441203ae442230396e3bfa290120d8f6c16a4b685814d8d, F)),
                    mulmod(state2, 0x204c66cea7c23b90ee7b803246c2aa835f1be7a63ea9408e04c9be691fd85e71, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xdc3d1b27afc2bb5eaa9e33d1829c6b2d1bd4335e2d9b5c2d1401c9d8e330c32, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x1adc44e7d9ee2f1ba736df04e5a3a1a1efda7f2321c8457c6d6191703dd56dc6, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xda87c31f917a17671de4f74c677e27c2e1d80b6d26c3ccdfe921e2db22b218d
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x17101db44c1decf3b4af787d37bfc0946f6c8827a1e9ee3c21ed524ddee5e471, F)),
                    mulmod(scratch2, 0x2f08ed4f1e750c7c32c027fad209f226c6688661bfc9a5c6641807daf67f0f2f, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x17ca1fc0bdd39a9afdc1de8198f020f37a169964645d564bd138db0f86a43857, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0xfe9705e40bb73a24ffe0fd667bb81c232c673297810af67e4840dbc3e1c788c, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x157b031c09640c8da934682c38ff4ef77b00b974919a075884d4c2f55541d29c
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1a3be42b3214fcc3cbed784346e5c9b496d7e7d7439acbc205da286e7efd68d2, F)),
                    mulmod(state2, 0xe1cb5e0c12e1e0eafc471d04e8ff5a4edb45abcc7ef478cc0995dcdede9532a, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xdb687a4fa00987effff7268472be9cd04a372e4d4c64f219daa5e75e1b2aac5, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2f50308113ab770a5706ffc4a383903228014c6659fff8604301ae088c9d4710, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x569e550a08befd6f1cb63221a353317130f6f7c8e8a725125b98bd90d261a50
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x290b607a737e6b650df9be8a01db5299c6124fc6622e4abf80f1264c9785719b, F)),
                    mulmod(scratch2, 0x105ee562dae48a0910e64c38e0901058966aab00450f248a1f108ce7dc92930c, F)
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x14a9ef7764a04918a96273e5df38e730009e3423bbac4f6ff70d0fb1d454706e, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x12fb7c1abd133f99d5950f924465fefa9bb3e729a8cd9b098f68b8c639222efb, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x116cc523d65b0ee44240b94af9ec74bffb7694606bee5690ad70fe6415cf9e8f
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x5cdcb78cab9f971edbc5692dae51d36efadcdbc39afef890986eebf05e27f2b, F)),
                    mulmod(state2, 0xf3619a414227ad12e1ee72ab401e8f44d7c601b2611d910f1b6cf48d5a3a60a, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x13b7d1daf1abdb08be8157d9266876d5147551e560d5341cc1acf78f8244dc1f, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x106514f71c74f2c8d8032b5713671e755f49d5730d3a95f7b9f14967ca9ac4be, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x173f869b6f30db480954302dc47de03e28b569f4ec341594b1ee94adf3ce377
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x17f5231d0aaae59cd36af0daf7374847ab590a7e8bcc3d8f3abf141f40b841b8, F)),
                    mulmod(scratch2, 0xead0703d5763f50b1626147acc78988d6fbbbadf119817bd13336cb57ae4e73, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2aae25a94a4e9b015d7b89f92ed650dfffd256990381b63d657a8d253e083917, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x277eae83ef044e8530c74af8f99a1630fd5414b7ca2201bd2c0d663c82f0d25d, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2c8ec92ee65d48b398953c7eed8b0727d893a10d888e372ee5fdaae39f82e0c2
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x166e1cda20e25bb0d9c8874238d2a2dd28d6acbbe4b2aa385d8e0b845e88492, F)),
                    mulmod(state2, 0x1e95c463ae548e42b775f61af153eda7ba57d0882b22959acc9f5f8d9d0bf66, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x15ef1aea3088c09d82426c39c3ffb1aecc715cc6ac1c31ade22dfd85918a4677, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x287421b7800b2a6098440ac6796954e8e07258f54b7649ef27881b6c63b49860, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x72ae0a9866365a88e634709287989f8ecd207a4fe5206adb1289c0ea89f4409
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x153200b90b89dc3777258a7291c8f21b38003b9fe2a45b42400dcff3446622c4, F)),
                    mulmod(scratch2, 0xd69d841943d616264d54ea71c4c9c7758c211db17de035981d44d77b355ca7d, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x1bb663e2de5126d084ac6b9011ee109a876a98ca1cc8439d168171af4a207075, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x6ceb0a34631504b5f00a93aaa13efaf036e03b61e646e3b04422c785e049ee, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1a1f2d9d5a015a1c1b25bfdf8ba86ef99c7dc3bb273b2dde6abcbd5aa30a9281
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2470ef1e625b7096c9f46d18d245e6583b19d9dd02987fc32a86e535bdd0afe7, F)),
                    mulmod(state2, 0x21e48602a5770361f04bce5b0a2eaff4a22febd51eb94cf0637a00829599cc95, F)
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x1efd69c4acf5e3a88daf2d3ed00eec550692bc76695fdf77c5a45cd2d62e6f0a, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x1ebe182e753f88900d71b07d09b5ea9ef807abcdc642dfd5b04ee498deb9576b, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2c9e21fbbbd81fa36728d81981857ad6c9bc57300f9bc095df2b53de4875facb
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xf0a5c39faab4291e7b80e08eb352827f3ee5477b30e74d4435770b1af48a759, F)),
                    mulmod(scratch2, 0x6fe70b7329b1b6528a56befb370d6efc5e8bd023754c8facd888c34baa5af47, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2518469c90f5342618b077b40f6c309cf4a62c8e023afecdd0846bcfc9bac63, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2a6b29b0172426d1a3c560feeae7df7c3574df9077446edd6b6e7d3bf69f630f, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2f51eeac8c2b185be6f9a47b49ab09806ebffb54dd33863beb2f7518ebe61ba2
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1bdaa74e5248ae047cbf72d5ae86200dc76818cbde8e3d3e660fd19c53473db2, F)),
                    mulmod(state2, 0x1f5bf39446e2aa7c35b8d600e7c2ef006e26019c85480b748b8dadb13f2c56c7, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x1dd4790a9c8d843080fd91f7cbbf42ffb386ad53b9f725ed7769561d13635608, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xadf684849421be59332da1d2b976c4771c01871e8b86f5452d520236dc90676, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1f7ef4ae162c729d4a9c3c268cb7f3db701cae6a617aa47b5e5461674e89062a
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x18cfafe2f9f2dea4bef010bae14f68d930014fd379ec4a982516baf6270c3960, F)),
                    mulmod(scratch2, 0x1e5c8481459ac532d4669c372761707be4c748250d2198f7d74c1b626711b6bb, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x42504663512cfa990374d3ece688ec531322ad844f796cbacbad6401d37ce26, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0xe2c2e817c668592c4d2df58f063a9d20133775f4cbda5486154253397b542c0, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1b03512091a2c4b0bd3b48e3e52822c2c8757a9cf4d95aba951de3e3a6eb70c0
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x21063b7ea1953bee67b3da95215df8713c587ce4bd5fb44d4ada280ff979ee4, F)),
                    mulmod(state2, 0x805c3a4f650fde6098acb1196a05097ef2a820301255df10ec998af4d9bdaa, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xcd2bdc9e1d4ec2679cfe23523e86d5fb9475a9db33ed498ea5096733a510f9a, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xc93958fe92ce0ba377582cc3b1708e73dde683c3eabcd86aa895c85058d6968, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xac1f2b712407a047d3b09353ce401180556af39e6a423b68f3a5f3a425793a4
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2aed56a394b7a3be5cb883a161e67fe8bb38b0a03dd2d62ba345f754df7eaaa3, F)),
                    mulmod(scratch2, 0x45c710580c307a417fb1a31398aec9ee3145e0c65b1f04c0b341423cc25fbcb, F)
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x139fe8c8dae7e13dbe088ccdb5b4ffb789ba9511f36c0247086d5bfeda7eafb1, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x22acd4a7a5b8d64877d02e1d802f182e3d48670491ae700994b2cd223d7319db, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1ba56d092b35f9a7e5e2c261e28c6f4035495555d146ac28e4e5104a1288268
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x25bf67a984597cfa94b37b5911eefd1cace687a562c54d4b280860dbff91fe29, F)),
                    mulmod(state2, 0x7d3204f3fe624e0f6e1b964b22cf85b22b920f4592ad0cc7165aea4e0a752cb, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x14d7a84fd4105daa607f0b3e0bc43bbe01c7db6724eb0a312c70f174e4607456, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x18425abd34aa1cb6802479939d49c615e97df39ad96f71ea12b9de1e21ea2f7b, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2171589faf3725d51ddfa54d7bf05c0f5b6de96b8ab43499923194e4d944555e
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xba0e6e647bb08caa5b9b4374debfe00999c4116573925d801ab3aada0a2c6e9, F)),
                    mulmod(scratch2, 0x1b1683bd35cac3c3a720f34292553dfcc11710bf9b27c5069057657baf14278d, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x78beddf51db3083b3c8a1d90ff1c44f78523053ee0fcd41a3f02fb93f880de5, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x24e5fab961c5cd2f04d3b69e731e339ccb92cb86f73fb4781368789f79ea0b51, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x9b1ef839f0ac493b74c1c5c3cf4f9ee940e45f436d65ba5f79d65fde9eaaa0
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x155bc463d01335435e56cb1200ce7fc701da87741f5b348d5e07981fc794bf03, F)),
                    mulmod(state2, 0x27e3fc067334fbcbd5ab34b9e7f29c898ca8a85788c45a1a8350ba9aa9a8e8d7, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x9865e68499422d910ca63d302b4e182c896f6df242b79d27f50bc61926bdd62, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x57bb82118c13e13f6beae858a1e2c2cdbffdcd6a9d1367a98053e9da310441f, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x209e7588bd42ea7bf92095372cfe6ab8882d423093b26c18057b443cdf32557e
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2fecb5130621898549502c8cba73cbcff8b98e2f54245ee1b24acfe823dfc777, F)),
                    mulmod(scratch2, 0x47a3993fd007435d3076627834c479751f0944c5da0554f8764e1f61398f4e7, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x898eb7151575da2712bf7998dba84a09144008c198b0b886e9d3361bd8d3cff, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x4bcd91da64e1f02a51daa99a9a830cec041d846027ec99d37638e9d34aee6b9, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xf4c6ac844a1a36e68dac19d3495c0caf8eabd327a0311d50d09439457b3c6be
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x171626a146368ddebf983b21c5510d0c8c4c8f57d2a44b3ebaf1361e97438ba, F)),
                    mulmod(state2, 0x242692d9f0faf66ec570d3ee7215b283edbeebdadf84442f3abb7d715ab4fa93, F)
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x222fa109ebd01b95f940ae5c3ea83365fce53f04aa2602e3fad1dbd93cf69c85, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x1fb33b6a83648325e8baa27e56683411459b85a07bb16a7bc9dc73dbf8e267f9, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1eece32f9736535dff7d1fcc1e167ca1da0124f4c17a721aa62782b01b4d643d
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x24d307dbe10e34d0e477981fb91745e50000df3b4d13a892e80f50e4ce99953e, F)),
                    mulmod(scratch2, 0x1431016268efef07cd2b39e3b4be9a5f5be0231fb83022b598a0d6981d49cb22, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x21b5324e2dbd2103eb57f53d9848a19e551d0bed5b678d7059e7a4378f1903f6, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x6e983dc8cca88b3617d0c72e968fa8c7323d8d666c8ad0dc0d78a29a7e58013, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x128775e774b086895e982fb1fdca05d420c717d87f09c1273eebb1d8668e77c
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x201228d04e82a4cca7d0e50a4713a9300fd2a073eb040c9b1a4e6bdc995cd8ad, F)),
                    mulmod(state2, 0x2e91e8b9e659adc74fe6c29398e07b8673dae4b45f9239b6031f58159c52ac2c, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x22f9bb242d490418a1cf2645298c8d34fbfacde47db12a6d24cbbc4bdf539595, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x4aa7abc8466c00aac0745a0fa2014a2d283dcf399cae90b4e48b9bfb0c64b60, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x19408fd6c9b7a2e4f9126bb3c25fb4deb4a684a767578c07a5aa4f269553a9ce
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xa1258c904daf0161ad8903a626cddaf53ccd049847c2210485ddd406f0a1971, F)),
                    mulmod(scratch2, 0xe6d911404ff6fdb81ff44c8a2facc41403733e0fa20569976ca6f989a82fdc8, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x115c71a97f3d268021de74e9b005372301445d0d8d7073a225a039296b6c9e50, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x18fbedd98bfa9ffaf643a66a673dad5edeaacbcf5faebd15a57e8e433c61876c, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x121d9d7f78084181b3cbdae3b405a222f0d37bd969c9b839e71be5569075c7f6
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x188d7a36a8851a4ffaa23e614d52016dcb7c8e6e97f8d0caaa53f60d635da0e3, F)),
                    mulmod(state2, 0x1d9847a8a8af5f3fecdd83866fdd448b46c1327238e343753f390e98965bb115, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x18206e502088634fe94544607d773e2ec5252f21436cdbaf9c52cb43587a9d5a, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2568b34f45900dcd0aa412acf69519008a6a004255333551f3b08e363a6e7204, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x62f8f7820471019bd21009938644ff9d819b0fdb83a74aeb0e7e5720d7443f
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x19778eb4153f3436be6e398e115be7fd7a4d5377843910423d294362a4cf012b, F)),
                    mulmod(scratch2, 0x251b1fc96c3361da112a87cb8e2fd94814d0f9de769d126419790d8b32fdff3, F)
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x1d800606af27cfd2d71edc055f03a4af4950d8a3cfafa44a2b7c54949290ec6f, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x226148da79d240fa1202bd0aa5fb96895243c19e719093b60d0574767265e5dd, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x104f76d269c18ea503f648bd9d050c75cc77360c293ee4eb9fa0c73947f87c3b
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x10cc4ad3c23dbb48954150fd681f59821e4fa2c4d08e6891cd23e7785d88bee, F)),
                    mulmod(state2, 0x256128e27490d3dd6b8ea3c712f48471cf75a185716f72ef16304e76851ceb33, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2f17caeb2041919353ad25ea64295683051c4af6dc6ee0d1a28d9788581bb02, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x833143e4802c7ce27cb8467dc50e4c2ac0f804e22a97cd79eb66958e8de3563, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x10d84b66599b67b26a7bd9fc006ab3960e1089b5f2042a0fdc7a035423d169b9
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x277bbbbbc19814de31713b6bfbbe7366b851622a829ce6e7907eeeb7db7f5dbe, F)),
                    mulmod(scratch2, 0x20205c9f7aa6988aa2b78ac4220379d1c082bd124f9915acdfac2f95cab9c951, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x759d6e66eb8eaf75d3b6f230212208da9ef81906615b72d33ba897b40bece3d, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x23351993e0b6dc35bc1ff12fcf9c575acb9e0890da31b64f9ace397d22fdb6ef, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1ee4ce08b338b2b122a3adbe6d8d8932dcddc2b7edb9a2b63c635737a740e371
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xcae71ac677b6a9f957831e4ccf8cd31b5d28429e5e382693ad391142ab55d9f, F)),
                    mulmod(state2, 0x8de348cbc74be1a64e3ae0af019fd3012df822cbe3f0551cd5f8c94c7f78085, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x10d6e2589e612ee7836b477347a63db17dac5fa5e64db292609ecdfb07b848c8, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xdce900ffb3fac3d7580dea79ac26f8efb08ad797b4abb19432b803c7e08d1e2, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x11104d0bfd38d48e2cc653bc92c20dd6a9860bba2e2f6a476275cf956a16ce5
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x8554b15b92ab29bc805ba2ccb76a983e82bd4c6fd6162febfb25c835898c7e9, F)),
                    mulmod(scratch2, 0x13ad8d306578bfb6e83c85f896905d6036b4cf194845e726f3f9bfb1acfec486, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x38620c4140a687cd0f56935f2f5d2c00604d21cf02e0711455199dfbdf2ed69, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0xe28e9a591c0524a10ea9e73390d15bd95a6121e92071a9bef12e93449064af3, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x125def7b39b9898bb37f49ec54f862847da6501e6a9eb0ab7269803919803442
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xeca2b0c084b01e31ee7ad89ac0e8bdb20f592817fd43e8d03d0516d998f7420, F)),
                    mulmod(state2, 0x99d3e842186df17debdceb8ae01b9469199185434c17b3235abcb0f6340330e, F)
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x24a243e3373ade7af3f5bf78b8e1d5c2ed9a99c158d06743064cc62eba45781, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0xc0e4315cd316752e1ac8cc08d898f7bf088482ba55d96ac79b25e09ee9baac, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xe3d405cbcf023646f8754e818b0d20bd002147cf7bef530173c84494a0fafca
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2ebc5d46d15255fdf4b11d9ae2f37ef610854124c0edf20da22751b2868c14de, F)),
                    mulmod(scratch2, 0x2c8f9d67b00236b4191eee2e431277bce07bd5dd9469bca348e44d54eb267906, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0xff0885082ea3e016838abb335ea04e7874520e58ba4d371a3d70d49100fdded, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1001872e48edbf137de97b4f14f0065697dc09a802bde1ce12752f55bc200ff7, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x192112dad845318f68223b5a516105f810caf6d8c84d7f9599c158eedba0b1cb
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2770dd08e6e3f9de8f0ad1df6181d2d78cdff6952a9c007c83bf636faa2b77ff, F)),
                    mulmod(state2, 0xccefe058e0a68396f5b0c4e65b8de058a806080a37aeb094e474d263ca4681c, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2fb2d43cf82e1a0ab2b55ac61d5bbabfca6a8783e3b730a95178633f5563755f, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x1fe79867de1729f1ab26af0579d877166e5376352ae537244e2346758d6eef7, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x26c08eac253e24ad1bead00a6230bac2ac33f37eab164226353a9adabaf7c4fd
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x16b5677dd6c72ab1240a8934d506d74e9d4d918c6807e918f6bf4d72b92b7a2, F)),
                    mulmod(scratch2, 0x2a4e86dfa0c49c7fa56650f7d24cd46b548c34c1ba4e52b5a8f25fae386a3131, F)
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x83053e92e8e3ea619bd0a8b94c832fb836b4f534d1eab8a15e4d198fcba595a, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2d20b17f8d769f53e14a7800dfad7922eff0fbce0af192604b0d43a00c61a11c, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2a0012e5a0d9fd8ea4cb42b48a982c10e27395f06ec5309bc5760cd088475663
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x18a5c7c79d07003a893a468ea92e3f64784a3a196d15f3d0088ab83963555cd8, F)),
                    mulmod(state2, 0x2f975785053a7f90b64936ea8044b78d9a00fb48bd10fb1f634425f7d46c3bbb, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x14bb4810523838d514cedfa36e1fa9dba8ae5790342f810854698b54688164b1, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xeb142787b3bf6b377d0fceed881546a9cb1352b3ead74f8d2ab9884b6d9c24a, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x253cde58025ad29a533734c0168961a67b222400f8dbcb4da3fad1e493a0b759
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x186a23a2cb67334b2363ba06002cdfa9ce739732a9de3a4a2ac6bec1297d27a0, F)),
                    mulmod(scratch2, 0x250ce6cbb2c4979f6a1c588cded50cfae08c7d938ae0822abbc799ef02b7722, F)
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x150f4a46a99b2e4dc974b74fe99d2a97528ce6a76d23dff4e2f85a963b220998, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x11837cd818cc602ebccf245880a733db7707038af306a099c81d818e68ebbc41, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1095fe6ca15216fe9489925ffba8434b3bb8f533d3b70c0e096ba358b85de1c4
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2dddc4c9caf01714ba7c337b9f66fff6cf6f9efffef425b3862b518e7d5f11cb, F)),
                    mulmod(state2, 0x29cd2e85ae1c3712bd7d1f8f74f8d7bbad4de101982e083410a6f76694221a11, F)
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x918c128f87746b43bc18e31a0e4c78b98a9f1a411295791b6eaef0350f08ebd, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x174d07cf0d458e07c552f7add458236bf24df5f60abb07e8b5210cb0deee3ce8, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 :=
                add(
                    0x20b767fadad90659c04b80736bde11e5ba72fa602bf07c1c3b0cb0e610e139f5,
                    add(
                        add(scratch0, mulmod(scratch1, 0x980645c35c928e00d1d083f7976e9300a74c2193c8752484904a0075ba7c5f, F)),
                        mulmod(scratch2, 0x651d5e11b17160b4e4d68e4659b8edaa24f0ff23bf51306041ad53f315ed5f5, F)
                    )
                )
            state1 :=
                add(
                    0x166c7ba02e36639e6b8221bf318d7a0e632bd3376083e00bdda75b27bfede695,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x132b9ed8af9efb088c842cef47ff7b9668888784f56a1d469deccbcea5bc2ca7, F)
                        ),
                        mulmod(scratch2, 0x2fada2e9a4b0edbac97e0380af3ca9238aa8375f9fde9a6bb9a39b6e372a137d, F)
                    )
                )
            state2 :=
                add(
                    0x1b41bed549bf66cac323f7e454211a252e31658253ed1aff7594f9d3c40029d4,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0x1f7a7acd10543163e107b10ab4eeed1b918f4b6eb7d487a85ce7b8b6f8beb98, F)
                        ),
                        mulmod(scratch2, 0xde17a144e1b9e7baf1cbd7056a4bdb0a347f61c317266835a42ea568d29df, F)
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 := mulmod(mulmod(scratch0, scratch0, F), state0, F)
            scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 :=
                add(
                    0xb10635ea87e23b264ba4f6afd8bb26e8ac116b9121d42224de752003412aa02,
                    add(
                        add(state0, mulmod(state1, 0x2a11d92ba0f6532b1bbf772c056ba4613da8297a47509c2fca022892937df027, F)),
                        mulmod(state2, 0xf13856dfa71006b7873a3cb51b9d6ec9747274ca88275f83113c93cb574c40a, F)
                    )
                )
            scratch1 :=
                add(
                    0x1d4abef5d3468062a4c35813d4cf1a5554d60621cee623de1358a1aa7da6073,
                    add(
                        add(state0, mulmod(state1, 0x153207a1aea7d6d99b1d2e32066540feff8b7f215fc033ec81acd8d61954d4c7, F)),
                        mulmod(state2, 0x1cfa0c07daeacef91af779e76b5ae1b3f23c51091dfb2498e31baa25a5ad9d49, F)
                    )
                )
            scratch2 :=
                add(
                    0xe7a5f7abcaab8b2b7bc9db43c1697b75ea0a72e45c2a6db8fdc0b4f8cb923a2,
                    add(
                        add(state0, mulmod(state1, 0x2cb0a1b70732f1fb62d1c685d8bd7efb2eb4a37ebb357bf1c5014ee113ff9ff2, F)),
                        mulmod(state2, 0xf6e7769354ae24f67def967a87db573def50485f0016722be62a5fa2fd20655, F)
                    )
                )
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 :=
                add(
                    0x12df414e169d05a9fd01b0b6b64780612385a5e6e61ac299cfd9af0866cdf2de,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x2a11d92ba0f6532b1bbf772c056ba4613da8297a47509c2fca022892937df027, F)
                        ),
                        mulmod(scratch2, 0xf13856dfa71006b7873a3cb51b9d6ec9747274ca88275f83113c93cb574c40a, F)
                    )
                )
            state1 :=
                add(
                    0x259da0dfa44763e26abbcc3622527cc418afc9a97100e7d2b80130fd70de7ba,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x153207a1aea7d6d99b1d2e32066540feff8b7f215fc033ec81acd8d61954d4c7, F)
                        ),
                        mulmod(scratch2, 0x1cfa0c07daeacef91af779e76b5ae1b3f23c51091dfb2498e31baa25a5ad9d49, F)
                    )
                )
            state2 :=
                add(
                    0x16159b522e010cdb5a8ac2fb316dc4ed2a15d0ff514f3ae0756aeb03c63e4c38,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x2cb0a1b70732f1fb62d1c685d8bd7efb2eb4a37ebb357bf1c5014ee113ff9ff2, F)
                        ),
                        mulmod(scratch2, 0xf6e7769354ae24f67def967a87db573def50485f0016722be62a5fa2fd20655, F)
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 := mulmod(mulmod(scratch0, scratch0, F), state0, F)
            scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            mstore(
                0,
                mulmod(
                    add(
                        add(
                            state0,
                            mulmod(state1, 0x2a11d92ba0f6532b1bbf772c056ba4613da8297a47509c2fca022892937df027, F)
                        ),
                        mulmod(state2, 0xf13856dfa71006b7873a3cb51b9d6ec9747274ca88275f83113c93cb574c40a, F)
                    ),
                    0x240a9bc8af504b09748b45d89e982e8e58e8dd18341b588fe9239872c2364fc2,
                    F
                )
            )
            return(0, 0x20)
        }
    }
}
