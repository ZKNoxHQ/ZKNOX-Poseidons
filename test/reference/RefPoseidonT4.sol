// SPDX-License-Identifier: MIT
pragma solidity 0.7.6;

/// @title Circomlib-compatible Poseidon hash for three inputs
/// @notice T4 is a width-four state: zero capacity element plus three inputs.
/// @dev Uses circomlib's optimized constants and sparse partial-round matrices
///      over the BN254 scalar field. This is original Poseidon, not Poseidon2.
///      Round-specific diagonal basis changes normalize one coefficient in
///      each linear row without changing the permutation over the field.
///      Sparse lanes are canonicalized first, then reduced every fifth round:
///      four raw additions are overflow-safe because 5F is less than 2^256.
library RefPoseidonT4 {
    function hash(uint256[3] calldata) external pure returns (uint256) {
        assembly {
            let F := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            let state1 :=
                addmod(calldataload(0x04), 0x265ddfe127dd51bd7239347b758f0a1320eb2cc7450acc1dad47f80c8dcf34d6, F)
            let state2 :=
                addmod(calldataload(0x24), 0x199750ec472f1809e0f66a545e1e51624108ac845015c2aa3dfc36bab497d8aa, F)
            let state3 :=
                addmod(calldataload(0x44), 0x157ff3fe65ac7208110f06a5f74302b14d743ea25067f0ffd032f787c7f1cdf8, F)
            let scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 := mulmod(state3, state3, F)
            state3 := mulmod(mulmod(scratch0, scratch0, F), state3, F)
            scratch0 :=
                add(
                    0xde780731b1de82f399faeb188a25d1555e38e7ed8eb71682447f3b174fef0f1,
                    add(
                        state1,
                        add(
                            mulmod(state2, 0x1d820ed90243d25b348169c01b5b55d7319a5d6527cf7b11a1fb15ceee542947, F),
                            mulmod(state3, 0x2dcb3021d89003544794b4804cd0dd8275ba21d59e5ef98516b6fb629a2372b9, F)
                        )
                    )
                )
            let scratch1 :=
                add(
                    0x194b18560359f2061e3b80e77656b679e3e6be85ad91bc2a5cea42ec0e178ef3,
                    add(
                        state1,
                        add(
                            mulmod(state2, 0x2fb15a53ccd15179a02a785297ab3c77af4853097507d9dd5a7af57f1225f4b4, F),
                            mulmod(state3, 0x10643f83f0c61de7cb00796bfc52514b3217566d6ebe949557f9c8a88c38426c, F)
                        )
                    )
                )
            let scratch2 :=
                add(
                    0x1f1bd5ce1d7c87c7460ad240f918e5b71823951576f8d033beabd595f4fc8a9c,
                    add(
                        state1,
                        add(
                            mulmod(state2, 0x1ba47bd2769c5145b24bce221fa5ac07ab3128e85545189b2c70d31a78c1566c, F),
                            mulmod(state3, 0xcb0c48a9f8267152f8d6f3a51c3c781f670166806734719ac7efce2271bd58e, F)
                        )
                    )
                )
            let scratch3 :=
                add(
                    0x1a13987f2a79c106b82ee853d3c101373b0f0da6e56530c26f59a8faf00d5319,
                    add(
                        state1,
                        add(
                            mulmod(state2, 0x35b86d0e7b4627c95df7551c11ae2811a8e4d88779f57f35b353a1d13137779, F),
                            mulmod(state3, 0x1ee6d19e3fade52894109325f0a30fb9f367b828d9e2a0381688967ace6f0e5b, F)
                        )
                    )
                )
            let state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 := mulmod(scratch3, scratch3, F)
            scratch3 := mulmod(mulmod(state0, state0, F), scratch3, F)
            state0 :=
                add(
                    0xe8ac47fdc964da75d974f4464170b9f814d34f0acaffac21cad639c0454eb6b,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x24c878e60b67abaaeb6e853844a1b9d9ada095c5bd491405149dd4509422d6df, F)
                        ),
                        add(
                            mulmod(scratch2, 0x1fd309de6f5bbe43db75d44b91d8c25b8e34eb4adf1a998ee14514b137c6abc2, F),
                            mulmod(scratch3, 0x1cd686e946878f7871771894775b4dcd4f08814853f2e421fae90d769e3afa0, F)
                        )
                    )
                )
            state1 :=
                add(
                    0x94b4ee89ece6808b4cb906558a2465098d57b0cfaeb652f16ac7f50b5bc86e3,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0x7675f33c28903b83e0197dd060d57fceede36be693f6dc7f9be9b2d93345046, F)
                        ),
                        add(
                            mulmod(scratch2, 0xe0a2df8eb09df94957f4ef21d49b39c00d7e55c29bd34731c9ee9f368ae33f6, F),
                            mulmod(scratch3, 0x2803a310f6bd001fe10637e11dfed28a661338a71c9995aeec9f60fb98901676, F)
                        )
                    )
                )
            state2 :=
                add(
                    0xf4269dbb7dad4b71a6f1df5e709444ce0fe2d1a30968c924b87822478af8d48,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0xe5c074bd4b66f101591c1d218393f2a778f70b0acd812c3f872f4ed79daf1fb, F)
                        ),
                        add(
                            mulmod(scratch2, 0x305092e3d4da75189677cf9f0fce593fced93092834298a4e03fc9291a3a1567, F),
                            mulmod(scratch3, 0x2f466990fe95d6bcf6f879e34c3544b51e861c06e663fe1a3b88071c1d9dacf9, F)
                        )
                    )
                )
            state3 :=
                add(
                    0x14a74cf77d751ccd5c82f091476fa0f0a4fe56f1af9e9437637e175cbc7f8c67,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0x44beacab762a5c20a4235b192868b79d854369346b91a3197c27d9a65dc35cb, F)
                        ),
                        add(
                            mulmod(scratch2, 0xc8532b37fa9ea5f9f8ed894e1348de1a0f1da9203e22ae158c329d85dfb9815, F),
                            mulmod(scratch3, 0x9d1a739312a311714e8fd41ced9cbc0d15973d2998e8341f7530d2aeba7ab27, F)
                        )
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 := mulmod(mulmod(scratch0, scratch0, F), state0, F)
            scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 := mulmod(state3, state3, F)
            state3 := mulmod(mulmod(scratch0, scratch0, F), state3, F)
            scratch0 :=
                add(
                    0x8d145927548af293e7e97472d0dc89bc41e860bbc45004be037424770753040,
                    add(
                        add(state0, mulmod(state1, 0x663ced12e20c43e9be6b4ba0a11fcbee412ed9874b03a2b5d7bb57f75b6220c, F)),
                        add(
                            mulmod(state2, 0x98957baa2c63d11223b7279f117d04f8d9a187cea4853157dbac91d0b0e1aaa, F),
                            mulmod(state3, 0x59e4c781799bb33aac6a2019bcc51e5afc3178d09df85dd453d7393a38f01aa, F)
                        )
                    )
                )
            scratch1 :=
                add(
                    0x19fb9fe736f1b5c1cd57ac7a5280049818b25c42c41a75741d67b2c46f373086,
                    add(
                        add(state0, mulmod(state1, 0x1b734ed59b2f987d0f0d72be82bd06c39f181f87f400baf52f2e1257bd819fc0, F)),
                        add(
                            mulmod(state2, 0x132bd394d45a477c00d36de5f491ff879b102eb08eeed5c4ec9b4ef1b497a2ae, F),
                            mulmod(state3, 0xbb63982636c126abbf19369180f9fcb462949051681ae1873bd0f9cf980210a, F)
                        )
                    )
                )
            scratch2 :=
                add(
                    0xa80126d0897a9d3c17688991cba326cc88b4db26a10929c3163097bff175b56,
                    add(
                        add(state0, mulmod(state1, 0x11e70e954d2c78c9c7ce9f0cb1dbbddf79c8f68e843413bba55e5fcefdc43fa6, F)),
                        add(
                            mulmod(state2, 0x2fe567a2786f2e383e3e65de78fe435b03a529ae3e05190a1ee64bd0741a3b3f, F),
                            mulmod(state3, 0xfa4de83927ee03f6244d1e44c45bc08acc5b9c52859892dc2606e5c486796e4, F)
                        )
                    )
                )
            scratch3 :=
                add(
                    0x1ad4e7e958543669a96a2e99b846827ed19cfd59488144e41875774e445f1e79,
                    add(
                        add(state0, mulmod(state1, 0x11e6ed81c0972175c1f3ae7f236fbacc96f04ea0fa21ace4b345c5e32eb02dc1, F)),
                        add(
                            mulmod(state2, 0x2b3983475518fd06fb0f5fe025f1c20a76e99e6c2d4ff72f08931ab38e7a97b6, F),
                            mulmod(state3, 0xc7e9c9ecba22d4c5561f6eac027619718c371a4f43ca329d19cc7a1e0bd6a17, F)
                        )
                    )
                )
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 := mulmod(scratch3, scratch3, F)
            scratch3 := mulmod(mulmod(state0, state0, F), scratch3, F)
            state0 :=
                add(
                    0x6dbcedf49fbf92da10378b374d9b78e484cbe442f423d9bd92f033d375aafb6,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0x663ced12e20c43e9be6b4ba0a11fcbee412ed9874b03a2b5d7bb57f75b6220c, F)
                        ),
                        add(
                            mulmod(scratch2, 0x98957baa2c63d11223b7279f117d04f8d9a187cea4853157dbac91d0b0e1aaa, F),
                            mulmod(scratch3, 0x59e4c781799bb33aac6a2019bcc51e5afc3178d09df85dd453d7393a38f01aa, F)
                        )
                    )
                )
            state1 :=
                add(
                    0x1f007b0dcd3de00f67c0a1c8bb70c2fa9447d46a1963415e2679988c9f9088d4,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x1341a272b30c04d21b05f286562ca12612f5e4e2536e71647112eafcd73b2f0a, F)
                        ),
                        add(
                            mulmod(scratch2, 0x1780554ec87f96178e29431ab8c4d3a1e1dff10b23d987ede1c0d74be2d396e0, F),
                            mulmod(scratch3, 0x29ce98f8c05fb2f50f0bc52a2614a2db51b09205dd54cc0c9fa3fdc5208f8f69, F)
                        )
                    )
                )
            state2 :=
                add(
                    0x225c6deaa75fe4e88ff8a411371372a9d214f5b83828e7d7940db76c4a35953c,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x2dbce4910f93113a67ee776b7e365b90c978762e8aba353de18ec5a09a671cc5, F)
                        ),
                        add(
                            mulmod(scratch2, 0x12c0523f6e878880222685cb9271b179181711c49d6735db0c6693f3acec1df1, F),
                            mulmod(scratch3, 0x137bdc3322186dc912843f42ba9ada010c8ff1fbfef8e7663cdb29ecfbab7112, F)
                        )
                    )
                )
            state3 :=
                add(
                    0x992a96143bdd9accbfa74d968779bbb25f3e8c0b2b2daba1a54191fe61cd940,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x2ab4a45159af67b9f8efbe2e6600ee3fd49add7ad16c3cfcef88cd172f7ebef1, F)
                        ),
                        add(
                            mulmod(scratch2, 0xeeafeabe0eee8122e115506db641084ed8927587728717ad09d2882fe00ddea, F),
                            mulmod(scratch3, 0x21341723e77ff10a535ae608833efaf051fed6f13ced1e12b0d4d60d18cf157c, F)
                        )
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x8ec463b63139fe72ec1a64359ce2e15cf35f0b5690e38a3e08c4ea98cd23fee
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x264fe665ec4ec81871cb97b3fc8b03ac9d41353f89675203935b445195971299, F)),
                    add(
                        mulmod(state2, 0x10c9ff07f82c08c2f5745514d52a7ce03d951f55ec99d20bc98d9cff44f3a069, F),
                        mulmod(state3, 0x7af5687f95959cb79674e27cc115933b938d25b77e882daf5368cf24bc60265, F)
                    )
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x2cf51b5a3d3f4d85ac5ebd17653b08c4f768d8455856c9afa4ff5aaebb2313b3, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x1b59ecb1a6ac02f4d79435901d0c6991cf0ada98715e23f5736512d4d4826c4a, F), F)
            scratch3 :=
                addmod(state3, mulmod(state0, 0xb57650f32fb23ac19866d185daf3f6424ce8ff7275801769f7a597f09906437, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x15cf1ea05b892e8e428f766c75b104f51fce664f53b84c29369116eb3c081e4f
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x303e85296b973c468e0f8694b21142ff691b25d6da9912c0001bc386f6c37568, F)),
                    add(
                        mulmod(scratch2, 0x2979cce96b39580355a149672e23fbac5df019270a6250b3a8c0b998dde3597a, F),
                        mulmod(scratch3, 0xe44b411acb1ef7d0f000793159347e52674c9869f7efab84a77d7b746c79910, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x8ce595d9d9e5e3133c7cb1f7bab497aebd31f9c9b1abbb16e13d35f1c8afa55, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x35818ad5857322f06adf3a4a91a6bd8adb609a467f465790942ac62b3e92a5c, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x7bb01b9094b263f9807ac4c5dd476fd6e5574d3bb1d402a196ba6993239e6fd, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x3005879bbfdc26aaae83c7dc25636e6401ed44f17154c7755e22edef8d3fb03c
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xb156d0ce92af44056c0f6cf42173034cada750c12c0cbb7e5c7bd6785347b29, F)),
                    add(
                        mulmod(state2, 0x13fe63fcae8b8fb08af32977a2084f1a43a58d842c5efcb747e0990dd9fe685c, F),
                        mulmod(state3, 0x2ca1d1383e5fb67a268c1178764475007cf8504d44887acd1eac7de89df13926, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x210b299bae228139fc2a2577030d1fb8269bf2a74f843b8c57b1d5a204f61519, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2bfb7df88807388edf4c0a1b1816e3e35e00143600d7930a63462a31d713594e, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x4cba9bacee77175ae1beb0b1b677c714e235590fb158f4cf05e6a7a92cf2c21, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xab58d76339de3327328d4648b3b02d41379440a829900c1de5b9a703ab3c866
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x1adbb638e58b7c1fe76fb2f719712f450b7b67671fbe6095b26706ce64a58f0c, F)),
                    add(
                        mulmod(scratch2, 0x87f516d328c99ec82245bc678054b77063158d54ec0c2a2a0b63ebaedd1a65b, F),
                        mulmod(scratch3, 0x55c9d2bbe65921ecca7d4b5b09814dd958ce261456511b8878a40d98b71c7dd, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2ea541d8a34f47279e6d8757434673d43e433e3d2b3a0f2235ee2588455aefbc, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x293a67ab22226ce3a32373bfd2e327f3c3d9d64ab5110cbfeaa3541f592eeab9, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x1f5f8e02aa9b15dbb884a660ab438b33aebe655f39e9d613bc7e7f0b371c801e, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2b81a266d2ffdfd1bca5e0ab868122541126974cd61a9fc45e75b6e14ddbd986
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1c0046d3096e3febf3f86dc1a4d0d493fb418cecaafa084d6154041397393588, F)),
                    add(
                        mulmod(state2, 0x2afb629daa24c0af0efec3dd743aa51b0642ce174d64a32eab9d1ec032daf445, F),
                        mulmod(state3, 0x17007a7afbebf543e703141947abb786e3c526e16a8b621139eb67de9ea231f1, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x23eaa0214e51e63bf9a20c80a6f4a0f0d6fabe06a776d6c79404e39457c12d70, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x1b6b0624bee4f65c528e13736ed3b36e660c57311473d3543feb70e450681fa0, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x20a7ab0e0c9b8fc839c2bf9a48e40043605dee33019ecfaad6b7ecafec2a3d08, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x23fb01680f622908a6bd2234b6fd75d53ef60ad5b40640c6b441e11086859908
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x89ff85f4f7f4c91fd4f16e0b036f6d124eaa1ff4bf61c9ddbf124b993c4a0e0, F)),
                    add(
                        mulmod(scratch2, 0x22753e5125bb77f97b58e3630ed0c8a912ad31e66572a9fd6fb13bde0ef4794b, F),
                        mulmod(scratch3, 0x298bbd902643c7ca4963fb4dd15c5aaa48d5332a5136ec6ee09ef5060656aa05, F)
                    )
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x171f7e31de09c8fec08c234ccd6601c2bc2297ec64af515941f8a5ee89b8b34a, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x80d2a34190888c6fa61e859cd6216500b5e64094f03bd5e207da25aa07fc59c, F), F)
            state3 :=
                addmod(scratch3, mulmod(scratch0, 0x1fcc529e2f30ffb354ea2c686877ae8644a51b43f87b830191285ef9e8fd357, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xdb2b22ecd92f290ee24a062eda21388b7df2ca8c1faf876b790d478543200c1
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x12789fc48a27c124129aaeac15692ae4b3db0e3aae19f1d6090036d051e4683a, F)),
                    add(
                        mulmod(state2, 0x183e4fb7fc7082ace5c8db85947fd1e7d5e253c06c69675862629f45415525a0, F),
                        mulmod(state3, 0x1046b5a3725464e09f4a1e3ca5cb5ee38c1f28f757c8fdda5842bb958a064bc3, F)
                    )
                )
            scratch1 := add(state1, mulmod(state0, 0x3f4098f97afbbe6310182e987e67f05f12f25403e45fc7d2d3aaf380fbbe68, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2aa5afa434cb5ebbbf4aed0aabcc3a25c73bf2de9a1edd20a49f1e2c534b36ec, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x2453ff7ca81953a5c9191be548b8dc764b77fbd4de7de1a4e35ba7fd8bd02796, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2e17791e377af516c041bd0aa0b69ecd814a8498e476999fb05f03e0cc0954ef
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x41dc78e919868151aa8cd423c7f0dc1efaf0866064836356166c6707c3e0f1a, F)),
                    add(
                        mulmod(scratch2, 0x293791c6fee5b879a76eee22f16edeeed5f88e48c46b65fdaa3e3dbc8a4be916, F),
                        mulmod(scratch3, 0x1513757e4906829286f45f376ec093ab48fce881ce6d5e0f910bfd8b68122c4e, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0xd786f2cee91528ba931719fbcc3134200ea317a7bb4c311573073f2698bcf19, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x107d6a845ae56aad38607f83ebb42f705f674dff535597386f5c7feba9e1aee8, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x2db2b1ca8d19ab02ac2b19d1d8fe5f9418048a979e35c26fec733955e8d8e3ee, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x15873ba6de25eaec43c3a1863cf493b91d53b73027b309e81367a5112077a97c
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x283e1a436e3d4416ec6441e43edc08d29a19ce31efbc727a9c5df3d887ad900a, F)),
                    add(
                        mulmod(state2, 0x5dcece2beed21a2dd5678323adf4bf1813e9842d3930a626d4b201f5fb70420, F),
                        mulmod(state3, 0x2a17394d492da2067b2f4149d7d0b19535009b1f1951073545c8c7032f8c0c4b, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x49f8964d6ba3772dbb3a0680398535296619dff385c247d31c185e7c4830ce5, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2120e1b415c17e1c45ed87b1232705678cf1ca517d9e667a853daeaa78c12a80, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x255a02c7bc2cc2637b79c1deb0b0d66d76fa6dda27edcbdaf53293dd2e4eaea7, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x292ab84203b79f1049e98f05dd5681e0c4f747dfc1b3dce7d0018fdc40b26a7f
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2341a26a1f339ec15b4e7dc1a035607ff738dcc2d2f4e30753220f69c3598aa2, F)),
                    add(
                        mulmod(scratch2, 0x1183b212bc0b45d11dc590136cfaa5b80904d03dc6374e0800d8cdb5556d0c6e, F),
                        mulmod(scratch3, 0x26fb9d6e33cfb7d4cb674f96dbc172d96fe352a6035e8e3d0fa8dc1b0859c148, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x12dae82f2b78d8aa2a90de8d843cac42e9fdb4e814d4279b00e6de1a8cb687d, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1cf12bd3af1cda1d15d95ecea30916b761e35bc2deb18499962095fc9293c1ed, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0xe6501dac1bfebb7fa11dc9a761c7595a45c60f69c9162d1027edc8593ca471d, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x119bb292fdc5c71ced3e8a5952f3900147e4f2fc663cbe8293b18fbc92c4f66
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1039709ac76ad7fab4e95b3ba6871fb43ee56b2e82c475cab60709ce4cfda931, F)),
                    add(
                        mulmod(state2, 0x2536a17c8a43c94cc551c2b13ff4d9f94cea3d49f4402d585bd2a73b9436e717, F),
                        mulmod(state3, 0x15ceb0b0d1d7036409ec2d7342953147f8a052a9564af5f779466b7704c4d095, F)
                    )
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x1ce45a10ca47d5c1d1af478c49a4688be7100d0eb5cfe83859cd0a5c17958680, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x12d22e2488ab9916e174982a3b6364f184cf67f6bf19621513eda0a89f5a3ebd, F), F)
            scratch3 :=
                addmod(state3, mulmod(state0, 0x2ae1c104a6b8fdcd091510cbf58df870dbc9a25f96dd09165ccdea53388a2782, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1712270f6d68fa033e5e2afbc59300917f6fb0bc74988766ef3997d384d770b2
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x120d536d69af24fc9cdade1529203c989af95b0a2a8a560e4d4a051bb12849e5, F)),
                    add(
                        mulmod(scratch2, 0x1a99e8794144bcc6e43eb8573492b4b9d1ab4a159c043d6efed3fe7aa87e392a, F),
                        mulmod(scratch3, 0x26244b4748f7428e239bf07546d0025f2573f95b6b1a34d3c71f9d391395d14a, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x85c7336ec5c7319d5c0004b70201802d9b50d204a71f7b6d23a47ca0e2299fa, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2d09f5a84f206bfd7a0c58496db057b522a9267e39bdd16ba2a923fd36e51497, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0xe5a27661c20f430acf3039513cebec7a9af9bd4eda599507e3ea84a301b25a, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2dc9520b542d38137d38f2238f3d948f6e431d1a0f444387488bc1f62f3592c
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1e1ea63599a2776c80823c3dfddd3d906b953c051980acf80e74e8836fc422da, F)),
                    add(
                        mulmod(state2, 0x1bf649d4998ab99663f1ebf58b578575fcc7c0e9ce9afe2fab978f107f65ea8, F),
                        mulmod(state3, 0x27baeecb79e3ce861df3e557bccbeb6790040c887758b579bcbd1112dd21467c, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x1f0a0503c3da4ed7133242d415040e8b89d627871919fddb8076bda4ff673af8, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xc892debfaa5afde6de8746339572f7be5fa3e76d3a85933e1bfb4d40c74993d, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x1ac4e02e9e6fe0e1c3767f8c9b37f1e1b94ede9e426ddfae97fc15d2b5a57b9c, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xfb9e7c983226462fcaa7605f898ed92c744c2c79c0f2d68f3b021d12f233254
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xd8a58f497c12701a3fd1ff840c9fdb48888dcda5b6c124ed2b574450baeaf79, F)),
                    add(
                        mulmod(scratch2, 0x78104aac0c76566d342bc62e1d93fe879d80a3ce65c4a76a74d2abac4052532, F),
                        mulmod(scratch3, 0x1767d5ed8acb5b8d1a4842322e9c19c418b430c767b7360df5453631a41c78fd, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x15d95752db397c7ab4ae3754c10b77404b697418684cc62cb5ffe9542b544bb6, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1e29d119906106eff8b5ef3ef7d17bcf8bcededcdb24d2df40670796b4745e3f, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0xa700419b0705e88c0bbd001bf580bba4ff2d5514da9f3085f54c9f98affee6f, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2aac37e7dcd48e10e969aec22a7b3dc6d00ff936c6c216199e29dac979403acf
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2f8605cf2eb83d2ef47832e42c24c4b99a4a96d4d92efd20262831a77bcc8317, F)),
                    add(
                        mulmod(state2, 0x1c4043a2fbcb51c10c94837ba5f1b517c8d2712a84863db046b16330a44c763e, F),
                        mulmod(state3, 0x166202bc14c33908c2bf0f08e2ca893bf069ad645054d0eedf28d3a0dec33b27, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x25ad07d22f8f7c1687ba198e322467147161d44eaed17b084eab333c2e4ab8b4, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x261c4a69c04b0b29402b369b9c3caa59c6071bfa0b3cf8c9fc50c968a4b01049, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x19f8b7e9aac5f827c33be932c3d370c72d134331194934407be09721f54c17bc, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2393a3b4f3ba27b616305874ad65750fc2a28559bb25bdecd453d78a2b032c10
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2e527cad76a807082ac810ef4ba16f8d985c720c98501ebdb5ecee131eb1dd3f, F)),
                    add(
                        mulmod(scratch2, 0xb307ab7f7d67379312b06a612295d71388758580730bd0bca2cb40bb6a93adb, F),
                        mulmod(scratch3, 0xc8540edd0dc3b61332e6ba2e2f9f3f4cd8cd5f35935247440981e946b8aaacd, F)
                    )
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x208799b65448b645a9bd9ff8bdc4bfd7cbbaf28b4cd39a10aa396f62c6ae9890, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x36201939c42ee6bc8e9da1dfe6fbfbd50f525007cb72e131d2f47910e598352, F), F)
            state3 :=
                addmod(scratch3, mulmod(scratch0, 0x2319fdbd6a494dfee07ae99615c18a3a765b777bf7cafab88e87c1ace20f3a78, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xcc983e20be336b245c27c544661b6d28d0b96da0645414b0fb83cdd50ba746a
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x54f0987bf6c427d14b91d775742faa43018db968e88d9e8ddf0caf907550d78, F)),
                    add(
                        mulmod(state2, 0x3365c522061b0b362980214af71f86b33d6226dc01443a77c31e378941cc70f, F),
                        mulmod(state3, 0x202e2aa5405a92ef04235f69a4dbb0a92689b0f19e62a670200ac907a84546e, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xdad2f85f68d857760ad35ab368b1d17e962f81702ed0fbad209052420448381, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x17d84c230edb17a14366143fe50bf9503082931cdd47da4bafef15131f9db3af, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x2c651482589520b6fb4315be36ebe7616dfc3cb93f9086dbb693efb5b0e702a2, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x17ecde52c95ad22cac6fc2d4d21f12b715a55d6e0bb0ef0906eb1cd86af66b04
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x20e0b3c49c2add216a73d012c0374dcbb032cbb3e397b285a056e7f1aec9e38d, F)),
                    add(
                        mulmod(scratch2, 0x123124e789aabdfd141b69734d698274f0ca09c2848b553ae931cfa7cc68b112, F),
                        mulmod(scratch3, 0x26ca2b4f441154cb5926faa4c89ec16056a04538ef39115b666e983110f873c2, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x7695637a87566533ea94619c3f8c6a0d8b55297b93724924d84064cdcc065b5, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0xd4c75f52eb17fd0d8c0b7ad6b12086fb8587e43b0cf55f1c9a5272464ccc189, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x1d422c1ed124aa8ffa8943ae406949e581dd8b46ace9ce9d42cd5b1be8940b51, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1832e00c63e6bf09145f2d36f90ea5ee792d7a05e9e8375bebf4efb630532ef1
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xf054201b8c364a6584dca5e54bb939eb71dc61ee5f1e2d3aa65a23d9618f356, F)),
                    add(
                        mulmod(state2, 0xf8a0882cb650e38a3241993da671f21267da5e0132468fabac13c8159218565, F),
                        mulmod(state3, 0xb020243570589e878295913df3fb5a4c8fbaf4b785809234cbe50124a1cc3fe, F)
                    )
                )
            scratch1 := add(state1, mulmod(state0, 0x8e2f5fdaddd60d0abb05281d4ccb54cf16ac2a28fd31f0caf5ebbe5c24b106, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2e66ccf20ed2eda69d7ddb3d87a70c2087a8a1bcf91f697e268c71ac4c0ee1a5, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x1b896f33747a369fd8b12a1d27d2f2deec33552f3f683e11de11de74e25bffdb, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1d8c2dc0b875cfb7a72d6b301f3044819faa2b60a44166c8b41e70cdbaa85b4b
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x122646d538f25344a8fab41f95ed46f895e279c478e257f6d90a402891ca5bdc, F)),
                    add(
                        mulmod(scratch2, 0x26f7a6c66919756f90ca35cfb6384dcaebb25c2b7558843d74a7b45e397d62d6, F),
                        mulmod(scratch3, 0x5966e1794084c182f7f99087e4537e98ddb5164fe08b6ac91bd1be95a352a06, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x16c5ea3b3dd2df705a4e0434154f2f809c957974ed0ddd4f5e95bfd840ecfae, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x217afb80d572a204476d95f462d3784dbb530e6406f31d91b22ad581badeef39, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x1e3890f175dc155bfdd1e666e50d5ef528f1e91410a1fbd27a33963711db4b98, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1eb194af1656ec4bf2b76ff7a86c837e03cf924a4abf60e7f40f41c5e26b0f11
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xe20b0a83521b33fe7ed3cf34f88c23aca5ac9e3a0cb23012239a1de869ed16, F)),
                    add(
                        mulmod(state2, 0x14c2d22c5864d87781270132f01a44dc1665db58fa22a7af0994b9cd16c38307, F),
                        mulmod(state3, 0x1a68a8ea6c951d7ec6997e148a23882bf04f0e280761c606733ce689abc2777, F)
                    )
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x28658e35ab6127aebd540cfe5291f2b64b2f6b3dec4b5eae8b16595236c0b101, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x2610ff6a10098c24b77dbaa2846413991e1e96c9770301085bb66ade6c68ba5e, F), F)
            scratch3 :=
                addmod(state3, mulmod(state0, 0x2d2141bab3d5daba891e29a320ef3d7619b4142ff9dad4dfea2fa8d62851b2a6, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1cfdabf11ed52761d31a8217a2e3c74a305fb92ead849dbb86dcb00db65149f7
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x1e10253bea600e69f16a511e0e1bc7e82273fb7ce7a5b98359c7a959a1178998, F)),
                    add(
                        mulmod(scratch2, 0x1db20d16e6333caeda05f5da11bde0e96119485068eb6d7f79a5ac1524729bc7, F),
                        mulmod(scratch3, 0x1fcbd77c78035e53a025affc1bc2743cd8a4c1676c5b73c3ed04d4c44d124237, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x24d2f9b737e8aa4a53b218d6bbebe7d7ebc3587f5d31d8c01713a4c3bc8a9d7b, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x155b96628c0c81bcef338738aafe81072b015234ce9f614321435e8713e29b67, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x284c025b89d2c0c3c7991da39d3d01f2a65c9ded8de185f4729c66b98414b7a1, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1caddc4be8385557aa9c006a1211685f4c55b85208ebdf8623a72153aad0da76
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x228348cbfe1107315b753d0fb64f513d720f870ef9ea8356b9dd9c8b840ae550, F)),
                    add(
                        mulmod(state2, 0x1132aa094fdd0fd8c5ddb48bfb981be474172b35aa043b98aaa76ddfaa94cc1d, F),
                        mulmod(state3, 0x2f4349a83eac5eae3efb7c96eefd234f2cb9a918b44d367a03cc1385c1df500a, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2986a9d79c132bd733d61b685c1922f10862bf823f2298490eb4604bb8e5c07e, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2f6211b6e57842c751e9c220db0730908b5812d20ea9696673f48b89effb7e32, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x15df9df17e3ac314caa4f892765157c8c214661bf1dd122ed4c956d03a955e97, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2471f8a8c0d0c4e44c237311773349f1148c6c917984a64c18fdd8123d275d9e
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x1fa3bd891e79991c6d12ae556a4ff644eb646e335146bea6e6d95a57d006952, F)),
                    add(
                        mulmod(scratch2, 0x2d20c9fd023cce724d1a7f2a737708429d4da492f00b05701e7fba8cb2058873, F),
                        mulmod(scratch3, 0xc77714241bd7646077f24c558867aaacf461f4eba30da0051761e8646833050, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x28369f6c4681367c7d82a520493b6a2d7539c1ffcf6228260bbc8ba81f1bfbea, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2f446645da6137044ad8dd929abd784cfd763e6e775eff9e668f5f1be7ce40a1, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x6249d2080a11edc0697b470d9d4b3f60c6ca099bf6fb590ba92ffc28003d81d, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1d975bda920817dd346bace06a8efe932db9e18b2e5183374cee197173f10305
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1edc053dc6162081a8669bd67bf654ee9cafd781c0e7b0559343fd9082441fa7, F)),
                    add(
                        mulmod(state2, 0x2e1fe54ffffed098117a67949d190856d47feb4cfb74463bc1531f05eb7db0c0, F),
                        mulmod(state3, 0x1b8cc9d926f65627171037b0ed5b79acec7a395febe04ba867d0bbf7e0b8d196, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x1e8a5db1c231a2f6b0c3cd467043491a5e5a6bac5105222fa4836066e4f5734f, F))
            scratch2 := add(state2, mulmod(state0, 0xfeb66563131a0c43789e1bb35a25477a264465d4eca911b0fff32cd2df2f05, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x4049b584fbf7055d552257e214cda7709ae26329e0a6ce79e15df1fbca3b721, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2b4a0ea40dbec57c1946843bba7fefc6093c2deacd92a1a3c37555e11c2fcfce
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x5e8dc87715567ef1b721c9351497f25ed6f7edf53cb4ddae3df9d132509d21c, F)),
                    add(
                        mulmod(scratch2, 0x884034e549c6c67d0b6fb9dabcc22daef7a58c9072a41580f1c5b411cc22a, F),
                        mulmod(scratch3, 0x13b93adcf48a109a597f26ab965a60f193b7a7cfd1a55fe7876cf81e2c00a3be, F)
                    )
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x12d2818f940d0c95b0d83aa247df47cfda9c91995714cc89e53febc03c058017, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x939ceff8881b9a7aff084d9de31c677416c9ac8cf9646bcfe6751d8ca5a266b, F), F)
            state3 :=
                addmod(scratch3, mulmod(scratch0, 0x297e6335eb1e5781bf6d018d3c74628c1ad1ee87c9419ba688a8b3919c1b5622, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x10c99e0758763759600e2013a55c17a8a264e4632ddf24141c86d14045ca0371
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x162bd6d5ff025fa47a130d5f68a5f7afcd835d30718987ac3dcaca3708b29cb6, F)),
                    add(
                        mulmod(state2, 0x2f1eb9adda1ddd6a8dd2ab82923bc44bf232c21f74292f209a8cc2645c2ed821, F),
                        mulmod(state3, 0xeac857f94c7f0902d210aa9b5636845592694797193420228efc40400d624c0, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x9720dbb724a3a5458afeac102c1cbc0905cf50cac357caac6a5a43b0480aae9, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2525a70a1e4afa46b1f6d37ddac5dacd99cd28c8d79f09d4c9193cca77ae2d2d, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x268b3a5af6ef4236e0f1848a1d8803c85d0ec33a691b264749e98396330033f6, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x9a0123c60767486535ad0b97cc51f0c2ff14cf288b6007d5e398cafa27adfc5
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x27b6489a26642b72a3f21e145375401d1453d5e9b7bed51afefb3585d43d2879, F)),
                    add(
                        mulmod(scratch2, 0x1e1353f38718deb73e717124fa8c3bdde7f789a6034aadd90105ad497d6a79d0, F),
                        mulmod(scratch3, 0x1ebf51e36efb84fb685364575e5d2f49105df396b27c6443f3bd6a55e8865b86, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x1c2e2d06daf1f282d8d727fd2f34106aaf3c31f83770fcd86aa824f84ad37ef9, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1a9876bd6ab42b2433d5fc756f4a4ae999e4f1fdf668c2afe3b8aa7a6ec2161b, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x2620ad6b42277e79346e78f08b45e27b181a636bb38eb0ede98487fbc2249fa3, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xc317008108701ffcb009fb602b2375e3ce4b921672eb402579fff4c401c040
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x25927784172a8642222321d5b4800c6a861ad1050fab3d4fa68ae55233f8c76d, F)),
                    add(
                        mulmod(state2, 0x2fa041cf1926d818c5113476b250352e9378e077b08b245f850337fdc410779e, F),
                        mulmod(state3, 0x19e09789be4c272b1d0c521f66dafd8e6428ab5b52419ba50976b0901ac7f245, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2c2468192a71a5b48909a84b364d3736f8ae5bc4079801cfe6bf3800943a5101, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2d5046e9ee5ee8bb6cb255876177f8fd45a150aa0af9d99d77a4fa3d68d26c6b, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x200ab58259474a2c1e2d3a5b4824221e12297836e8f99b74d778a0f9ab12ce6b, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2b8d85aaa13b325b636f92ba4518c84ad46b240505884fee872b11c36ad162ac
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x22ffaa7827784d051c79b0f6e5d21bcd9278bdc62570fefea74a80211b0ca81c, F)),
                    add(
                        mulmod(scratch2, 0x89d3da69a2abdb4b24d5ce98b9c225d437a614d88dac93c7f31a8780ad8071e, F),
                        mulmod(scratch3, 0x261cec5c296ed9d176479799bb2b1f92afb918623f44d66936b0146094163ba4, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2e84e79cc72aabe8468646e3dfab39c4b712918879ec91e31f5c17d28f1e5cd8, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2853816635c21bb5e66fde0d4f35cbce07e7245f457ef3027b682502bf477fd2, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x6dd22adb45946cf5885cc2b3157c353a878310e1d1943420a6f5aafdcbd68d0, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x5aa802d7743640f65079faff48c4d1e811cea147ee15ff38c84a7d6a59dfd58
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x241ab25cd74402bb8c2bd890eebf817f6e4ed4b437a44fa750aba5474fa19774, F)),
                    add(
                        mulmod(state2, 0x2cacd7be0be004e317305105a03137fcc0c4d33636c71b4249fc647df0c2b4f3, F),
                        mulmod(state3, 0x24a11dbc7e645fb8c68a0dfbd369ecb1bd61c463f682c44e5875976ca05562c8, F)
                    )
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0xd76ddfc2602d30af89ad39e03272db0577c46bd01218ebc332d312fa5bacdfb, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x9d07fd86f31bbe17d19100da8167b32f030a0c974d727685524d15ed20b2d3d, F), F)
            scratch3 :=
                addmod(state3, mulmod(state0, 0x206f755c27729f3984c61cdbd7a08370b55d966b6103f324c9b2e3f020068ca0, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1a21844d59d494c6df2fad657b57e3f3b9efc9a0693efa686d0b6e78fdc0918b
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x19a09bcbf999589baf0c97deb916f06fae3b65204bf2159362749dfea887f528, F)),
                    add(
                        mulmod(scratch2, 0x15518cc448cb152ecdd0b6e798492aa8795dc154e55f472b325755918bf1c35b, F),
                        mulmod(scratch3, 0x16d0b13f5ded8d0efa54330eb18e4578da25960c13c2b3bc4c10120d1a3a4245, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x9366c29ac578731c5e4762ef13e0ddab35881bbce45191f3cc34574a83616a0, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x93faa710ce7382b8371e3048c6936db9eab8102227a669029c9d99cc764757b, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x295d7701cb770bb4e84041bae24a2fa4d709f817e9dba6ec7b67faa53dcf1796, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x10e4e9001fcf240592ad4fcee9ce023ec8a44ae73dad0ae729e0ab6c1e2cfb16
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x22e2c0a0a905bc2895458825f8743a36424c5db130ed514252d9c68b10802375, F)),
                    add(
                        mulmod(state2, 0x308887446d2ac2a9f95b40f9f0c9635e844ca96de2d2be5bd2d26f8906fe225, F),
                        mulmod(state3, 0x10ffde6318449dac11cc4b5af734f90f06c934e1edd7ae1b1b0ddc0cd3a73834, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x1c786add5b6c36738ab10c3e4556cd259cc4698e435e353aae8901d0aa75ae24, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x232c0e545f0d39899a0083ece120c9abe67bf106e755af49a3316a54e2188712, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x1d17d4e2cce2ecefb2fadd9f0cfb930a7ce0a59468c38482432c28daef34b648, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x27769ea000db83e48ac10ddb011844dea254f8f1cabaf07b4c7c7bfd05cea066
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x1a6b5771d6803fa1a5e7c592373bfe1eb3885cf50e2c053f5c6a200b375d0555, F)),
                    add(
                        mulmod(scratch2, 0x14a35f9a8408b3679732b05a2b1f66598ee4a1bc8b8fde2fa50532b84a2c0a90, F),
                        mulmod(scratch3, 0x21614acacec1cd62d1cacd5553d7e7ef7093afdacfbea71949042508473a2a3b, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x26d6c35db95235fbcac91332bbf09cf944d0da2d9359495c3cc523e2e7f1a838, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x3019d2ac9e47c4e6fd2a1e2760dfbc772467f1ae42284a882c63f647cbbef95c, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x257f8ab9ab34f2f43714726324aeca465e01c9d41bfa29cf888be5ee4bb1d410, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x28d1da0d0763b3d167a9ddd076710aa447218c5ecf9db1cdd91011c49158433f
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2cc0d49d59dfd866d8fcf45d0bf9ab4cc59e64752cd28c1f4664cae1a703a69c, F)),
                    add(
                        mulmod(state2, 0x1a09769dc37a362f3d1f7073719d791d890d8eafce749dadcb87804e435dfd72, F),
                        mulmod(state3, 0x1005bb85bc7d6049361cbb896158f755c5bab3f8a3e89af2b713c05df35c9fb, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2d82b897a768a526673d6ac8ab2ceccb3dd82711f3eea69cfa6b28c4c0822ac3, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x18f7da524f4aff58711b019358ecc2b16d72ac334daffc073e93efe0b4f1a4af, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x148950f45e6f9a04daa319b8fdf9c0fd03ce074947d2a564aaaed7a96030972e, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xb6fd9557e2a641268c71b3315aeae9b6a6e144f1c3dbacd87297b8275e9ee5a
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2757b835290fd122654c2928ff7df171003b827a4e7280b5ae5bc38643ea0963, F)),
                    add(
                        mulmod(scratch2, 0x2844d0be5c0d20b822d771b05b85e98c91b3e6a7e90574c5714a499117861118, F),
                        mulmod(scratch3, 0x120268cddce641db4940b4d6bd285bb36d6992aa644c1652b3a92754ed9c95b1, F)
                    )
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x19f85468653c742abb9cdb845a8913a4afefd7a0fc3bb42cba9b1b2636e8ad4b, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0xfb5471092d8d750776ef46cd9f8227cab2a1d01e36e54192b24474a4de75d03, F), F)
            state3 :=
                addmod(scratch3, mulmod(scratch0, 0x2035e88b8c7d70007f01c41e605b868371fefeb893e0c53b2cc287499c0630a0, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xb1d59ab1043ec3c65d75ab729aa25f57314481b16b6f3692106c8f6dfb4791a
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x1d1fc29e388a4fbed580ce020b1f96a4aff71f4e96bf82bc39921dcd816a37f0, F)),
                    add(
                        mulmod(state2, 0x107fc410f38708d608e1fafb5beb313033152ce6c18e601421df97f66e73d53d, F),
                        mulmod(state3, 0xee81252e959d47a5c974fa87cc21e282c985f95d24e1c71f6c789cc0159b567, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x98f1116ff2cd835c7f2921959fdae8b1bb3b93a3d17b37ab7bcf1e5aba5ff09, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x380010061d18421c057ce541060cc37846ddd5baa3b8257fb81367223dd8c22, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x2c270f27c14f61409573b01cdac9d9ad1eed63996ed16fa71a4d0291a495adb9, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x175db130ad7293cdaec78733c2528c7b893c4de6eeaed6ddba403704996c2904
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x175b2013641f199ec0ee8f1e58b5b0949d9d82abff03e9097a2e03dae0738313, F)),
                    add(
                        mulmod(scratch2, 0x8c2c9eb83874c089ee29496bc5b75ede2334bcef4cdc0a7dbde5d8853097ec8, F),
                        mulmod(scratch3, 0x27194fdbceb6493c4d2c52e120642f71ca7c7ec1eb1fb2164a07cdd4ac6bca4d, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x29a3650d24b9f5b5abf9fcd6766c9dedab20fa325c10d7282e2a39f264884980, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0xd26f20690f7dfd5caae8b9a6ffe95f862c7528035481e0abba2396e7a618e1e, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x1236aff173bc7288e48a2ca8e647759129d6b7e9e1d44961d4e32fd98d3f9fe4, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x1299be102ffc5912ca1b62194f757baf54dc3a905c6c70db3be21c64ae1cbfa
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x2dc6dca9f079d02912f38063de9b3b72edb1597251bc387ee96c7b485faf9014, F)),
                    add(
                        mulmod(state2, 0x2cfaf1766be1ecd8468dd41a537d287e3c3f1c695f08e59d699cb2af7c39add8, F),
                        mulmod(state3, 0x2058a3f15c656f94d9f3c378074655cd4dba5fe94fd51c379cb36f938bf24611, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2bae3a90726676f3e7e2ae4ac6ac565f7e2d101d3937909e08ecb66bcf2fdf12, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x1308b851cb6577dd1431d2a108c636ba711e15f490e7886f173d42f807bc1e2, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x1a641971b280f65c201fcd422d4fd4518349f023b9e5734aadd2fa58cab44aec, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x18f4475a847d162e4f20b36a7b52ed32703f35d03c73bd0b36193d1015944ecc
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x275f6a7b28c4552228b34d35fcb416816062bd2306ac1bf37829284cb64df932, F)),
                    add(
                        mulmod(scratch2, 0x468d9cbc98f5da1e71f62ef54db7460a246bdef96a9974f32694650ec161275, F),
                        mulmod(scratch3, 0x2fcd5759e64ece88bd02f1f93d307ecd9667a3b7fd94a98247baed3432dd75af, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x7aa214858a5fb4feb41fd2fb463abeb46b4d94fd6f479c77ee83e009d4b0964, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2759ba8ed89fe56ac35d079ed0c6672b33edf2d206230e745f418b0ffc1bb7b3, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x29ebe3a88017dbbd3dee8b11de049410e395bb5f4d67240bc107d8f00e9b7d66, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x2c34fc0c526b82970f0250ba724d6b2b4cde991aed21c3cec2a20c679ccc84c4
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x43ac3249f1ec7c834d6506a7981be98fa65611f2c234ba0138ba38496285390, F)),
                    add(
                        mulmod(state2, 0x9aee3aed2b8f3da8569ff6f977bbc1bd91d5f6e71897339f4d7a524bddf76ca, F),
                        mulmod(state3, 0xa08663929d8e305e25d81152fc3b959fce8f9477ccc7520355c6eba6d72e0ac, F)
                    )
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x25e982d33daa5a66f32b0826ef96cd235c02725b0d44508f0cd50f19613a40f7, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x1cf184d8bb6e6fb16e87c3869c4287157b9782e3db156ad6b03b1b6a1682567f, F), F)
            scratch3 :=
                addmod(state3, mulmod(state0, 0x84b98f54b7058903b99b974eea21e9d07e1cba4a01f7556e926d16b84412a4d, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x286efc9b3f165541ab615806eeec285646e88d84e36b957fd4f456d170f9861
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x1e80853d17c22e54427ce24858a8df52e5f9f82bd7e43d2b2593767e393606da, F)),
                    add(
                        mulmod(scratch2, 0x2ac32cba9bee353125aa0ca0ea5c746b574875947db9d2666078a10425e8c60e, F),
                        mulmod(scratch3, 0x4d6ba76337fa37970571c97b1d386e75000679064042f9258aa97f7d1646782, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x229ba1a346962eeee8641de969a7417afb640d1aed44b031cbcf18093cebdda5, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2adb63f52d0d8b84136afde227f6462e363dca873c0948ec5a09bf884e3e55c3, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0xe5dc3d15f61d8e0dc2c1e4eb2785d873dcdbdcf4d1216e4b4ee63577e6f984f, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xbba8d477abf6de1535877497a0e9dfa2efe8ef919fea8f7e2d58952e4ce8014
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x6991f1efc2cc5b82336d6c72d6f773f2c991fe00ec5e0ec3b843c540b57b905, F)),
                    add(
                        mulmod(state2, 0x1460938c892d808b14e8d741dd2fa7c696ac17b62bcc1ee5df5694a35e132a2a, F),
                        mulmod(state3, 0x102929dad70078635d447a2108ba8655841540e859517bc66e99993a7e2d65e9, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x1ce63bdaf3f2c0eb883c4b0add7d10ea66678fa194d6a671c1dec12200695d95, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xa4d7ca5f2017d8d79bc1ba2f525d06f0d2bb7b8c4b465fd15852462d7b5bc8d, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x29fa3a2fbed2886e9fa7ae54e854ffc02fe118fb7575307763219fa7ecf445fb, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0xce4df9a7783f25fa8a0314923bd8342d89b8c1c1f73c44454a9bee8710686ff
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x26c99f9a7f34c37f60c2151708920b404f59330afa0e93794b47d6062e92dad2, F)),
                    add(
                        mulmod(scratch2, 0x3d66dc153d207a6dac2a8584418d2a1765465801780d52bbbd457e30d511805, F),
                        mulmod(scratch3, 0x1d9d2c271f135b728f6b5126c55090ebc1bf536792e68d3828b6dc3cb205f96b, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x122ee2ceb53c8bf75cad4199f34844f10ce7f7c1eceb194c1c0995095bff0f34, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2c5de90728025f695a97bf49f339ac7f5759cfc0a64579bb517043e8e83986, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0xca7a0ad4c9a1e0f2c4fad7d45bf857525f30f5cf6b668bd89315037acc0e5b2, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x230aaf644cf2bb574f9ff8eb4f379844609827764f6e1dcc16dec44b1a0e652a
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x72fca1ab68de8ea219830012753dfa0e4d7b4e82de6b4d587880aa5aa7677de, F)),
                    add(
                        mulmod(state2, 0x1c33f874532a1c963282a57c4c23a9fd8205292219e3ec8973cd112b5024948f, F),
                        mulmod(state3, 0x1f4235417fa09810d87ef253d7241d8b60885cd2e7a1043c3f796bc9a6e18b4c, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x2ff04922672700cf6264e7afa3e53defca5bf17a6233f20576835c0eec820263, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x2be78a609db3816594eca211ffd2db4d62ff20a0f699b946e0eee333d660a50b, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x144f7514466107b17c830e7107a8c0079b978d5ab9fa4f984ab48dacc297981a, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x1dd8a4943ea8f52cec9f22833e75137668ee9ae7f4ddfbb168d49484aa20c462
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x123c4a1c8e4899688f82e01003734d6330f2f1dbf3381351e5dca8fb738bdef2, F)),
                    add(
                        mulmod(scratch2, 0x119e67fde655b5955a4b5ec684edd8bf2206b2a7eb59e9f15096ca75834926af, F),
                        mulmod(scratch3, 0x17836f4a1e751f39a063ac6209b889d9497132e50221c5398be6bec44d388afc, F)
                    )
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0x706b2a2dabc375c06dae0ab44cc148c5cfdae00a42c1ee91f544116ac50bdde, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0x185d93cf4e7d3f43ffac98bbe4e6de82ed7cd5f45f7dabeed62bff8b2729bdb7, F), F)
            state3 :=
                addmod(scratch3, mulmod(scratch0, 0x28fde9b0f3cc587aa7c5ed5851c497fe5c585ee8f6fbf7b362ee8079ab029e6e, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x5fdd9ec5b71a22bcbd1b5f9d7070d4974b72690d5e5f076d803305649a0ddbc
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x23d3af708ec92177cfc7be51b19f804c6e094893af419f7539a5d9cae193ac5b, F)),
                    add(
                        mulmod(state2, 0x2610a2ef3075281ef660ea0bc85d46d99ec5e9986d9ccd5d5e5d2f442e2b4b4a, F),
                        mulmod(state3, 0x116e9d296c54176b377931cbe78b7fe6bc36dca94e3eb4a356a440d3b7f0c5ca, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x6df27706ae505c3290bce845b77e71b9896cfce530043f1ead4ab71b752cef8, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x24c364f8128c52fd2bb181978419d08f95bc16dcf2e8c2c3cf3d1ea225d8232, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x7ad437e2e7226d43a336bf1ef9d24ddb628e73d052c0be8d59faa00fdee4faa, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x214b27ccfb92912b5e34c5d28751fc9fbfc0bd41203e9e275cd17d29f9583d2c
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x2b6ca6cb5714df573b05397e94dc43fe3fa69ea197a4e9e6d41e2b848a62303d, F)),
                    add(
                        mulmod(scratch2, 0x2dc35b8f0c31ebad882a1b5ee562422d2ca238b40ca6f131143dfa2ad705f89, F),
                        mulmod(scratch3, 0x42822031f2cd628fa285d180cf3a8f4267cbf7b553ee89c1615a32758149fbd, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0xf7d48e540fb1c52f4d02b923d866fb74b309a30771ccbbe198d343dc77a0d7b, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x11cbb9e57127376b285a244abc9f8335b47b687c443ef08f7d974fcbc07794f0, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x293243c2cfc64e120e7554a1abef0c9ac3e53ed28c7fb7e67da72f0de9e0af3e, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x4167b7521f2df586ce40a5cbb0a5a8894741e4668d319747beb58c41fec8eb7
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xa4e062370da0495bbda23efb2fb06dadaf7fa13c9101f12baf1bd1b1c96bdbe, F)),
                    add(
                        mulmod(state2, 0x151221d44d3e0c9bd72102675c4b23c4d9aa17fc699a3b95e39d8ee947c61168, F),
                        mulmod(state3, 0x78bd872bce9136fa5bec6e7759fd12faf09a2a49d66a967533590a102035235, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x14ad26225e4db9cbbd72b7b380eb4cb3bb142ef7b402081ba72fb6ace89ac388, F))
            scratch2 :=
                add(state2, mulmod(state0, 0x99586a278a3e3011da16bcae007974b7ce4d62c90b01b9c3659386b7e2f2732, F))
            scratch3 :=
                add(state3, mulmod(state0, 0xe03608aa72be7e2297de6dae9ffa81d7cf9d9f6eb4a71470a18f21c0137a5f5, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x150cb2e59c15571a4a13bf9717f7bbf7ad16d02e390b16ca28584fdf62e1c887
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x6cdbeb5979f2e57195c5b240a90dbd2418a263187082957b0a73d77b60626bd, F)),
                    add(
                        mulmod(scratch2, 0xb56babb7d7a663b2e767f30ca0af82cd79dcef11f091e42bdfc73901997218d, F),
                        mulmod(scratch3, 0x26d69e0f548ee76e51ef3b8036061df831950abae011e1f1e856d09c7cf6aa8f, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x28770922bd2803e9f286db50fb2b8d6f7117c39e648c4fd3f1fedff6943fa2ed, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x479e59c95e648bdb151d5438a7b1a78781a47778497a5d786628bfb06c40154, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x2e989373f27c9545fbb54b7238731a8109fd312ede4a024903628eb3b87e4197, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x91ad8b935f188b7e8accab9ab0714c7a49387f077a7de9876a5144733310a3a
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x21cf74b69dab5939a76c0b5354e4437d01524502155e40e204521176235b780b, F)),
                    add(
                        mulmod(state2, 0x18e04196ea623a0a9b273cbfb93bd711966f7248cf28bba89cbd64f1aa5612b5, F),
                        mulmod(state3, 0x289e5d4f3b63956a39caa9adcb2199fcd1308b972ebb5d0d82b257b9bfd7aad8, F)
                    )
                )
            scratch1 :=
                addmod(state1, mulmod(state0, 0x18c925e9d138474b0e5ab38fabbcdd4ff7c60b00fb1ab9fc03d18946fd7d9d4f, F), F)
            scratch2 :=
                addmod(state2, mulmod(state0, 0x1f53108d9d46d950bc002b8fc0fdefcb2ebfd8da16c97c4a11b4c5f890f62ec6, F), F)
            scratch3 :=
                addmod(state3, mulmod(state0, 0x171b1810a7b8f9e4bd265939c8376898e91c503e5ea889bd5cd4a39ebc511f76, F), F)
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x190c7326b3ad92f47b26dc0d1464260980b2e410406b9f90ee88b0bb2f714130
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xaefb2792216adb5c751a91b3cfe1ebb388ac1c76eb3e6ae9c63eb46ae8c119e, F)),
                    add(
                        mulmod(scratch2, 0x126a917bec9226d88ab7eff57258926ad6a0e97ed29af2d5475d92601212e658, F),
                        mulmod(scratch3, 0xab542132b45cc89b238a953ad6067698f3b25d636ea4b78c165646f79eb74de, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0xb5bdd2ee504085ca1f7f9e7c22ba8be4cb303eeb95bd587a4206f4b8b96aa29, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x1b1dd50fe39bf868dc6548ca661f4cfcbbe3b6ceb65c9bc3724efc5a124668fe, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x1c692a335947cba29d21fd4c8994c4878f2693725b4bd141ccd49a599b2fef55, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0xd22439c275dcd0acaf5e17e0ef860215318b6cf072ec0e0a90084b61cf65f0b
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0x5df3198344a820f7b951cc5a0f8ed1025f545ecd1d889fc3fd41c11dfcc7299, F)),
                    add(
                        mulmod(state2, 0x2cd9ea732211aa8fb71f1654d1e9f933649faa16cf839df52049f0dcc15f111d, F),
                        mulmod(state3, 0x280d99984b03049843f20ac6aa0fc18146207d10bc83f00e45331d5e8ac94a16, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0x11603c758dff6c1a43cc980518ce2ac7ee5c2df9fe1bcab3d6f97a7d96130d89, F))
            scratch2 :=
                add(state2, mulmod(state0, 0xe5fdcc614e1102079ef036da466db690f79648ed472a0fceea84993c74582ef, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x1403cb9aba4d4b6178ed16b9dc6f6250f3a63ea8f99b5bd78c6d6884add8f99b, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x19d43a28efa441e38d39b0fb38d9a325bcd3a7d1c99124e6f3d39efd15a9b2fe
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0xffa79411b0fd18104f179c0d2e88266544b5255cb92038a6ad919d6c7e390ef, F)),
                    add(
                        mulmod(scratch2, 0x287fd57edcf07e6db3baab4c5348662de28c328fb50103e793135cb67c229e26, F),
                        mulmod(scratch3, 0x13668c71348d000ea30f31f98c66a4a1c9bac85647ceb90b77f71e54b2a94e48, F)
                    )
                )
            state1 :=
                add(scratch1, mulmod(scratch0, 0x2c53eac1a30aa44a0ea5eb0f41033f47713d5ef9684befaaf60b9c62587adba7, F))
            state2 :=
                add(scratch2, mulmod(scratch0, 0x2b4de349afb1a4904c13f2d2ed11a86d1d4285a13d3f627380f21f75703f3363, F))
            state3 :=
                add(scratch3, mulmod(scratch0, 0x76d942e289b022b369c6187e938947855ea1a7fc3db0d28f05b1b93143edbb0, F))
            scratch0 := mulmod(state0, state0, F)
            state0 :=
                add(
                    mulmod(mulmod(scratch0, scratch0, F), state0, F),
                    0x23c7399b1fe74afa14e11c61154bc4bc47e5965b5dd198b39506f69614160309
                )
            scratch0 :=
                add(
                    add(state0, mulmod(state1, 0xbcc66f1cc25a23ac337b702358e7111b55f0d0ea27b9f68047bc39b587c7d42, F)),
                    add(
                        mulmod(state2, 0xe78cf6b1817c2139321076851091f7212dd8bc342d33a52a4b71f0aaece6a30, F),
                        mulmod(state3, 0x50e895683b02999a4b5fa898b61f8d17c1168c909ef8fde3f5f2573c3448af7, F)
                    )
                )
            scratch1 :=
                add(state1, mulmod(state0, 0xae58a953830e16be1c442029223ed992e8db48ee4ad1ee8825bdb7791b0e8f0, F))
            scratch2 := add(state2, mulmod(state0, 0x248462e05806a40d93c1ba1489548f1774f7b921bc75aed841b3a47de73b16, F))
            scratch3 :=
                add(state3, mulmod(state0, 0x1b476cddf10a3ff6b123f903a9732861c447a61ba55391133ecd712818343578, F))
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 :=
                add(
                    mulmod(mulmod(state0, state0, F), scratch0, F),
                    0x2f97d90e9db83548cd2323ce47c1db1b6e773b74c922571a0eb6497678c735eb
                )
            state0 :=
                add(
                    add(scratch0, mulmod(scratch1, 0x1c595c8ae053a7de9b0469bdabaeacac203f0af93fe48b7e7afc34dc0054b30, F)),
                    add(
                        mulmod(scratch2, 0x123b106520fa9e56ef05ec69ad7c6986ed58ad08ae9a0d9c24c44977cdd4a3c3, F),
                        mulmod(scratch3, 0x1f5ce878fe709d0cb23cc5b2d8545cf7a99222f81e60b126ad198854629e2284, F)
                    )
                )
            state1 :=
                addmod(scratch1, mulmod(scratch0, 0xc0a991b3c9e1d536cb198ee13c072b0e15b1331b607692385f0e3d22a18200a, F), F)
            state2 :=
                addmod(scratch2, mulmod(scratch0, 0xe2fbd479ac1e012f1c177bf8d09d7b45951800a41a826aa414584443c5db973, F), F)
            state3 :=
                addmod(scratch3, mulmod(scratch0, 0x27ccd60840adf2f97229e5ff04b5a0c782b987c2f83647930c3c97e1893f3354, F), F)
            scratch0 := mulmod(state0, state0, F)
            state0 := mulmod(mulmod(scratch0, scratch0, F), state0, F)
            scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 := mulmod(state3, state3, F)
            state3 := mulmod(mulmod(scratch0, scratch0, F), state3, F)
            scratch0 :=
                add(
                    0x2c3c4d9abdf8c064a840e815dc3108330fd9af43840c59de785a0745f701b76d,
                    add(
                        add(state0, mulmod(state1, 0x305371407871eef9f2b8ba170ddd1a184cc268c7c68a1d8177b5edf2543827de, F)),
                        add(
                            mulmod(state2, 0x6dffab7a1280f76f84a9448dbb105b5ea0ac9f3e885bd07fa5e91b194bba2c1, F),
                            mulmod(state3, 0x1bcc6988e078bdcfbec79086afd498036c996ed6028f45825563246c64684d3b, F)
                        )
                    )
                )
            scratch1 :=
                add(
                    0x75a2cc153c160597721d3b498cab391bcba53cf6069a8009af569879fcffe7e,
                    add(
                        add(state0, mulmod(state1, 0x30160322e56c7fe842d734171f56165c54fd479aac92ade950a8bbfa2bc9b9ff, F)),
                        add(
                            mulmod(state2, 0x9927fbf82ee91c25ddc3f453518d771c85a9b60689b4747f4b97761a121bce4, F),
                            mulmod(state3, 0x201e6a43a791cf67dcd2e4cf599d7b27b94336943f73af66fc302ffd693bc512, F)
                        )
                    )
                )
            scratch2 :=
                add(
                    0x1b964a10df2b3b4cf12d7d85ac318f35f6ff769902c9182bcecfeb4268771812,
                    add(
                        add(state0, mulmod(state1, 0x21133e53817739f46fefbd72b81eba0bb7aa4f8f7fbd2562828a690375af52b3, F)),
                        add(
                            mulmod(state2, 0xb38c7c6b78e1ef4c34d61560cc96b5563afaee07d80839801be414d0a4c4fca, F),
                            mulmod(state3, 0x1af6a88bc5e30031838ced25b87c11ea4ed35ed372919fcd3af01f2f77c2618, F)
                        )
                    )
                )
            scratch3 :=
                add(
                    0x26e5aeb6cecd546f38531ee60285a2466e758626b0c60680f45412740a7f1c49,
                    add(
                        add(state0, mulmod(state1, 0x17b24a4e284f8206a1f5e2f0b1c1192fa4fbaf7076bb71bded454ace29e6f952, F)),
                        add(
                            mulmod(state2, 0x6c6b39653c0abaea7cfe9733567a0e966d13792cd0f5b0e1d36eb471896b1cb, F),
                            mulmod(state3, 0xedc9343e7fe93e733d823e545f76af781954996d6f7261b0e83daeef7f7c9c2, F)
                        )
                    )
                )
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 := mulmod(scratch3, scratch3, F)
            scratch3 := mulmod(mulmod(state0, state0, F), scratch3, F)
            state0 :=
                add(
                    0x2f3333a78e805aabf9c96cffb2b98e9d74d338b8090e1fb86da2d7adbf214e03,
                    add(
                        add(
                            scratch0, mulmod(scratch1, 0x663ced12e20c43e9be6b4ba0a11fcbee412ed9874b03a2b5d7bb57f75b6220c, F)
                        ),
                        add(
                            mulmod(scratch2, 0x98957baa2c63d11223b7279f117d04f8d9a187cea4853157dbac91d0b0e1aaa, F),
                            mulmod(scratch3, 0x59e4c781799bb33aac6a2019bcc51e5afc3178d09df85dd453d7393a38f01aa, F)
                        )
                    )
                )
            state1 :=
                add(
                    0x21bb1a7308b90562e0f4a0a836a18b30ad7c831684e5ff504b662cc43b4d272,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x1b734ed59b2f987d0f0d72be82bd06c39f181f87f400baf52f2e1257bd819fc0, F)
                        ),
                        add(
                            mulmod(scratch2, 0x132bd394d45a477c00d36de5f491ff879b102eb08eeed5c4ec9b4ef1b497a2ae, F),
                            mulmod(scratch3, 0xbb63982636c126abbf19369180f9fcb462949051681ae1873bd0f9cf980210a, F)
                        )
                    )
                )
            state2 :=
                add(
                    0x22951469dc64e98c9c98b0f8e46e87e1e3d11ce3e7fd912fd11f4644e8c82158,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x11e70e954d2c78c9c7ce9f0cb1dbbddf79c8f68e843413bba55e5fcefdc43fa6, F)
                        ),
                        add(
                            mulmod(scratch2, 0x2fe567a2786f2e383e3e65de78fe435b03a529ae3e05190a1ee64bd0741a3b3f, F),
                            mulmod(scratch3, 0xfa4de83927ee03f6244d1e44c45bc08acc5b9c52859892dc2606e5c486796e4, F)
                        )
                    )
                )
            state3 :=
                add(
                    0x1bc8a3af3e4924ac27bb916f03446bddd7983a41e9ad0d3a69a9f844d209ed9d,
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x11e6ed81c0972175c1f3ae7f236fbacc96f04ea0fa21ace4b345c5e32eb02dc1, F)
                        ),
                        add(
                            mulmod(scratch2, 0x2b3983475518fd06fb0f5fe025f1c20a76e99e6c2d4ff72f08931ab38e7a97b6, F),
                            mulmod(scratch3, 0xc7e9c9ecba22d4c5561f6eac027619718c371a4f43ca329d19cc7a1e0bd6a17, F)
                        )
                    )
                )
            scratch0 := mulmod(state0, state0, F)
            state0 := mulmod(mulmod(scratch0, scratch0, F), state0, F)
            scratch0 := mulmod(state1, state1, F)
            state1 := mulmod(mulmod(scratch0, scratch0, F), state1, F)
            scratch0 := mulmod(state2, state2, F)
            state2 := mulmod(mulmod(scratch0, scratch0, F), state2, F)
            scratch0 := mulmod(state3, state3, F)
            state3 := mulmod(mulmod(scratch0, scratch0, F), state3, F)
            scratch0 :=
                add(
                    0x21d08567dd584d66ca6c5f48e30ddb2d6fbc38802499ca0e12be623caf939964,
                    add(
                        add(state0, mulmod(state1, 0x663ced12e20c43e9be6b4ba0a11fcbee412ed9874b03a2b5d7bb57f75b6220c, F)),
                        add(
                            mulmod(state2, 0x98957baa2c63d11223b7279f117d04f8d9a187cea4853157dbac91d0b0e1aaa, F),
                            mulmod(state3, 0x59e4c781799bb33aac6a2019bcc51e5afc3178d09df85dd453d7393a38f01aa, F)
                        )
                    )
                )
            scratch1 :=
                add(
                    0x28a5489f87bdfa9daeb240388b0d4fc30ca788cf55531acbb627c49e8cc6aa75,
                    add(
                        add(state0, mulmod(state1, 0x1b734ed59b2f987d0f0d72be82bd06c39f181f87f400baf52f2e1257bd819fc0, F)),
                        add(
                            mulmod(state2, 0x132bd394d45a477c00d36de5f491ff879b102eb08eeed5c4ec9b4ef1b497a2ae, F),
                            mulmod(state3, 0xbb63982636c126abbf19369180f9fcb462949051681ae1873bd0f9cf980210a, F)
                        )
                    )
                )
            scratch2 :=
                add(
                    0x2d64a03e6c0ff9409c161b6a21550763c76d43a9dd9269fb759bb15e8ee1ff25,
                    add(
                        add(state0, mulmod(state1, 0x11e70e954d2c78c9c7ce9f0cb1dbbddf79c8f68e843413bba55e5fcefdc43fa6, F)),
                        add(
                            mulmod(state2, 0x2fe567a2786f2e383e3e65de78fe435b03a529ae3e05190a1ee64bd0741a3b3f, F),
                            mulmod(state3, 0xfa4de83927ee03f6244d1e44c45bc08acc5b9c52859892dc2606e5c486796e4, F)
                        )
                    )
                )
            scratch3 :=
                add(
                    0x1e97712cf954722e28241527d9af5f56910e14cecf2de15aae95269b198bba12,
                    add(
                        add(state0, mulmod(state1, 0x11e6ed81c0972175c1f3ae7f236fbacc96f04ea0fa21ace4b345c5e32eb02dc1, F)),
                        add(
                            mulmod(state2, 0x2b3983475518fd06fb0f5fe025f1c20a76e99e6c2d4ff72f08931ab38e7a97b6, F),
                            mulmod(state3, 0xc7e9c9ecba22d4c5561f6eac027619718c371a4f43ca329d19cc7a1e0bd6a17, F)
                        )
                    )
                )
            state0 := mulmod(scratch0, scratch0, F)
            scratch0 := mulmod(mulmod(state0, state0, F), scratch0, F)
            state0 := mulmod(scratch1, scratch1, F)
            scratch1 := mulmod(mulmod(state0, state0, F), scratch1, F)
            state0 := mulmod(scratch2, scratch2, F)
            scratch2 := mulmod(mulmod(state0, state0, F), scratch2, F)
            state0 := mulmod(scratch3, scratch3, F)
            scratch3 := mulmod(mulmod(state0, state0, F), scratch3, F)
            mstore(
                0,
                mulmod(
                    add(
                        add(
                            scratch0,
                            mulmod(scratch1, 0x663ced12e20c43e9be6b4ba0a11fcbee412ed9874b03a2b5d7bb57f75b6220c, F)
                        ),
                        add(
                            mulmod(scratch2, 0x98957baa2c63d11223b7279f117d04f8d9a187cea4853157dbac91d0b0e1aaa, F),
                            mulmod(scratch3, 0x59e4c781799bb33aac6a2019bcc51e5afc3178d09df85dd453d7393a38f01aa, F)
                        )
                    ),
                    0x155d8e9f7d34ea0090e8d2800b7d538cbd170dbcdfda0a1eff5bd182fb879c54,
                    F
                )
            )
            return(0, 0x20)
        }
    }
}
