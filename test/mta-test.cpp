//
// Created by 何剑虹 on 2020/10/22.
//
#include "gtest/gtest.h"
#include "crypto-hash/sha256.h"
#include "crypto-bn/rand.h"
#include "crypto-encode/base64.h"
#include "crypto-curve/curve.h"
#include "crypto-paillier/pail.h"
#include "crypto-zkp/zkp.h"
#include "crypto-mta/mta.h"
#include "exception/located_exception.h"

using std::string;
using std::vector;
using safeheron::bignum::BN;
using safeheron::curve::CurvePoint;
using safeheron::pail::PailPrivKey;
using safeheron::pail::PailPubKey;
using safeheron::pail::CreatePailPubKey;
using safeheron::pail::CreatePailPrivKey;
using safeheron::zkp::dlog::DLogProof;
using namespace safeheron;
using namespace safeheron::rand;
using namespace safeheron::encode;

std::map<std::string, std::string> priv2048 = {
        {"lambda", "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93d1fe2f400fe25e95eed238e545d2ba504ae212da3ddd01c4eb6634a4e5d4d765f5dafe0693b03d87dbacac12230e27930593725ae222c11c501b18794fa0d5a283dad49c9fd4a16b54604de5b9aa3d0d36bbe15a5a8d51a20b712245035c290ba0d3cfa701ae665b2f0a153bc8c8da941c676b206b161e9391c152591e9fbf224"},
        {"mu",
                   "11a7a4fedbefb6e095b33f34e3b0319f2ea5f35cf008c53c28c400297ac34917e7d0f7124dc9c8d4d31b6e08cf95034b0a730f353822ad29fff108bfdcd1762530c4be0e152c5e1beb3946495e8a9dd1f93a4fb8d9c0431cec9f8d1007d8cf75f5b8d740595ba0d374d42c360c3f680c85b080edba823f5b922131c484965ff18c731dabbde53b3ca16d123c0eceea37705f33bdad6c3187590d201f48465d9e1de09a649c5ee893157374b764aafd50f7c82896c76861627f5bca754d22514fdedc6d19050afa7c78c1b8e090bde9c0b9fb98e903a126063361bbb8123ab1d5fc1e8b1524a014cd3f5a264758627dcda53cc88f7af83ea6586d570c78f9d73f"},
        {"n",
                   "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611"},
        {"nSqr",
                   "6822b1e5d8b6006a3f3684e380bfbc2763b6315f93c1e8a02386c1639bb781f8e04b99e110affd8adb277ca46eba4345895089dd6f313f4853ad20e9419946439a177c07db78799824d67adb0a22523bffc6685017d8a12dc054b22c3beeea0baa0d264a2a37d02d25792fd0ce23ac23ccc2daacf9f131ac4907235c53635c39a5bc683f60a9d6edc04d64f0c4c6ff92c4e2a913e4e13cbb2575335cb74f0660a7b9400f9fe9dd1188e48530d4a768773f10f8e60c19b8cd21a02580ea88537f0380de7db354b952b2ea0d930782e7a66a942cb091e941a8dc79a73a732e40bcaf1e5551ab49f417b9ba82e12e9b1331da10fa52468f48ebacdfe5f97eb64f2e54580afb9cd81126ddbf560a9ffb068e35ebe9928ad922d84d44ca36b8533de99d687264732798e36e810b5bf80b1119c0f5a8c0fec9580564dfe5d4f50a61dd3baff354151d1bde7dce45d2ec83e7bc3eb6a428326861a3deb5854f741be7a99f2ebfe97d66db7975abd8581dc067941e193a00fccb698f1b243342719a3a6fd57a3ca54232d32eb6f45e96c3159065bb4118b9849fa2b2f9fc9ef23805d99a7ce065fd78a48d6aa18c6bed2e0cf943c4bd5af52de69cb783c9a1861e9e522f6d597cf0248f67ce9b668c6295b57251ef2c6a6e19064ab8dd9324f46394eeeb79eb29af6f5a54df8048e7256ff94983789a1ce971ea37e0a3e3dcaadb3f4d21"},
        {"p",
                   "e6118f475fef7194edfa31aff540ca5fe560ef9c1fa9b29d39dc3900eb67f00fdebfbdf74e34f8d1a4c343ee9bd494674838fba47f2f43c35418867fa918edd7b35eb0a5e50a76449680cc98975348784aa22c08110543fc064041a1c9c7d734fed04273220880decf38b8b34d0456f4b4b8159bc8163fc14b162bf371e4e61f"},
        {"q",
                   "b5ad8a0d18f5b924da639591892f9842d4a89c6014e485498a77e5caa2c77c12510088c972f01fe1555d23cd411eafb4ec000f41b6faddd1c62fc5bdfa6bf3de5586bbd83ca0bcc34630170cd8f5c04344bf7cdba30a770469d6638f5d5a82f4603e146816c12fc632c313a10dbe52387e8cde2556997df31bbd2e1c0a986dcf"},
        {"pSqr",
                   "cec38ea8980dcef88d0e253e1971fc9be1e00c88955f27c04c2a07131a2697c7687700513cc8e9eeba083e52366986e8cfcc766b0f30fbeafef675658cb3f9deb57dc7555ec0364b7442d6212590b73735398688e39c45528756e31855ed3fa246efacfd890e03c2f5d1333692b3894f56e382acc556cdd2fdf1e6a3339f056373a8ecf21e3e87635878b19c4b8120d65427b457a7a8ac941eb1ddb48220224467bdcf3241828a24660751d97e52da7b6989ab385ef7b878c89bc83300d41c3e3be804370179f1d70e576f7b835a29a17968e07eb6e1ad6fd5b6d87ff665b46ef78ced9f9f867587ff9dc723de84869d0463113e9bd99eb007db28ac1413b7c1"},
        {"qSqr",
                   "80eedada6571537ecf9f83dc4d71c7eb30cd0966d3f4d26325e9192a114184b41935a23f5ed2b411284426bbff0f69233fc1e552a1c3a3eb8147d5eec7f735538d6c37eccc558287e392c96fa674b003ff7df0fc75945fc67b9c033f4f255c7be799519c55d9b4b80e13eb12bfdb96e98680e4fd5be1cbaaacd9b28340855cb40dddd3a9e68c8e5883edab1d0de3b8388f4bb5e54ad8871ffe1d64f9e64ca9727cb189e6bacda59dc825c937a4450df68c08b1e1ee1e1d4fff7c5e4507418a9f9a3243881daa0b2ef1ac0a22cfbbff0555ed4078df2ab791559bcc37131488b1869e3cea0641894a25b24a2d993fd2ebacbc34ec55fc8016e6e4ac9ec0e9ed61"},
        {"pMinus1",
                   "e6118f475fef7194edfa31aff540ca5fe560ef9c1fa9b29d39dc3900eb67f00fdebfbdf74e34f8d1a4c343ee9bd494674838fba47f2f43c35418867fa918edd7b35eb0a5e50a76449680cc98975348784aa22c08110543fc064041a1c9c7d734fed04273220880decf38b8b34d0456f4b4b8159bc8163fc14b162bf371e4e61e"},
        {"qMinus1",
                   "b5ad8a0d18f5b924da639591892f9842d4a89c6014e485498a77e5caa2c77c12510088c972f01fe1555d23cd411eafb4ec000f41b6faddd1c62fc5bdfa6bf3de5586bbd83ca0bcc34630170cd8f5c04344bf7cdba30a770469d6638f5d5a82f4603e146816c12fc632c313a10dbe52387e8cde2556997df31bbd2e1c0a986dce"},
        {"hp",
                   "d277047b3f2399450c12bdbded3091607197326092c32785e0d3f6c0552716d8ffbde1433f125168d48e5438ca34e33d75fa7fe749b7ad60605401208eda7669cbec6d5017521d19fc50144179d5433290d60014a7db108851c9ce70d85577d2ea6df26a6350e6a1a8df4ce98d66f5dde71457f37581723c7ed01587322c1211"},
        {"hq",
                   "f7afbe4f1697f3d241f3e9f95fb8436cbe6ce4bfe719d855af23b1e5e7abdef3776f560436b88901d6276ac21ad8da426c746245a7985ebc9460224aecefb153ce5c3b4b257d3e25de029df3180cc2d523c388c1d5404c90127c8a5791ff46e5fae3319e3c0e20733bdde102ff64736150b41de8347d3f7c69ff3e3891ede8f"},
        {"qInvP",
                   "139a8acc20cbd84fe1e773f2081038ff73c9bd3b8ce68b17590842409640d936df01dcb40f22a768d034efb5d19fb129d23e7bbd35779662f3c4855f1a3e776de7724355cdb8592a9a30b8571d7e0545b9cc2bf3692a3373b4767330f1725f6214625008beb79a3d26596bc9bf9d6116cda3bda85294cd84cc46166c3fb8d40e"},
        {"pInvQ",
                   "a6328e28278c39e7b64456f1f334140c08c1ce141672e7c42f85aaac444cbe23198993692f84975137faad211f712210c538c91d5c8157e5fce9c3994b9cf8c918a0f8238a48e8e0e84fed2da774f415f283444f85b6723b68ae9ae9e43a8e86008fe14e33004dbeff053590ddc80b0269819c46d351a9fb551d3a3881798f40"},
        {"pInvQ",
                   "a6328e28278c39e7b64456f1f334140c08c1ce141672e7c42f85aaac444cbe23198993692f84975137faad211f712210c538c91d5c8157e5fce9c3994b9cf8c918a0f8238a48e8e0e84fed2da774f415f283444f85b6723b68ae9ae9e43a8e86008fe14e33004dbeff053590ddc80b0269819c46d351a9fb551d3a3881798f40"},
};

std::map<std::string, std::string> pub2048 = {
        {"n", "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611"},
        {"g", "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794612"}
};

class MtaTestEnv : public ::testing::Environment{
    class KeyPair{
    public:
        PailPubKey pub;
        PailPrivKey priv;
    };
public:
    virtual void SetUp(){
        printf("Environment Set up!");
    }
    virtual void TearDown(){
        printf("Environment Test down");
    }
};

MtaTestEnv * mta_env;

TEST(MtaTest, Key_2048_Encrypt10) {
    std::string s;
    PailPrivKey pailPriv = CreatePailPrivKey(
            priv2048["lambda"],
            priv2048["mu"],
            priv2048["n"],
            priv2048["nSqr"],
            priv2048["p"],
            priv2048["q"],
            priv2048["pSqr"],
            priv2048["qSqr"],
            priv2048["pMinus1"],
            priv2048["qMinus1"],
            priv2048["hp"],
            priv2048["hq"],
            priv2048["qInvP"],
            priv2048["pInvQ"]);

    PailPubKey pailPub = CreatePailPubKey(
            pub2048["n"],
            pub2048["g"]);

    const curve::Curve * curv = curve::GetCurveParam(curve::CurveType::SECP256K1);
    string str;
    // Party A: a
    // BN a = RandomBNLt(curv->n);
    // BN r_lt_pailN = RandomBNLtGcd(pailPub.n());
    BN a("7be1d6640185ee7f27ee41bac110044b04e0c0cdd13e7ff9dbcd3db284c24543", 16);
    BN r_lt_pailN("7173ad00cf469b1b55b8dc591c22000fb1ccf36d56feb4ccd03a4327d9f7afe87115675b785634a1d8b3b45c6533b4bba33dfa38fa4a40c7eeab473b5bb177d", 16);
    r_lt_pailN.ToHexStr(str);
    std::cout << "r_lt_pailN = " << str << std::endl;
    BN message_a;
    mta::construct_message_a_with_R(message_a, pailPub, a, r_lt_pailN);
    message_a.ToHexStr(str);
    std::cout << "message_a = " << str << std::endl;
    a.ToHexStr(str);
    std::cout << "a = " << str << std::endl;

    // Party B: b
    // => beta
    //BN b = RandomBNLt(curv->n);
    //BN r0_lt_pailN = RandomBNLt(pailPub.n());
    //BN r1_lt_pailN = RandomBNLt(curv->n);
    //BN r2_lt_pailN = RandomBNLt(curv->n);
    BN b("259ce861037d9b623c136aa957c88aa263c9b8c78b9c8030143e606622c8a25a", 16);
    BN r0_lt_pailN("6c469a0c4291201cf5c581d1f7f1e0e9ecad7b8ab25bf493ab2133172b1664df7c21aa20043fcef9b96ffdd92eee75bca0c762d3e124a41e534bba5429bf429d", 16);
    BN r1_lt_curveN("3c039238a077794069580bb9db134e76725718796293ffc5ecd74df70e3c4456", 16);
    BN r2_lt_curveN("e1da77074b8f39ab77c2c2131b775b863dbd72a60e0e54b4a8750cc44fe63294", 16);
    mta::MessageB message_b;
    BN beta;
    r0_lt_pailN.ToHexStr(str);
    std::cout << "r0_lt_pailN = " << str << std::endl;
    mta::construct_message_b_with_R(message_b, beta, pailPub, b, message_a, r0_lt_pailN, r1_lt_curveN, r2_lt_curveN);
    b.ToHexStr(str);
    std::cout << "b = " << str << std::endl;
    beta.ToHexStr(str);
    std::cout << "beta = " << str << std::endl;

    // Party A: b
    // => alpha
    BN alpha;
    EXPECT_TRUE(mta::get_alpha(alpha, message_b, a, pailPriv));
    alpha.ToHexStr(str);
    std::cout << "alpha = " << str << std::endl;

    BN left = ( alpha + beta ) % curv->n;
    BN right = ( a * b ) % curv->n;
    left.ToHexStr(str);
    std::cout << "left = " << str << std::endl;
    right.ToHexStr(str);
    std::cout << "right = " << str << std::endl;
    EXPECT_TRUE(left == right);



    std::string base64;
    mta::MessageB recovered_message_b;
    std::string recovered_base64;
    EXPECT_TRUE(message_b.ToBase64(base64));
    EXPECT_TRUE(recovered_message_b.FromBase64(base64));
    EXPECT_TRUE(recovered_message_b.ToBase64(recovered_base64));
    EXPECT_TRUE((message_b.c_b_ == message_b.c_b_) );
    EXPECT_TRUE(recovered_base64 == base64 );

    //// json string
    std::string jsonStr;
    std::string recovered_jsonStr;
    EXPECT_TRUE(message_b.ToJsonString(jsonStr));
    EXPECT_TRUE(recovered_message_b.FromJsonString(jsonStr));
    EXPECT_TRUE(recovered_message_b.ToJsonString(recovered_jsonStr));
    EXPECT_TRUE((message_b.c_b_ == message_b.c_b_) );
    EXPECT_TRUE(recovered_jsonStr == jsonStr );
}

TEST(MtaTest, RandomTestCase) {
    std::string s;
    PailPrivKey pailPriv = CreatePailPrivKey(
            priv2048["lambda"],
            priv2048["mu"],
            priv2048["n"],
            priv2048["nSqr"],
            priv2048["p"],
            priv2048["q"],
            priv2048["pSqr"],
            priv2048["qSqr"],
            priv2048["pMinus1"],
            priv2048["qMinus1"],
            priv2048["hp"],
            priv2048["hq"],
            priv2048["qInvP"],
            priv2048["pInvQ"]);

    PailPubKey pailPub = CreatePailPubKey(
            pub2048["n"],
            pub2048["g"]);

    const curve::Curve * curv = curve::GetCurveParam(curve::CurveType::SECP256K1);
    string str;
    // Party A: a
    BN a = RandomBNLt(curv->n);
    BN r_lt_pailN = RandomBNLtGcd(pailPub.n());
    r_lt_pailN.ToHexStr(str);
    std::cout << "r_lt_pailN = " << str << std::endl;
    BN message_a;
    mta::construct_message_a_with_R(message_a, pailPub, a, r_lt_pailN);
    message_a.ToHexStr(str);
    std::cout << "message_a = " << str << std::endl;
    a.ToHexStr(str);
    std::cout << "a = " << str << std::endl;

    // Party B: b
    // => beta
    BN b = RandomBNLt(curv->n);
    BN r0_lt_pailN = RandomBNLt(pailPub.n());
    BN r1_lt_curveN = RandomBNLt(curv->n);
    BN r2_lt_curveN = RandomBNLt(curv->n);
    mta::MessageB message_b;
    BN beta;
    r0_lt_pailN.ToHexStr(str);
    std::cout << "r0_lt_pailN = " << str << std::endl;
    mta::construct_message_b_with_R(message_b, beta, pailPub, b, message_a, r0_lt_pailN, r1_lt_curveN, r2_lt_curveN);
    b.ToHexStr(str);
    std::cout << "b = " << str << std::endl;
    beta.ToHexStr(str);
    std::cout << "beta = " << str << std::endl;

    // Party A: b
    // => alpha
    BN alpha;
    EXPECT_TRUE(mta::get_alpha(alpha, message_b, a, pailPriv));
    alpha.ToHexStr(str);
    std::cout << "alpha = " << str << std::endl;

    BN left = ( alpha + beta ) % curv->n;
    BN right = ( a * b ) % curv->n;
    left.ToHexStr(str);
    std::cout << "left = " << str << std::endl;
    right.ToHexStr(str);
    std::cout << "right = " << str << std::endl;
    EXPECT_TRUE(left == right);
}



int main(int argc, char **argv) {
    mta_env = new MtaTestEnv();
    ::testing::AddGlobalTestEnvironment(mta_env);
    ::testing::InitGoogleTest(&argc, argv);
    int ret = RUN_ALL_TESTS();
    google::protobuf::ShutdownProtobufLibrary();
    return ret;
}
