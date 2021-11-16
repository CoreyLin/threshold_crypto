use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};
use threshold_crypto::{PublicKey, SecretKey, Signature};

#[derive(Deserialize, Serialize)]
// 签名后的消息，包含消息本身和消息签名
struct SignedMsg {
    msg: Vec<u8>,
    sig: Signature,
}

#[derive(Debug)]
// 公私钥对
struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl KeyPair {
    // 生成随机的公私钥对
    fn random() -> Self {
        // 生成一个随机的私钥
        let sk = SecretKey::random();
        // 通过私钥生成对应的公钥
        let pk = sk.public_key();
        // 组合成公私钥对
        KeyPair { sk, pk }
    }

    // 对给定的消息进行签名
    fn create_signed_msg(&self, msg: &[u8]) -> SignedMsg {
        // 用私钥对消息进行签名，生成签名
        let sig = self.sk.sign(msg);
        let msg = msg.to_vec();
        // 根据消息和其签名组合成SignedMsg
        SignedMsg { msg, sig }
    }
}

fn main() {
    // Alice和Bob各生成一个公私钥对
    // Alice and Bob each generate a public/private key-pair.
    //
    // 注意:对加密/解密和签名使用相同的公私钥对是违反最佳实践的。在本例中，Bob的密钥对用于签名，而Alice的密钥对用于加密/解密。
    // Note: it is against best practices to use the same key-pair for both encryption/decryption
    // and signing. The following example could be interpreted as advocating this, which it is not
    // meant to. This is just a basic example. In this example, Bob's key-pair is used for signing
    // where as Alice's is used for encryption/decryption.
    // 生成Alice的公私钥对
    let alice = KeyPair::random();
    // 生成Bob的公私钥对
    let bob = KeyPair::random();

    // Bob想给Alice发送一条消息。Bob用他的私钥对明文消息进行签名，然后，他用Alice的公钥对已签名的消息进行加密。即先签名，后加密。
    // Bob wants to send Alice a message. He signs the plaintext message with his secret key. He
    // then encrypts the signed message with Alice's public key.
    let msg = b"let's get pizza";
    // Bob用他的私钥对消息进行签名
    let signed_msg = bob.create_signed_msg(msg);
    // 对已经签名的消息进行序列化
    let serialized = serialize(&signed_msg).expect("Failed to serialize `SignedMsg`");
    // 用Alice的公钥对序列化后的消息进行加密
    let ciphertext = alice.pk.encrypt(&serialized);

    // Alice收到了Bob的加密消息。她用她的私钥解密了这条消息。然后，她使用Bob的公钥验证消息明文的签名是否合法，即是否的确是Bob的签名。
    // Alice receives Bob's encrypted message. She decrypts the message using her secret key. She
    // then verifies that the signature of the plaintext is valid using Bob's public key.
    // Alice用她的私钥对消息进行解密
    let decrypted = alice.sk.decrypt(&ciphertext).expect("Invalid ciphertext");
    // 对解密后的消息进行反序列化，生成SignedMsg对象
    let deserialized: SignedMsg =
        deserialize(&decrypted).expect("Failed to deserialize bytes to `SignedMsg`");
    // 用Bob的公钥对消息签名和消息进行合法性验证
    assert!(bob.pk.verify(&deserialized.sig, &deserialized.msg));

    // We assert that the message that Alice received is the same message that Bob sent.
    // Alice收到的消息应该和Bob发送的消息一模一样
    assert_eq!(msg, &deserialized.msg[..]);
}
