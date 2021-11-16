use std::collections::BTreeMap;

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKeySet,
    SecretKeyShare,
};

// In this example scenario, the `SecretSociety` is the "trusted key dealer". The trusted dealer is
// responsible for key generation. The society creates a master public-key, which anyone can use to
// encrypt a message to the society's members; the society is also responsible for giving each
// actor their respective share of the secret-key.
// 在这个示例场景中，“SecretSociety”是“trusted key dealer”。trusted dealer负责生成密钥。该society（协会）创建了一个主公钥，
// 任何人都可以使用主公钥来加密发给该society（协会）成员的消息;该协会还负责给每个参与者分配各自的私钥份额。
struct SecretSociety {
    // 各参与者的集合，即协会成员的集合
    actors: Vec<Actor>,
    pk_set: PublicKeySet,
}

impl SecretSociety {
    // Creates a new `SecretSociety`.创建一个新的SecretSociety
    //
    // # Arguments 参数
    //
    // `n_actors` - the number of actors (members) in the secret society. 协会成员数量
    // `threshold` - the number of actors that must collaborate to successfully 
    // decrypt a message must exceed this `threshold`.能够正常解密的协会成员阈值，即至少要多少个协会成员合作才能完成解密，必须要比阈值大1
    fn new(n_actors: usize, threshold: usize) -> Self {
        // thread_rng模式产生随机数
        let mut rng = rand::thread_rng();
        // 根据协会成员阈值数量生成私钥set
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        // 根据私钥set生成公钥set
        let pk_set = sk_set.public_keys();

        // 把私钥set和公钥set的份额分配给每一个协会成员，并生成协会成员集合
        let actors = (0..n_actors)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id); // 私钥份额
                let pk_share = pk_set.public_key_share(id); // 公钥份额
                Actor::new(id, sk_share, pk_share) // 根据id、私钥份额、公钥份额初始化一个协会成员
            })
            .collect();

        // 生成SecretSociety，包含协会成员（拥有各自的公私钥）和公钥set
        SecretSociety { actors, pk_set }
    }

    // The secret society publishes its public-key to a publicly accessible key server.
    // secret society将其公钥发布到一个可公开访问的密钥服务器上。这个地方仅仅是模拟，方法的作用就是返回主公钥。
    fn publish_public_key(&self) -> PublicKey {
        // 通过公钥set获取主公钥
        self.pk_set.public_key()
    }

    fn get_actor(&mut self, id: usize) -> &mut Actor {
        self.actors
            .get_mut(id)
            .expect("No `Actor` exists with that ID")
    }

    // Starts a new meeting of the secret society. Each time the set of actors receive an encrypted
    // message, at least 2 of them (i.e. 1 more than the threshold) must work together to decrypt
    // the ciphertext.
    // 开始secret society的一次新会议。每次一组参与者收到一条加密消息时，至少有2个参与者(即比阈值多1个参与者)必须合作解密密文。
    // 此处仅仅是初始化构造一个DecryptionMeeting，还没有真正地执行解密过程。
    fn start_decryption_meeting(&self) -> DecryptionMeeting {
        DecryptionMeeting {
            pk_set: self.pk_set.clone(),
            ciphertext: None,
            dec_shares: BTreeMap::new(),
        }
    }
}

// A member of the secret society.
// secret society的一个成员
#[derive(Clone, Debug)]
struct Actor {
    id: usize,
    sk_share: SecretKeyShare,
    pk_share: PublicKeyShare,
    msg_inbox: Option<Ciphertext>,
}

impl Actor {
    fn new(id: usize, sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        Actor {
            id, // id
            sk_share, // 私钥份额
            pk_share, // 公钥份额
            msg_inbox: None, // 收到的消息密文
        }
    }
}

// Sends an encrypted message to an `Actor`.
// 发送一条加密消息给一个参与者，即Actor。
// 此处的实现就是把消息密文赋给Actor对象的msg_inbox字段，这样每个Actor就获取了消息的密文。
fn send_msg(actor: &mut Actor, enc_msg: Ciphertext) {
    actor.msg_inbox = Some(enc_msg);
}

// A meeting of the secret society. At this meeting, actors collaborate to decrypt a shared
// ciphertext.
// secret society的一次会议。在这次会议上，参与者合作解密共享的密文。
struct DecryptionMeeting {
    pk_set: PublicKeySet, // 公钥set
    ciphertext: Option<Ciphertext>, // 密文，可选
    dec_shares: BTreeMap<usize, DecryptionShare>, // 所有参与者解密份额的集合
}

impl DecryptionMeeting {
    // An actor contributes their decryption share to the decryption process.
    // 一个参与者将其解密份额贡献给解密过程。
    fn accept_decryption_share(&mut self, actor: &mut Actor) {
        let ciphertext = actor.msg_inbox.take().unwrap();

        // Check that the actor's ciphertext is the same ciphertext decrypted at the meeting.
        // The first actor to arrive at the decryption meeting sets the meeting's ciphertext.
        // 检查参与者的密文是否与在会议上解密的密文相同。第一个到达解密会议的参与者设置会议的密文。
        if let Some(ref meeting_ciphertext) = self.ciphertext { //这个分支说明不是第一个参与者，因为self.ciphertext已经被第一个参与者设置了
            // 检查参与者的密文和会议的密文是否一致，如果不一致，就直接返回
            if ciphertext != *meeting_ciphertext {
                return;
            }
        } else {
            // 这个分支表示第一个参与者到达会议，设置会议的密文
            self.ciphertext = Some(ciphertext.clone());
        }

        // 用参与者的私钥份额对密文进行解密，得到解密份额
        let dec_share = actor.sk_share.decrypt_share(&ciphertext).unwrap();
        // 用参与者的公钥份额验证其解密份额是否合法，即解密是否正确
        let dec_share_is_valid = actor
            .pk_share
            .verify_decryption_share(&dec_share, &ciphertext);
        assert!(dec_share_is_valid);
        // 把参与者的解密份额添加到会议的解密份额集合里
        self.dec_shares.insert(actor.id, dec_share);
    }

    // Tries to decrypt the shared ciphertext using the decryption shares.
    // 尝试使用解密份额集合解密共享密文。
    fn decrypt_message(&self) -> Result<Vec<u8>, ()> {
        let ciphertext = self.ciphertext.clone().unwrap();
        // 用会议已有的解密份额解密密文，如果解密份额没有达到阈值的个数，那么解密失败
        self.pk_set
            .decrypt(&self.dec_shares, &ciphertext)
            .map_err(|_| ())
    }
}

fn main() {
    // Create a `SecretSociety` with 3 actors. Any message encrypted with the society's public-key
    // will require 2 or more actors working together to decrypt (i.e. the decryption threshold is
    // 1). Once the secret society has created its master keys, it "deals" a secret-key share and
    // public-key share to each of its actors. The secret society then publishes its public key
    // to a publicly accessible key-server.
    // 用3个成员创建一个“SecretSociety”。任何用协会的公钥加密的消息都需要2个或更多的参与者共同解密(即解密阈值为1，要解密必须大于1)。
    // 一旦SecretSociety创建了它的主密钥，它就会向每个参与者分配私钥份额和公钥份额。然后，SecretSociety将其公钥发布到一个可公开访问的密钥服务器。
    let mut society = SecretSociety::new(3, 1);
    // 获取主公钥
    let pk = society.publish_public_key();

    // Create a named alias for each actor in the secret society.
    // 为secret society的每个成员都创建一个别名。alice是0，bob是1，clara是2.
    let alice = society.get_actor(0).id;
    let bob = society.get_actor(1).id;
    let clara = society.get_actor(2).id;

    // I, the society's benevolent hacker, want to send an important message to each of my
    // comrades. I encrypt my message with the society's public-key. I then send the ciphertext to
    // each of the society's actors.
    // 我，这个协会仁慈的黑客，想给我的每一位同志发送一条重要消息。我用协会的主公钥加密我要发送的消息。然后我将密文发送给协会的每个参与者。
    let msg = b"let's get pizza";
    // 用主公钥加密消息，得到密文
    let ciphertext = pk.encrypt(msg);
    // 发送一条加密消息给一个参与者，即Actor。这里总共有3个参与者。
    // 此处的实现就是把消息密文赋给Actor对象的msg_inbox字段，这样每个Actor就获取了消息的密文。    
    send_msg(society.get_actor(alice), ciphertext.clone());
    send_msg(society.get_actor(bob), ciphertext.clone());
    send_msg(society.get_actor(clara), ciphertext);

    // We start a meeting of the secret society. At the meeting, each actor contributes their
    // share of the decryption process to decrypt the ciphertext that they each received.
    // 我们开始secret society的会议。在会议上，每个参与者贡献他们的解密过程的份额，以解密他们各自收到的密文。
    // 此处仅仅是初始化构造一个DecryptionMeeting，还没有真正地执行解密过程。
    let mut meeting = society.start_decryption_meeting();

    // Alice is the first actor to arrive at the meeting, she provides her decryption share. One
    // actor alone cannot decrypt the ciphertext, decryption fails.
    // Alice是第一个到达会议的参与者，她提供了她的解密份额。单独一个参与者无法解密密文，解密失败。
    meeting.accept_decryption_share(society.get_actor(alice));
    // 断言解密失败
    assert!(meeting.decrypt_message().is_err());

    // Bob joins the meeting and provides his decryption share. Alice and Bob are now collaborating
    // to decrypt the ciphertext, they succeed because the society requires two or more actors for
    // decryption.
    // Bob加入会议并提供他的解密份额。Alice和Bob正在合作解密密文，他们成功了，因为协会需要两个或更多的参与者来解密，现在已经达到了两个参与者。
    meeting.accept_decryption_share(society.get_actor(bob));
    let mut res = meeting.decrypt_message();
    // 断言解密成功
    assert!(res.is_ok());
    // 断言解密后的明文和原本的消息是相同的
    assert_eq!(msg, res.unwrap().as_slice());

    // Clara joins the meeting and provides her decryption share. We already are able to decrypt
    // the ciphertext with 2 actors, but let's show that we can with 3 actors as well.
    // Clara加入了会议并提供了她的解密份额。我们已经能够用两个参与者解密密文，但让我们证明我们也可以用三个参与者来解密。
    meeting.accept_decryption_share(society.get_actor(clara));
    res = meeting.decrypt_message();
    // 断言解密成功
    assert!(res.is_ok());
    // 断言解密后的明文和原本的消息是相同的
    assert_eq!(msg, res.unwrap().as_slice());
}
