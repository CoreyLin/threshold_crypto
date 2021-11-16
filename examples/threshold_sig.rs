use std::collections::BTreeMap;

use threshold_crypto::{
    PublicKeySet, PublicKeyShare, SecretKeySet, SecretKeyShare, Signature, SignatureShare,
};

type UserId = usize;
type NodeId = usize;
type Msg = String;

// The database schema that validator nodes use to store messages they receive from users.
// Messages are first indexed numerically by user ID then alphabetically by message. Each message
// is mapped to its list of validator signatures.
type MsgDatabase = BTreeMap<UserId, BTreeMap<Msg, Vec<NodeSignature>>>;

// An append-only list of chat message "blocks". Each block contains the user ID for the user who
// broadcast the message to the network, the message text, and the combined signature of the
// message. A block can be appended to this list each time our chat protocol runs its consensus
// algorithm.
// 聊天消息“块”的添加列表。每个块包含向网络广播消息的用户的用户ID、消息文本和消息的组合签名。每次我们的聊天协议运行它的共识算法时，一个块可以被添加到这个列表中。
type ChatLog = Vec<(UserId, Msg, Signature)>;

// Represents a network of nodes running a distributed chat protocol. Clients, or "users", of our
// network, create a string that they want to append to the network's `chat_log`, they broadcast
// this message to the network, and each node that receives the message signs it with their
// signing-key. When the network runs a round of consensus, each node contributes its set of signed
// messages. The first message to receive `threshold + 1` signatures from validator nodes
// gets added to the `chat_log`.
// 表示运行分布式聊天协议的节点网络。网络的客户端，或“用户”，创建一个他们想要添加到网络' chat_log '的字符串，他们将此消息广播到网络，
// 每个接收到消息的节点用他们的签名私钥对其签名。当网络运行一轮协商时，每个节点贡献其签名的消息集。从验证者节点接收到' threshold + 1 '个签名的第一条消息被添加到' chat_log '中。
struct ChatNetwork {
    // 公钥set
    pk_set: PublicKeySet,
    // 网络中节点的集合
    nodes: Vec<Node>,
    // 聊天日志
    chat_log: ChatLog,
    // user的id标志位，从0开始，每注册一个新user，这个值递增1
    n_users: usize,
}

impl ChatNetwork {
    // Creates a new network of nodes running our distributed chat protocol. 创建一个运行我们的分布式聊天协议的新节点网络。
    //
    // # Arguments 参数
    //
    // `n_nodes` - the number of validator/signing nodes in the network. 网络中验证者/签名节点的数量。
    // `threshold` - a message must have `threshold + 1` validator signatures
    // before it can be added to the `chat_log`. 消息必须有“threshold + 1”个验证者的签名，才能被添加到“chat_log”中。
    fn new(n_nodes: usize, threshold: usize) -> Self {
        // thread_rng模式产生随机数
        let mut rng = rand::thread_rng();
        // 根据成员阈值数量生成私钥set
        let sk_set = SecretKeySet::random(threshold, &mut rng);
        // 根据私钥set生成公钥set
        let pk_set = sk_set.public_keys();

        // 把私钥set和公钥set的份额分配给每一个成员/节点，并生成成员/节点集合
        let nodes = (0..n_nodes)
            .map(|id| {
                let sk_share = sk_set.secret_key_share(id); // 私钥份额
                let pk_share = pk_set.public_key_share(id); // 公钥份额
                Node::new(id, sk_share, pk_share) // 根据id、私钥份额、公钥份额初始化一个成员/节点
            })
            .collect();

        ChatNetwork {
            pk_set,
            nodes,
            chat_log: vec![],
            n_users: 0,
        }
    }

    // 创建一个新user
    fn create_user(&mut self) -> User {
        let user_id = self.n_users;
        let user = User::new(user_id);
        self.n_users += 1;
        user
    }

    fn get_node(&self, id: NodeId) -> &Node {
        self.nodes.get(id).expect("No `Node` exists with that ID")
    }

    fn get_mut_node(&mut self, id: NodeId) -> &mut Node {
        self.nodes
            .get_mut(id)
            .expect("No `Node` exists with that ID")
    }

    // Run a single round of the consensus algorithm. If consensus produced a new block, append
    // that block the chat log.
    fn step(&mut self) {
        if let Some(block) = self.run_consensus() {
            self.chat_log.push(block);
        }
    }

    // Our chat protocol's consensus algorithm. This algorithm produces a new block to append to the chat
    // log. Our consensus uses threshold-signing to verify a message has received enough
    // signature shares (i.e. has been signed by `threshold + 1` nodes).
    fn run_consensus(&self) -> Option<(UserId, Msg, Signature)> {
        // Create a new `MsgDatabase` of every message that has been signed by a validator node.
        let all_pending: MsgDatabase =
            self.nodes
                .iter()
                .fold(BTreeMap::new(), |mut all_pending, node| {
                    for (user_id, signed_msgs) in &node.pending {
                        let user_msgs = all_pending.entry(*user_id).or_insert_with(BTreeMap::new);
                        for (msg, sigs) in signed_msgs.iter() {
                            let sigs = sigs.iter().cloned();
                            user_msgs
                                .entry(msg.to_string())
                                .or_insert_with(Vec::new)
                                .extend(sigs);
                        }
                    }
                    all_pending
                });

        // Iterate over the `MsgDatabase` numerically by user ID, then iterate over each user's
        // messages alphabetically. Try to combine the validator signatures. The first message to
        // receive `threshold + 1` node signatures produces a valid "combined" signature
        // and is added to the chat log.
        for (user_id, signed_msgs) in &all_pending {
            for (msg, sigs) in signed_msgs.iter() {
                let sigs = sigs.iter().filter_map(|node_sig| {
                    let node_sig_is_valid = self
                        .get_node(node_sig.node_id)
                        .pk_share
                        .verify(&node_sig.sig, msg.as_bytes());

                    if node_sig_is_valid {
                        Some((node_sig.node_id, &node_sig.sig))
                    } else {
                        None
                    }
                });

                if let Ok(sig) = self.pk_set.combine_signatures(sigs) {
                    return Some((*user_id, msg.clone(), sig));
                }
            }
        }

        None
    }
}

// A network node running our chat protocol.
// 运行聊天协议的网络节点。
struct Node {
    // 节点id
    id: NodeId,
    // 私钥份额
    sk_share: SecretKeyShare,
    // 公钥份额
    pk_share: PublicKeyShare,
    pending: MsgDatabase,
}

impl Node {
    fn new(id: NodeId, sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        Node {
            id,
            sk_share,
            pk_share,
            pending: BTreeMap::new(),
        }
    }

    // Receives a message from a user, signs the message with the node's signing-key share,
    // then adds the signed message to its database of `pending` messages.
    fn recv(&mut self, user_id: UserId, msg: Msg) {
        let sig = NodeSignature {
            node_id: self.id,
            sig: self.sk_share.sign(msg.as_bytes()),
        };
        self.pending
            .entry(user_id)
            .or_insert_with(BTreeMap::new)
            .entry(msg)
            .or_insert_with(Vec::new)
            .push(sig);
    }
}

#[derive(Clone, Debug)]
struct NodeSignature {
    node_id: NodeId,
    sig: SignatureShare,
}

// A client of our chat protocol.
// 聊天协议的客户端。只有一个id属性。
struct User {
    id: UserId,
}

impl User {
    // 创建一个新user
    fn new(id: UserId) -> Self {
        User { id }
    }

    // Sends a message to one of the network's validator nodes.
    fn send(&self, node: &mut Node, msg: Msg) {
        node.recv(self.id, msg);
    }
}

fn main() {
    // Creates a new network of 3 nodes running our chat protocol. The protocol has a
    // signing-threshold of 1. This means each message requires 2 validator signatures before it can be
    // added to the chat log.
    // 创建一个由3个节点组成的新网络，运行我们的聊天协议。协议的签名阈值为1。这意味着每条消息在添加到聊天日志之前都需要2个验证者的签名。
    let mut network = ChatNetwork::new(3, 1);
    // 获取3个节点中的2个节点的id
    let node1 = network.get_node(0).id;
    let node2 = network.get_node(1).id;

    // Register a new user, Alice, with the network. Alice wants to add a message to the chat log.
    // 向网络注册一个新用户Alice。Alice想在聊天日志中添加一条消息。
    let alice = network.create_user();
    let alice_greeting = "hey, this is alice".to_string();

    // Alice sends her message to a validator. The validator signs the message. Before Alice can
    // send her message to a second validator, the network runs a round of consensus. Because
    // Alice's message has only one validator signature, it is not added to the chat log.
    // Alice将消息发送给一个验证者/节点。验证者对消息进行签名。在Alice将消息发送给第二个验证者之前，网络会进行一轮协商。因为Alice的消息只有一个验证者签名，所以它不会被添加到聊天日志中。
    alice.send(network.get_mut_node(node1), alice_greeting.clone());
    network.step();
    assert!(network.chat_log.is_empty());

    // Alice sends her message to a second validator. The validator signs the message. Alice's
    // message now has two signatures (which is `threshold + 1` signatures). The network runs a
    // round of consensus, which successfully creates a combined-signature for Alice's message.
    // Alice's message is appended to the chat log.
    alice.send(network.get_mut_node(node2), alice_greeting);
    network.step();
    assert_eq!(network.chat_log.len(), 1);
}
