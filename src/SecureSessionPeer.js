const nacl = require('libsodium-wrappers');
const Encryptor = require('./Encryptor');
const Decryptor = require('./Decryptor');

async function SecuroSessionPeerFactory(peer = null) {
    await nacl.ready;

    let { publicKey, privateKey } = nacl.crypto_box_keypair();

    let secureSessionPeer = {
        peer: null,
        encryptor: null,
        decryptor: null,
        Message: "",
        client: true,
        publicKey,
        setUp: async function(connectTo, client = true) {
            this.peer = connectTo;
            this.client = client;
            let { sharedRx, sharedTx } = (client ? nacl.crypto_kx_client_session_keys : nacl.crypto_kx_server_session_keys)(publicKey, privateKey, connectTo.publicKey);
            this.encryptor = await Encryptor(sharedTx);
            this.decryptor = await Decryptor(sharedRx);
        },
        encrypt: function(msg) {
            let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);
            return {
                nonce,
                ciphertext: this.encryptor.encrypt(msg, nonce)
            };
        },
        decrypt: function(msg, nonce) {
            return this.decryptor.decrypt(msg, nonce);
        },
        send: function(msg) {
            this.peer.onReceive(this.encrypt(msg));
        },
        onReceive: function(msg) {
            this.Message = this.decrypt(msg.ciphertext, msg.nonce);
        },
        receive: function() {
            return this.Message;
        }
    }

    if (peer) {
        await secureSessionPeer.setUp(peer, true);
        await peer.setUp(secureSessionPeer, false);
    }

    return Object.defineProperties(secureSessionPeer, {
        publicKey: { writable: false },
        privateKey: { writable: false }
    });
}

module.exports = SecuroSessionPeerFactory;