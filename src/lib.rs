//! Ocaml interface to the Rust library `threshold_crypto`.

use ocaml::{caml, tuple, Array1, List, Str, ToValue, Tuple, Value};
use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKeySet,
    SecretKeyShare, Signature,
};

// Interface to `PublicKey::verify`.
caml!(public_key_verify(pub_key, sig, msg) {
    let pub_key: &PublicKey = &*pub_key.ptr_val();
    let sig: &Signature = &*sig.ptr_val();
    let msg: Array1<u8> = Array1::from(msg);
    Value::bool(pub_key.verify(&sig, msg.data()))
});

// Interface to `PublicKey::encrypt`.
//
// Allocates a ciphertext object on the heap.
caml!(public_key_encrypt(pub_key, msg) {
    let pub_key: &PublicKey = &*pub_key.ptr_val();
    let msg: Array1<u8> = Array1::from(msg);
    let ciphertext: Ciphertext = pub_key.encrypt(msg.data());
    let boxed_ciphertext = Box::new(ciphertext);
    Value::ptr(Box::into_raw(boxed_ciphertext))
});

// TODO: Interface to `PublicKeyShare::verify`.
// ...

// Interface to `PublicKeyShare::verify_decryption_share`.
caml!(public_key_share_verify_decryption_share(pk_share, dec_share, ct) {
    let pk_share: &PublicKeyShare = &*pk_share.ptr_val();
    let dec_share: &DecryptionShare = &*dec_share.ptr_val();
    let ct: &Ciphertext = &*ct.ptr_val();
    Value::bool(pk_share.verify_decryption_share(&dec_share, &ct))
});

// Interface to `PublicKeySet::decrypt`.
caml!(public_key_set_decrypt(pk_set, dec_shares, ct) {
    let pk_set: &PublicKeySet = &*pk_set.ptr_val();
    // Iterate through the decryption shares. The decryption shares are indexed with a `u64` and
    // thus formed pairs are stored one after another in a list.
    let list: List = List::from(dec_shares);
    let vec: Vec<Value> = list.to_vec();
    let mut dec_shares = Vec::new();
    for v in vec {
        let tuple = Tuple::from(v);
        let i = tuple.get(0).unwrap().usize_val();
        let dec_share = tuple.get(1).unwrap();
        let dec_share: &DecryptionShare = &*dec_share.ptr_val();
        dec_shares.push((i, dec_share));
    }
    let ct: &Ciphertext = &*ct.ptr_val();
    let msg = pk_set.decrypt(dec_shares, ct);
    if let Err(e) = msg {
        return tuple!(
            Value::none(),
            Value::from(
                Str::from(format!("decrypt error: {}", e).as_str())
            )
        ).into();
    }
    let mut msg = msg.unwrap();
    tuple!(
        Value::some(Value::from(Array1::from(msg.as_slice()))),
        Value::from(Str::from(""))
    ).into()
});

// Interface to `SecretKeyShare::decrypt_share_no_verify`.
//
// Allocates a `DecryptionShare` object on the heap.
caml!(secret_key_share_decrypt_share_no_verify(sk_share, ct) {
    let sk_share: &SecretKeyShare = &*sk_share.ptr_val();
    let ct: &Ciphertext = &*ct.ptr_val();
    let dec_share = sk_share.decrypt_share_no_verify(ct);
    let boxed_dec_share = Box::new(dec_share);
    Value::ptr(Box::into_raw(boxed_dec_share))
});

// Interface to `SecretKeySet::random`.
//
// Constructs and returns a `SecretKeySet` object along with an error message if construction
// failed.
caml!(secret_key_set_random(threshold) {
    let threshold = threshold.usize_val();
    let mut rng = rand::thread_rng();
    let sk_set = SecretKeySet::try_random(threshold, &mut rng);
    if let Err(e) = sk_set {
        return tuple!(
            Value::none(),
            Value::from(Str::from(format!("SecretKeySet error: {}", e).as_str()))
        ).into();
    }
    let sk_set = sk_set.unwrap();
    let boxed_sk_set = Box::new(sk_set);
    tuple!(
        Value::some(Value::ptr(Box::into_raw(boxed_sk_set))),
        Value::from(Str::from(""))
    ).into()
});

// Interface to `SecretKeySet::public_keys`.
//
// Returns the `PublicKeySet` object.
caml!(secret_key_set_public_keys(sk_set) {
    let sk_set: &SecretKeySet = &*sk_set.ptr_val();
    let pk_set = sk_set.public_keys();
    let boxed_pk_set = Box::new(pk_set);
    Value::ptr(Box::into_raw(boxed_pk_set))
});

// Interface to `SecretKeySet::secret_key_share`.
//
// Returns the `SecretKeyShare` object.
caml!(secret_key_set_secret_key_share(sk_set, i) {
    let sk_set: &SecretKeySet = &*sk_set.ptr_val();
    let i = i.usize_val();
    let sk_share = sk_set.secret_key_share(i);
    let boxed_sk_share = Box::new(sk_share);
    Value::ptr(Box::into_raw(boxed_sk_share))
});

// Interface to `PublicKeySet::public_key_share`.
//
// Returns the `PublicKeyShare` object.
caml!(public_key_set_public_key_share(pk_set, i) {
    let pk_set: &PublicKeySet = &*pk_set.ptr_val();
    let i = i.usize_val();
    let pk_share = pk_set.public_key_share(i);
    let boxed_pk_share = Box::new(pk_share);
    Value::ptr(Box::into_raw(boxed_pk_share))
});

// Interface to `PublicKeySet::public_key`.
//
// Returns the `PublicKey` object.
caml!(public_key_set_public_key(pk_set) {
    let pk_set: &PublicKeySet = &*pk_set.ptr_val();
    let pk = pk_set.public_key();
    let boxed_pk = Box::new(pk);
    Value::ptr(Box::into_raw(boxed_pk))
});

/// Ocaml garbage collector callback function for heap-allocated objects.
fn drop_boxed_value<T>(v: Value) -> Value {
    let obj: *mut T = v.ptr_val::<T>() as *mut T;
    if obj.is_null() {
        panic!("Cannot free a null pointer!");
    }
    let boxed: Box<T> = unsafe { Box::from_raw(obj) };
    drop(boxed);
    Value::unit()
}

// Destructor for a `SecretKeySet` structure.
caml!(secret_key_set_drop(sk_set) {
    drop_boxed_value::<SecretKeySet>(sk_set)
});

// Destructor for a `PublicKeySet` structure.
caml!(public_key_set_drop(pk_set) {
    drop_boxed_value::<PublicKeySet>(pk_set)
});

// Destructor for a `SecretKeyShare` structure.
caml!(secret_key_share_drop(sk_share) {
    drop_boxed_value::<SecretKeyShare>(sk_share)
});

// Destructor for a `PublicKeyShare` structure.
caml!(public_key_share_drop(pk_share) {
    drop_boxed_value::<PublicKeyShare>(pk_share)
});

// Destructor for a `DecryptionShare` structure.
caml!(decryption_share_drop(dec_share) {
    drop_boxed_value::<DecryptionShare>(dec_share)
});

// Destructor for a `PublicKey` structure.
caml!(public_key_drop(pk) {
    drop_boxed_value::<PublicKey>(pk)
});

// Destructor for a `Ciphertext` structure.
caml!(ciphertext_drop(ct) {
    drop_boxed_value::<Ciphertext>(ct)
});
