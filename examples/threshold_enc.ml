open Threshold_crypto

(*
Threshold encryption and decryption example

Three actors - Alice, Bob and Carol - collaborate to decrypt a message encrypted to a threshold of
secret key shares.
 *)

let _ = print_endline " *** Threshold encryption example ***";
(* Create a set of secret key shares where at least 2 shares are required to decrypt a ciphertext. *)
let (maybe_sk_set, error) = secret_key_set_random(1) in
match maybe_sk_set with
  None ->
    Printf.printf "Could not create a secret key set: %s" error
| Some sk_set ->
    print_endline "Created a secret key set";
    (* Compute the public key set for distribution to all actors. *)
    let pk_set = secret_key_set_public_keys sk_set in
    (* Create public and secret key shares for the three actors below. Every actor knows their
       secret key share which is not known to other actors and which is used to create decryption
       shares. On the other hand, every actor knows their own as well as every other actor's public
       key share, which they use to verify decryption shares. *)
    let sk_share_alice = secret_key_set_secret_key_share sk_set 0 in
    let pk_share_alice = public_key_set_public_key_share pk_set 0 in
    let sk_share_bob   = secret_key_set_secret_key_share sk_set 1 in
    let pk_share_bob   = public_key_set_public_key_share pk_set 1 in
    let sk_share_carol = secret_key_set_secret_key_share sk_set 2 in
    let pk_share_carol = public_key_set_public_key_share pk_set 2 in
    (* The public key is known to every actor as part of the public key set. *)
    let pk = public_key_set_public_key pk_set in
    (* Encrypt a test message. *)
    let msg = Base_bigstring.of_string "Hello, threshold crypto!" in
    (* The ciphertext is then distributed to all actors. *)
    let ciphertext = public_key_encrypt pk msg in
    (* Start decryption of the message. One actor is not enough to decrypt it. *)
    let dec_share_alice = secret_key_share_decrypt_share_no_verify sk_share_alice ciphertext in
    (* Check the validity of the decryption share. Every actor can do this when they receive it. *)
    assert (public_key_share_verify_decryption_share pk_share_alice dec_share_alice ciphertext);
    let dec_shares = [(0, dec_share_alice)] in
    let (maybe_msg, dec_error) = public_key_set_decrypt pk_set dec_shares ciphertext in
    assert (Option.is_none maybe_msg);
    Printf.printf "Alice cannot decrypt the message on her own. (%s)\n" dec_error;
    assert (dec_error != "");
    let dec_share_bob = secret_key_share_decrypt_share_no_verify sk_share_bob ciphertext in
    (* Check the validity of the decryption share. Every actor can do this when they receive it. *)
    assert (public_key_share_verify_decryption_share pk_share_bob dec_share_bob ciphertext);
    (* Two valid decryption shares are enough to decrypt the ciphertext. *)
    let dec_shares = (1, dec_share_bob) :: dec_shares in
    let (maybe_msg, dec_error) = public_key_set_decrypt pk_set dec_shares ciphertext in
    assert (Option.is_some maybe_msg);
    Printf.printf "Alice and Bob decrypted the message: %s\n"
      (Base_bigstring.to_string (Option.get maybe_msg));
    assert (dec_error = "");
    let dec_share_carol = secret_key_share_decrypt_share_no_verify sk_share_carol ciphertext in
    (* Check the validity of the decryption share. Every actor can do this when they receive it. *)
    assert (public_key_share_verify_decryption_share pk_share_carol dec_share_carol ciphertext);
    (* Three decryption shares can decrypt the ciphertext because already two can. *)
    let dec_shares = (2, dec_share_carol) :: dec_shares in
    let (maybe_msg, dec_error) = public_key_set_decrypt pk_set dec_shares ciphertext in
    assert (Option.is_some maybe_msg);
    Printf.printf "Alice, Bob and Carol decrypted the message: %s\n"
      (Base_bigstring.to_string (Option.get maybe_msg));
    assert (dec_error = "");
    (* All values of abstract, opaque pointer types need a memory management workaround. In order to
       free heap-allocated objects in Rust that are hidden behind abstract Ocaml types (opaque
       pointers), we allocate references on the heap to those opaque pointer values and then
       register a deallocation callback for each heap-allocated object. Later, when the garbage
       collector finalises the references, it calls the callbacks that deallocate Rust objects.

       TODO: Investigate the possibility of attaching finalisers to `ocaml.rs` values. *)
    let mm_sk_set = ref sk_set in
    Gc.finalise (fun r -> secret_key_set_drop !r; print_endline "Finalised sk_set") mm_sk_set;
    let mm_pk_set = ref pk_set in
    Gc.finalise (fun r -> public_key_set_drop !r; print_endline "Finalised pk_set") mm_pk_set;
    let mm_pk = ref pk in
    Gc.finalise (fun r -> public_key_drop !r; print_endline "Finalised pk") mm_pk;

    (* FIXME: Add finalisers for the rest of the objects in the same way. *)

    (* Force deallocation of heap-allocated Rust objects. TODO: Hopefully?.. Needs testing. *)
    Gc.major ()
