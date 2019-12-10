type message = Base_bigstring.t
type secretKeySet
type publicKeySet
type secretKeyShare
type publicKeyShare
type decryptionShare
type publicKey
type signature
type ciphertext

external public_key_verify : publicKey -> signature -> message -> bool =
  "public_key_verify"
external public_key_encrypt : publicKey -> message -> ciphertext =
  "public_key_encrypt"
external public_key_share_verify_decryption_share :
  publicKeyShare -> decryptionShare -> ciphertext -> bool =
  "public_key_share_verify_decryption_share"
external public_key_set_decrypt :
  publicKeySet -> (int * decryptionShare) list -> ciphertext -> message option * string =
  "public_key_set_decrypt"
external secret_key_share_decrypt_share_no_verify :
  secretKeyShare -> ciphertext -> decryptionShare =
  "secret_key_share_decrypt_share_no_verify"
external secret_key_set_random : int -> secretKeySet option * string =
  "secret_key_set_random"
external secret_key_set_public_keys : secretKeySet -> publicKeySet =
  "secret_key_set_public_keys"
external secret_key_set_secret_key_share : secretKeySet -> int -> secretKeyShare =
  "secret_key_set_secret_key_share"
external public_key_set_public_key_share : publicKeySet -> int -> publicKeyShare =
  "public_key_set_public_key_share"
external public_key_set_public_key : publicKeySet -> publicKey =
  "public_key_set_public_key"
external secret_key_set_drop : secretKeySet -> unit =
  "secret_key_set_drop"
external public_key_set_drop : publicKeySet -> unit =
  "public_key_set_drop"
external secret_key_share_drop : secretKeyShare -> unit =
  "secret_key_share_drop"
external public_key_share_drop : publicKeyShare -> unit =
  "public_key_share_drop"
external decryption_share_drop : decryptionShare -> unit =
  "decryption_share_drop"
external public_key_drop : publicKey -> unit =
  "public_key_drop"
external ciphertext_drop : ciphertext -> unit =
  "ciphertext_drop"
