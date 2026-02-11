from crypto_core.ecc import generate_ecc_keys
from crypto_core.key_derivation import derive_shared_secret, derive_aes_key
from crypto_core.encryption import encrypt_data, decrypt_data
from crypto_core.signature import sign_data, verify_signature

# Step 1: Generate keys
alice_private, alice_public = generate_ecc_keys()
bob_private, bob_public = generate_ecc_keys()

# Step 2: ECDH shared secret
alice_shared = derive_shared_secret(alice_private, bob_public)
bob_shared = derive_shared_secret(bob_private, alice_public)

# Step 3: Derive AES key
alice_aes = derive_aes_key(alice_shared)
bob_aes = derive_aes_key(bob_shared)

# Step 4: Encrypt data
message = b"Confidential File Data"
nonce, ciphertext = encrypt_data(message, alice_aes)

# Step 5: Sign data
signature = sign_data(alice_private, ciphertext)

# Step 6: Decrypt
decrypted = decrypt_data(nonce, ciphertext, bob_aes)

# Step 7: Verify signature
verify_signature(alice_public, signature, ciphertext)

print("Decrypted:", decrypted.decode())
print("Signature Verified Successfully!")