import time
from custom_aes import AES

def benchmark_aes():
    # Prepare the input
    plaintext = b"master ssi 2024!"  # 16 bytes
    key = bytes.fromhex("30313233343536373839616263646566")  # "0123456789abcdef" in hex

    # Create AES instance
    aes = AES(key)

    # Number of iterations for the benchmark
    iterations = 32

    # Benchmark encryption
    start_time = time.time()
    for _ in range(iterations):
        encrypted = aes.encrypt(plaintext)
    end_time = time.time()
    encryption_time = end_time - start_time

    # Benchmark decryption
    start_time = time.time()
    for _ in range(iterations):
        decrypted = aes.decrypt(encrypted)
    end_time = time.time()
    decryption_time = end_time - start_time

    # Print results
    print(f"AES Benchmark Results (iterations: {iterations}):")
    print(f"Encryption time: {encryption_time:.4f} seconds")
    print(f"Decryption time: {decryption_time:.4f} seconds")
    print(f"Encryption speed: {iterations / encryption_time:.2f} operations/second")
    print(f"Decryption speed: {iterations / decryption_time:.2f} operations/second")

    # Verify correctness
    print("\nVerification:")
    print(f"Original text: {plaintext}")
    print(f"Encrypted (hex): {bytes(encrypted).hex()}")
    print(f"Decrypted: {bytes(decrypted)}")
    print(f"Correct decryption: {bytes(decrypted) == plaintext}")

if __name__ == "__main__":
    benchmark_aes()
