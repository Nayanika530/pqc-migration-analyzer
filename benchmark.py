# benchmark.py
# Measures real key generation and operation speed for classical vs PQC algorithms

import json
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import oqs


def benchmark_rsa(key_size: int, rounds: int = 5) -> dict:
    """Time RSA key generation, averaged over several rounds."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        RSA.generate(key_size)
        end = time.perf_counter()
        times.append(end - start)

    avg_time_ms = (sum(times) / len(times)) * 1000
    return {
        "algorithm": "RSA",
        "key_size": key_size,
        "avg_keygen_time_ms": round(avg_time_ms, 3),
        "rounds": rounds
    }


def benchmark_kem(mechanism: str, rounds: int = 5) -> dict:
    """Time PQC KEM key generation, averaged over several rounds."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        with oqs.KeyEncapsulation(mechanism) as kem:
            kem.generate_keypair()
        end = time.perf_counter()
        times.append(end - start)

    avg_time_ms = (sum(times) / len(times)) * 1000
    return {
        "algorithm": mechanism,
        "avg_keygen_time_ms": round(avg_time_ms, 3),
        "rounds": rounds
    }


def benchmark_rsa_encryption(key_size: int, rounds: int = 5) -> dict:
    """Time RSA encrypt+decrypt of a small message, averaged over rounds."""
    key = RSA.generate(key_size)
    cipher_enc = PKCS1_OAEP.new(key.publickey())
    cipher_dec = PKCS1_OAEP.new(key)
    message = b"benchmark test message"

    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        ciphertext = cipher_enc.encrypt(message)
        cipher_dec.decrypt(ciphertext)
        end = time.perf_counter()
        times.append(end - start)

    avg_time_ms = (sum(times) / len(times)) * 1000
    return {
        "algorithm": "RSA",
        "key_size": key_size,
        "operation": "encrypt+decrypt",
        "avg_time_ms": round(avg_time_ms, 4),
        "rounds": rounds
    }


def benchmark_kem_exchange(mechanism: str, rounds: int = 5) -> dict:
    """Time a full ML-KEM key exchange: keygen + encapsulate + decapsulate."""
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        with oqs.KeyEncapsulation(mechanism) as kem_client:
            public_key = kem_client.generate_keypair()
            with oqs.KeyEncapsulation(mechanism) as kem_server:
                ciphertext, shared_secret_server = kem_server.encap_secret(public_key)
            shared_secret_client = kem_client.decap_secret(ciphertext)
        end = time.perf_counter()
        times.append(end - start)

    avg_time_ms = (sum(times) / len(times)) * 1000
    return {
        "algorithm": mechanism,
        "operation": "full key exchange (keygen+encap+decap)",
        "avg_time_ms": round(avg_time_ms, 4),
        "rounds": rounds
    }


def benchmark_aes(key_size_bytes: int = 32, rounds: int = 50) -> dict:
    """Time AES-256 encrypt+decrypt of a small message, averaged over rounds (with warm-up). Uses CBC mode to match 3DES for a fair comparison."""
    key = get_random_bytes(key_size_bytes)
    message = b"benchmark test message!"

    # Warm-up round, discarded
    cipher = AES.new(key, AES.MODE_CBC)
    padded = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    decipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
    unpad(decipher.decrypt(ciphertext), AES.block_size)

    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        cipher = AES.new(key, AES.MODE_CBC)
        padded = pad(message, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        decipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
        unpad(decipher.decrypt(ciphertext), AES.block_size)
        end = time.perf_counter()
        times.append(end - start)

    avg_time_ms = (sum(times) / len(times)) * 1000
    return {
        "algorithm": "AES-256",
        "operation": "encrypt+decrypt",
        "avg_time_ms": round(avg_time_ms, 4),
        "rounds": rounds
    }


def benchmark_3des(rounds: int = 50) -> dict:
    """Time 3DES encrypt+decrypt of a small message, averaged over rounds (with warm-up)."""
    key = DES3.adjust_key_parity(get_random_bytes(24))
    message = b"benchmark test message!"

    # Warm-up round, discarded
    cipher = DES3.new(key, DES3.MODE_CBC)
    padded = pad(message, DES3.block_size)
    ciphertext = cipher.encrypt(padded)
    decipher = DES3.new(key, DES3.MODE_CBC, iv=cipher.iv)
    unpad(decipher.decrypt(ciphertext), DES3.block_size)

    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        cipher = DES3.new(key, DES3.MODE_CBC)
        padded = pad(message, DES3.block_size)
        ciphertext = cipher.encrypt(padded)
        decipher = DES3.new(key, DES3.MODE_CBC, iv=cipher.iv)
        unpad(decipher.decrypt(ciphertext), DES3.block_size)
        end = time.perf_counter()
        times.append(end - start)

    avg_time_ms = (sum(times) / len(times)) * 1000
    return {
        "algorithm": "3DES",
        "operation": "encrypt+decrypt",
        "avg_time_ms": round(avg_time_ms, 4),
        "rounds": rounds
    }

if __name__ == "__main__":
    results = {
        "RSA-2048": {
            "keygen": benchmark_rsa(2048, rounds=20),
            "operation": benchmark_rsa_encryption(2048, rounds=20)
        },
        "ML-KEM-768": {
            "keygen": benchmark_kem("ML-KEM-768", rounds=20),
            "operation": benchmark_kem_exchange("ML-KEM-768", rounds=20)
        },
        "AES-256": {
            "keygen": {"avg_keygen_time_ms": 0.0, "note": "Symmetric key generation is effectively instant (random bytes)"},
            "operation": benchmark_aes(rounds=20)
        },
        "3DES": {
            "keygen": {"avg_keygen_time_ms": 0.0, "note": "Symmetric key generation is effectively instant (random bytes)"},
            "operation": benchmark_3des(rounds=20)
        }
    }

    with open("benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("Benchmarks complete. Saved to benchmark_results.json")
    print(json.dumps(results, indent=2))