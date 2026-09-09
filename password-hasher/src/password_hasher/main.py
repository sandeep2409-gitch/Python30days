import hashlib
import sys
import string

# Known hash lengths (hex-encoded) -> possible algorithms
HASH_LENGTHS = {
    32: ["md5"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256", "sha3_256"],
    96: ["sha384"],
    128: ["sha512", "sha3_512"],
}


def identify_hash(hash_str: str) -> list[str]:
    """Guess likely hash algorithm(s) based on length and character set."""
    hash_str = hash_str.strip()

    if not all(c in string.hexdigits for c in hash_str):
        return []  # not a hex-encoded hash we recognize

    return HASH_LENGTHS.get(len(hash_str), [])


def hash_word(word: str, algo: str) -> str:
    """Hash a single word with the given algorithm."""
    h = hashlib.new(algo)
    h.update(word.encode("utf-8"))
    return h.hexdigest()


def dictionary_attack(target_hash: str, algo: str, wordlist_path: str) -> str | None:
    """
    Try each word in the wordlist against the target hash.
    Returns the matching plaintext, or None if not found.
    """
    target_hash = target_hash.strip().lower()

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if not word:
                continue
            if hash_word(word, algo) == target_hash:
                return word

    return None


def crack(target_hash: str, wordlist_path: str):
    candidates = identify_hash(target_hash)

    if not candidates:
        print(f"Could not identify hash type for: {target_hash}")
        return

    print(f"Hash: {target_hash}")
    print(f"Possible algorithm(s): {', '.join(candidates)}")

    for algo in candidates:
        print(f"\nTrying dictionary attack with {algo}...")
        result = dictionary_attack(target_hash, algo, wordlist_path)
        if result:
            print(f"MATCH FOUND ({algo}): '{result}'")
            return
        else:
            print(f"No match found using {algo}.")

    print("\nNot found in wordlist under any guessed algorithm.")


def main():
    if len(sys.argv) < 3:
        print("Usage: python hash_cracker.py <hash> <wordlist_path>")
        print("Example: python hash_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 wordlist.txt")
        sys.exit(1)

    target_hash = sys.argv[1]
    wordlist_path = sys.argv[2]

    crack(target_hash, wordlist_path)


if __name__ == "__main__":
    main()