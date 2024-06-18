"""
    Disclaimer: Hashswap is intended for educational purposes and 
    authorized security testing only. Unauthorized use for illegal 
    activities is prohibited and can result in severe legal consequences.
    The developers and distributors are not responsible for misuse. 
    Always obtain proper authorization before using Hashswap.
    
    => Hash cracking tool (simple but easy)
    => Version 1.0.1
    => Coded By - Ritesh Kumar
"""

import hashlib
import argparse
import threading
import sys
import json
import time
from colorama import init, Fore, Style

# Initialize colorama (this needs to be called once at the beginning)
init()

class Listalgo(argparse.Action):
    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super().__init__(option_strings, dest, nargs=nargs, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print("""
Available Hashes .....\n
    [0] MD5
    [1] SHA1
    [2] SHA-256
    [3] SHA-224
    [4] SHA-384
    [5] SHA-512
    [6] SHA-3-256
    [7] SHA-3-224
    [8] SHA-3-384
    [9] SHA-3-512
    [10] BLAKE2s
    [11] BLAKE2b
        """)
        parser.exit()

class HashSwap:
      
    def __init__(self):
        self.msg = "This is a simple hash cracking tool. Coded By RITESH KUMAR."
        self.parser = argparse.ArgumentParser(description=self.msg)
        self._add_arguments()
        self.found = threading.Event()
        self.stop = threading.Event()
        self.word_count = 0
        self.lock = threading.Lock()

    def _add_arguments(self):
        self.parser.add_argument('--listalgo', action=Listalgo, help='Show available hashes to crack')
        self.parser.add_argument('-hT', "--hashType", type=str, help='To find type of hash (Give .txt hash file)', default=None)
        self.parser.add_argument('-hC', "--hashCrack", type=str, help='To crack hash (Give .txt hash file)', default=None)
        self.parser.add_argument('-a', "--algorithm", type=int, help='algorithm', default=0)
        self.parser.add_argument('-w', "--wordlist", type=str, help='wordlist file (Default: hSwap.txt)', default="hSwap.txt")
        self.parser.add_argument('-t', "--threads", type=int, help='Threads (Default: 50)', default=50)
        self.parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0.1')
    
    def parse(self):
        args = self.parser.parse_args()
        return args

    def _hashType(self, file):
        try:
            with open(file, 'r') as f:
                file_content = f.read().strip()
                print(file)
        except Exception as e:
            return f"File can't open! {e}"

        hash_types = {
            32: ["MD5", "MD4", "MD2", "BLAKE2s-128", "RIPEMD-128", "Tiger-128"],
            40: ["SHA-1", "RIPEMD-160", "BLAKE2b-160", "BLAKE2s-160", "Tiger-160"],
            48: ["Tiger-192"],
            56: ["SHA-224", "SHA-3-224", "BLAKE2s-224", "SHA-512/224"],
            64: ["SHA-256", "SHA-3-256", "BLAKE2b-256", "BLAKE2s-256", "RIPEMD-256", "SHA-512/256"],
            80: ["RIPEMD-320"],
            96: ["SHA-384", "SHA-3-384", "BLAKE2b-384"],
            128: ["SHA-512", "SHA-3-512", "Whirlpool", "BLAKE2b-512"]
        }

        hash_length = len(file_content)
        possible_hashes = hash_types.get(hash_length, ["Unknown hash type"])

        if possible_hashes == ["Unknown hash type"]:
            return f"The hash type is: {Fore.GREEN}{possible_hashes[0]}{Style.RESET_ALL}"
        else:
            return f"The hash type could be: {Fore.GREEN}{', '.join(possible_hashes)}{Style.RESET_ALL}"

    def _MD5HashCrack(self, word, target_hash):
        hashed = hashlib.md5(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0

    def _SHA1HashCrack(self, word, target_hash):
        hashed = hashlib.sha1(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA256HashCrack(self, word, target_hash):
        hashed = hashlib.sha256(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0

    def _SHA224HashCrack(self, word, target_hash):
        hashed = hashlib.sha224(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA384HashCrack(self, word, target_hash):
        hashed = hashlib.sha384(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA512HashCrack(self, word, target_hash):
        hashed = hashlib.sha512(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA3256HashCrack(self, word, target_hash):
        hashed = hashlib.sha3_256(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA3224HashCrack(self, word, target_hash):
        hashed = hashlib.sha3_224(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA3384HashCrack(self, word, target_hash):
        hashed = hashlib.sha3_384(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _SHA3512HashCrack(self, word, target_hash):
        hashed = hashlib.sha3_512(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _BLAKE2SHashCrack(self, word, target_hash):
        hashed = hashlib.blake2s(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    def _BLAKE2BHashCrack(self, word, target_hash):
        hashed = hashlib.blake2b(word.encode()).hexdigest()
        if hashed == target_hash:
            self.update_json_file("database.json", target_hash, word)
            print(f"MATCH FOUND: {hashed}")
            print(f"WORD: {Fore.YELLOW}{word}{Style.RESET_ALL}")
            self.found.set()
            return 1
        return 0
    
    # Add more hash functions as needed

    def _hashCrack(self, file, wordlist, num_threads, algorithm):
        
        try:
            with open(file, 'r') as f:
                target_hash = f.read().strip()
        except Exception as e:
            print(f"File can't open! {e}")
            return
        
        # Check if the hash is already cracked and present in the database
        with open("database.json", "r") as db:
            data = json.load(db)
            if target_hash in data.keys():
                print()
                print(F"MATCH FOUND: {target_hash}")
                print(f"WORD: {Fore.YELLOW}{data[target_hash]}{Style.RESET_ALL}")
                print(F"{Fore.GREEN}Hash successfully loaded from the database!{Style.RESET_ALL}")
                print()
                sys.exit()
        print("READING FILE. PLEASE WAIT !!")

        # Function to handle thread execution and waiting
        def run_threads(wordlist_chunks, target_hash, hash_func):
            threads_list = []
            try:
                for chunk in wordlist_chunks:
                    if self.found.is_set() or self.stop.is_set():
                        break
                    thread = threading.Thread(target=worker, daemon=True ,args=(chunk, target_hash, hash_func))
                    thread.start()
                    threads_list.append(thread)
                    time.sleep(0.5)  # Wait for 1 second between starting threads
            except KeyboardInterrupt:
                print(f"{Fore.RED}\nExiting....  pressed Ctrl + C{Style.RESET_ALL}")
                self.stop.set()
                for t in threads_list:
                    t.join()
            for t in threads_list:
                t.join()
            if not self.found.is_set():
                print(f"{Fore.GREEN}Hash not cracked.\n{Style.RESET_ALL}")
            if self.found.is_set():
                print(f"{Fore.GREEN}Hashes is Cracked.\n{Style.RESET_ALL}")

        # Function to process a chunk of wordlist
        def worker(wordlist_chunk, target_hash, hash_func):
            for word in wordlist_chunk:
                if self.found.is_set() or self.stop.is_set():
                    return
                hash_func(word, target_hash)
        try:
            with open(wordlist, 'r',encoding="latin-1") as f:
                wordlist_content = f.read().strip().split('\n')
        except Exception as e:
            print(f"Wordlist can't open! {e}")
            return
        
        self.word_count = len(wordlist_content)
        num_threads = min(num_threads, self.word_count)
        print("DONE.")
        print()
        print("------------------------------- START CRACKING ----------------------------------")      
        print()     
        print(f"Hash File: {file}") 
        print(f"Wordlist File: {wordlist}")
        print(f"Threads: {num_threads}")
        print(f"Algorithm No: {algorithm}")
        print(f"Total words: {self.word_count}")
        print(f"Using {num_threads} threads")
        print()
        print("----------------------------------------------------------------------------------")
        print()
        
      
        chunk_size = (self.word_count // num_threads) + 1
        wordlist_chunks = [wordlist_content[i:i + chunk_size] for i in range(0, self.word_count, chunk_size)]
        
        hash_funcs = {
            0: self._MD5HashCrack,
            1: self._SHA1HashCrack,
            2: self._SHA256HashCrack,
            3: self._SHA224HashCrack,
            4: self._SHA384HashCrack,
            5: self._SHA512HashCrack,
            6: self._SHA3256HashCrack,
            7: self._SHA3224HashCrack,
            8: self._SHA3384HashCrack,
            9: self._SHA3512HashCrack,
            10: self._BLAKE2SHashCrack,
            11: self._BLAKE2BHashCrack,
        }

        hash_func = hash_funcs.get(algorithm)
        if hash_func is None:
            print(f"{Fore.RED}Invalid algorithm selected{Style.RESET_ALL}")
            return
        
        run_threads(wordlist_chunks, target_hash, hash_func)

    def update_json_file(self, json_file, hash_key, word):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}

        with self.lock:
            data[hash_key] = word

            with open(json_file, 'w') as f:
                json.dump(data, f)

if __name__ == "__main__":
    cracker = HashSwap()
    args = cracker.parse()
    
    if args.hashType:
        print(cracker._hashType(args.hashType))
    
    if args.hashCrack:
        try:
            cracker._hashCrack(args.hashCrack, args.wordlist, args.threads, args.algorithm)
        except KeyboardInterrupt:
            print(f"{Fore.RED}\nExiting....  pressed Ctrl + C{Style.RESET_ALL}")
