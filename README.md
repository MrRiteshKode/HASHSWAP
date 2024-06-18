This is simple passoword (hash) cracking tool.

## Getting Started

Functionality :-

    1. Can find type of hash.
    2. Can crack different type hashes.
    3. Multi-threaded
    4. It has by default wordlist (hswap.txt)
    5. By default threads used is 50

Download :-

    1. Download, ```bash git clone https://github.com/MrRiteshKode/Kelian.git ```
    2. Download requirements, ```bash pip install -r requirements.txt ```

Usage:-
    1. ```bash python hSwap.py -h ``` [For help menu]

    2. ```bash python hSwap.py -v ``` [For version]

    3. ```bash python hSwap.py --listalgo ``` [List for available hashes can crack by hashswap]

    [+] For Finding type of hash
    3. ```bash python hSwap.py -hT [hash_file.txt] ```
        eg - python hSwap -hT hash.txt

    [+] For cracking hashes
    4. ```bash python hSwap.py -hC [hash_file.txt] -a [algorithm_number] -w [wordlist_file] -t [threads] ```
        eg - python hSwap -hC hash.txt -a -0 -w rockyou.txt -t 100

THANK YOU :)
