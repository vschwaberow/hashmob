# HashMob Client

HashMob Client is a Rust-based command-line tool that searches for hash cleartext counterparts in the HashMob database.

## Features

- Search for single hashes or multiple hashes
- Read hashes from a file
- Support for piped input
- Colored and formatted JSON output
- Quiet mode for simple hash:plain output
- Progress indicator during API queries

## Installation

The easiest way is to install ```hashmob``` via ```crates.io```:

```bash
cargo install hashmob
```

To install HashMob Client, you need to have Rust and Cargo installed on your system. If you don't have them installed, you can get them from [https://rustup.rs/](https://rustup.rs/).

Once you have Rust and Cargo, you can install HashMob Client by cloning this repository and building it:

```bash
git clone https://github.com/vschwaberow/hashmob.git
cd hashmob
cargo build --release
```

After building, you can find the binary in the `target/release` directory. You can either run it from there or copy it to a directory in your PATH.

## Usage

HashMob Client can be used to search for hash cleartext counterparts in the HashMob database. You can search for single hashes, multiple hashes, or read hashes from a file. The client supports piped input and provides colored and formatted JSON output. You can also use the quiet mode to get simple hash:plain output.

Before using HashMob Client, you need to set your HashMob API key as an environment variable:

```bash
export HASHMOB_API_KEY=your-api-key
```

To search for a single hash, use the following command:

```bash
hashmob 0b5c29670f2afc9648f77291856d84a5
```

Search for multiple hashes by providing them as arguments:

```bash
hashmob 0b5c29670f2afc9648f77291856d84a5 5f4dcc3b5aa765d61d8327deb882cf99
```

Read hashes from a file:

```bash
hashmob hashes.txt
```

Use piped input:

```bash 
echo -n "0b5c29670f2afc9648f77291856d84a5" | hashmob
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License.

## Author
Volker Schwaberow

## Acknowledgements

* HashMob for providing the API
* All the awesome Rust crate authors that made this project possible
