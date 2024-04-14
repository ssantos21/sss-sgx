# Shamir's Secret Sharing Scheme on Intel SGX

## Setup:

1. Clone the repository
2. Install https://github.com/ssantos21/bc-crypto-base
3. Install https://github.com/ssantos21/bc-shamir
4. Install https://github.com/ssantos21/bc-bip39
5. Install libpqxx-dev 7.8.1 (C++ client API for PostgreSQ) 
```bash
# Remove any other version of libpqxx-dev from the operating system if necessary
$ sudo apt remove libpqxx-dev
# It may be necessary to install `libpq-dev` first.
$ sudo apt-get install libpq-dev
# Clone libpqxx project
$ git clone https://github.com/jtv/libpqxx.git
# Change to 7.8.1 version
$ cd libpqxx && git checkout 7.8.1
# Build it
$ cd cmake && cmake .. && cmake --build .
# Install it
$ sudo cmake --install .
```
6. Run `make SGX_MODE=SIM`
7. Set the correct database in `Settings.toml` file
8. Run the commands below.

## Commands:

### Generate scheme and secret

```bash
$ ./app create-new-scheme seedname 2 3 -g

Seed: 47e3661d0ee2ec9ca99914950a03c691ada5a6aeacd6b52ff8b78459e83a7195

Key share index: 0
Password: 77kU3P3PSdNc
Mnemonics: island blade material chunk file desk mouse pole start civil inspire faculty alien always opera year busy beyond fiction start express slogan winner champion

Key share index: 1
Password: A1c4KbntFETu
Mnemonics: jump about pluck this boil impulse wrap increase gaze sand tattoo jungle scorpion destroy ill neutral diamond survey biology zebra very sea dynamic episode

Key share index: 2
Password: JkWDepdT5sga
Mnemonics: input volume surface fish sight belt winner make october remember earth army broom suffer talent history west crowd basic world put fossil occur cook

Scheme created, seed generated.
```

The command is `create-new-scheme <seed_name> <threshold> <share-count> <-g,--generate-seed>` 

The `seed_name` is an identifier. Multiple seeds can be generated and the name works as a reference.

The `threshold` parameter is the threshold for this seed.

The `share-count` is the total number of shares for this seed.

The `-g,--generate-seed` is an optional flag to generate a new secret. If not set, the seed will be created without a secret.

### Generate scheme without secret (in this case, keys will be added later)

```bash
$ ./app create-new-scheme seedtest1 2 3
Scheme created, seed not generated.
```

### Add a mnemonic.

```bash
$ ./app add-mnemonic seedtest1 0 "fork clerk hover mystery replace crucial industry deliver rule into broom brave derive slam limit market alarm weird worth reform idle indoor ozone must" 77kU3P3PSdNc
Key added.
```

The command is `add-mnemonic <seed_name> <index> <mnemonic> <password>`.

The `seed_name` is the seed identifier.

The `index` parameter is the index of that key in the scheme.

The `mnemonic` is the mnemonic.

The `password` is the password used to encrypt the key share.

If the user adds a new key and then the total number of keys for this seed reaches the threshold, a secret will be automatically generated.

```bash
$ ./app add-mnemonic seedtest1 1 "volcano share general tonight artefact injury alcohol unveil asset grain flee nut piece parrot vital improve property desk pact three dog vehicle purity turn" JkWDepdT5sga
There are already enough keys to calculate the seed.
Seed:
6141fc5eb49c3e0d47fb7d63aefe1a86e1d61104b50df4b8b705548a10c89505
```

## Running from docker 

### Simulation Mode

```bash
$ docker compose --file Dockerfiles/SIM/docker-compose.yml build

$ docker compose --file Dockerfiles/SIM/docker-compose.yml up
```

Now the same commands above can be used.

```bash
$ docker compose run sss-sgx create-new-scheme seedtest1 2 3 -g

$ docker compose run sss-sgx create-new-scheme seedtest2 2 3

$ docker compose run sss-sgx add-mnemonic seedtest2 0 "fork clerk hover mystery replace crucial industry deliver rule into broom brave derive slam limit market alarm weird worth reform idle indoor ozone must" 77kU3P3PSdNc
```

To stop the container and remove the volume.

```bash
$ docker compose down -v 
```

### Hardware Mode

```bash
$ cd Dockerfiles/HW
$ ./build_compose_run.sh
```

```bash
$ docker compose run sample create-new-scheme seedtest1 2 3 -g
```

