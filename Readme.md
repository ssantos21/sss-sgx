# Shamir's Secret Sharing Scheme on Intel SGX

## Setup:

1. Clone the repository
2. Run `make SGX_MODE=SIM`
2. Set the correct database in `Settings.toml` file
3. Run the commands below.

## Commands:

### Generate scheme and secret

```bash
$ ./app create-new-scheme seedname 2 3 -g

Seed:
b4cca0656b0b67113291e6378d776b81c469c1c82a859a5dea551bc62ce02938

Key share 0
c31d3f75c46742be525cdfc1c66ca404a59965bb4b063947bf13de806115a108
seek try talent match injury game enact orbit scrub cricket cinnamon announce flower ready unfold general deer digital shaft rug alcohol member loud before

Key share 1
a019d2ae5f1b8325be13553c4373d3ea552c3aa8bba03244491a7189acccc37e
parade soldier process sail return name weapon height detail breeze visual start fan bubble pepper inject crane car educate toast onion grid assume skirt

Key share 2
0515fed8e99fdb9391c2d020d7524ac35ee8db9db0512f4148019b92e0bc65e4
agree quiz renew spring world six either foam camp ritual naive mammal update horse item any consider apart about damp come funny nurse minimum

Scheme created, seed generated.
```

The command is `adcreate-new-scheme <seed_name> <threshold> <share-count> <-g,--generate-seed>` 

The `<seed_name>` is an identifier. Multiple seeds can be generated and the name works as a reference.

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
$ ./app add-mnemonic seedtest1 0 "fork clerk hover mystery replace crucial industry deliver rule into broom brave derive slam limit market alarm weird worth reform idle indoor ozone must"
Key added.
```

The command is `add-mnemonic <seed_name> <index> <mnemonic>`.

The `<seed_name>` is the seed identifier.

The `index` parameter is the index of that key in the scheme.

The `mnemonic` is the mnemonic.

If the user adds a new key and then the total number of keys for this seed reaches the threshold, a secret will be automatically generated.

```bash
$ ./app add-mnemonic seedtest1 1 "volcano share general tonight artefact injury alcohol unveil asset grain flee nut piece parrot vital improve property desk pact three dog vehicle purity turn"
There are already enough keys to calculate the seed.
Seed:
6141fc5eb49c3e0d47fb7d63aefe1a86e1d61104b50df4b8b705548a10c89505
```

### Add a key (hexadecimal).

Instead of adding a mnemonic, the user can add a key directly.

```bash
$ ./app add-key seedtest2 1 f5b8a5837240cee84187730dacb1634bda4740fd4390ac677e7af08409e3eb97
Key added.
```

The command is `add-key <seed_name> <index> <key>`.

The parameters are the same as `add-mnemonic` except for `<key>`, which is a key share represented in hexadecimal.
