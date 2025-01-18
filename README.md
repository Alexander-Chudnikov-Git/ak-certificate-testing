# ak-certificate-testing

This project is designed for testing and working with X.509 certificates using the `libakrypt` library. It provides functionality to load, parse, and dump information from certificate files, as well as perform cryptographic operations like point multiplication on elliptic curves.

## Features

- **Certificate Loading:** Loads X.509 certificates from files.
- **Certificate Dumping:** Extracts and displays essential certificate information, including:
    - Serial number
    - Expiration date
    - Common Name (CN)
    - Public key coordinates (x, y, z)
    - Elliptic curve used
- **Cryptographic Operations:**
    - Verifies if the public key point lies on the specified elliptic curve.
    - Calculates and verifies a multiple point on the curve using a randomly generated scalar.
- **Command-Line Interface:** Uses `cxxopts` for easy command-line argument parsing.
- **Logging:** Employs `spdlog` for informative logging during execution.

## Dependencies

- **libakrypt:** A cryptographic library used for certificate parsing and operations.
- **cxxopts:** A lightweight C++ library for command-line argument parsing.
- **spdlog:** A fast and flexible logging library.

Make sure these libraries are installed and accessible to your build system.

## Building

This project uses CMake as its build system. To build the project, follow these steps:

1. **Navigate to the project's root directory:**
```bash
cd path/to/ak-certificate-testing
```

2. **Create a build directory and build**
```bash
cmake . -B ./build/ && cmake --build ./build
```

This will create a build directory and generate the executable within it.

## Usage

After building, you can run the executable with the following command-line options:

-c or --certificate: Specifies the path to the certificate file you want to load.

-d or --dump: Enables dumping of the certificate information.

Example:
```bash
./build/ak-certificate-testing -c ./res/test.pam -d
```

This command will load the certificate located at ./res/test.pam and display its information.

## License

Well, I don't give a fuck about licensing and stuff, the only thing i despise is propietary bullshit,
so I guess you can call it GNU license. 
