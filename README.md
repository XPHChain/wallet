# PhantomChain Wallet


> Contributor: [PhantomChain](https://github.com/xphchain)
> Lead Maintainer: [Brian Faust](https://github.com/faustbrian)

## Download

[Latest Release](https://github.com/xphchain/wallet/releases/latest)


## Development

### Requirements

#### Ubuntu

In Ubuntu the development files of `libudev` are necessary:

```
sudo apt-get install libudev-dev libusb-1.0-0-dev
```

#### Windows

-   Python 2.7
-   Visual Studio 2017

#### Node 12

To download, head over to [here](https://nodejs.org/en/) and download Node 12.

If you already have npm installed, you can run

```
npm install -g n
sudo n 12
```

#### Yarn

Install the Yarn dependency manager

```
npm install -g yarn
```

### Commands

<details><summary>List of commands</summary>

```bash
# Install dependencies
yarn install

# Execute the electron application. Making changes in the code, updates the application (hot reloading).
yarn dev

# Execute the browser version application. Making changes in the code, updates the application (hot reloading) good for designing :3.
yarn start

# Runs linter over the files
yarn lint

# Try to automatically fix lint errors
yarn lint:fix

# Builds the production code for the react application
yarn build

# Build and electron application for production (Mac)
yarn build:mac

# Build and electron application for production (Linux)
yarn build:linux

# Build electron application for production (Windows - x32 and x64)
yarn build:win

# Run the default test switch in default watch mode
yarn test

# Run unit tests and generate and display the coverage report
yarn test:coverage
```

</details>

## Security

If you discover a security vulnerability within this package, please send an e-mail to security@ark.io. All security vulnerabilities will be promptly addressed.

## Credits

This project exists thanks to all the people who [contribute](../../contributors).

## License

[MIT](LICENSE) © [Payvo](https://payvo.com)
