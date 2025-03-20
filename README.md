# SimpleBitcoinMiner
A simple Bitcoin solo miner implemented in CUDA and C++.  
This miner does not require any additional software like Bitcoin core and is designed for educational purposes or experimentation.  
It is obviously not profitable on a simple PC. On an RTX 3060 for example it would take on average 11000000 years to mine a single block...

## Requirements
- Windows
- CUDA-capable GPU
- An internet connection

## How to Use
To get started, you'll need to customize a few parts of the code before building and running it.
- **Set the Node IP**:  
    In main.cpp (line 52), update the IP address of the Bitcoin node you want to connect to once you mine a block.  
    In NetworkMessageTypes.h (line 24), set remote_ip to match the node IP. An explanation can be found [here](https://learnmeabitcoin.com/technical/networking/#message-payload).  
    The defaults for these values work for testing since it only connects to the node after mining a valid block which basically never happens...
- **Set the Bitcoin Network Difficulty (n_bits)**:  
    In main.cpp (line 70), update n_bits to the current Bitcoin network difficulty. I haven’t found a simple way to fetch this automatically yet. Check [this](https://learnmeabitcoin.com/technical/block/bits/) for more info.
- **Change the script to use your address**:  
    In CoinbaseTransaction.h (line 21), replace the pk_script with your Bitcoin wallet’s public key script. If you don’t change this and mine a block, the reward (3.125 BTC) will go to my wallet (the default)! Check [this](https://learnmeabitcoin.com/technical/script/p2pkh/#scriptpubkey) for more info.
- **Add a Custom Blockchain Message**:  
    If you want to you can modify script[] in CoinbaseTransaction.h (line 11) to include a custom message (up to ~80 bytes) that will be embedded in the blockchain if you mine a block.
- **Additional Customization**:  
    Check the header files (*.h) for more tweakable fields. Resources like [learnmeabitcoin.com](https://learnmeabitcoin.com) and the [Bitcoin Wiki](https://en.bitcoin.it/wiki/Protocol_documentation) can help explain them. The defaults should work out of the box.  
    Also experiment with the CUDA kernel launch configuration in Hashing.cu (line 176) to optimize performance for your GPU if you want to.

Once customized, build the project with these steps:  
```
git clone https://github.com/SubatomicPlanets/SimpleBitcoinMiner.git
cd SimpleBitcoinMiner
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Limitations & TODO
- Only works on Windows.
- Requires a CUDA-capable GPU.
- Continuously hashes the same block until stopped. If another miner finds a block first, you’ll need to restart the program. Initially I saw this as a downside but it's also good because it means you can't let this run for hours at a time wasting electricity...
- Only includes a coinbase transaction (no regular transactions). I did this to keep it simple.
- Submits mined blocks to a single node. Submitting to multiple nodes would improve reliability.
- Uses the [CPR](https://github.com/libcpr/cpr) library, which seems a bit too big for this project. A more lightweight library would be better.

## Files
- main.cpp: Main entry point. Fetches blockchain data from a public API, runs the mining loop, and submits mined blocks to a node (if successful).
- Hashing.cu: CUDA implementation of the SHA-256 hashing kernel, optimized for GPU execution.
- cpu_sha256.h: CPU-based SHA-256 implementation used by main.cpp before and after the GPU hash loop
- BlockHeader.h: Defines the BlockHeader structure that gets hashed.
- CoinbaseTransaction.h: Contains structs for creating a coinbase transaction.
- Block.h: Combines BlockHeader and CoinbaseTransaction into a complete block.
- NetworkMessageTypes.h: Defines networking structs used to submit mined blocks to a node.

## Who Is This For?
- People curious about their PC’s Bitcoin mining hashrate.
- People who want to learn more about Bitcoin, SHA-256, or CUDA.
- Optimists who think they’re lucky enough to mine a block with this code!

## Disclaimer
I built this in two weeks with no prior Bitcoin or CMake experience.  
Testing was minimal. If you mine a block there is a chance it doesn't get sent to the node properly and you won't get a reward...  
Let me know if you find any bugs or things that can be improved!  
Use at your own risk. I’m not responsible for anything you do. I just want to share my code :)  
Thanks!
