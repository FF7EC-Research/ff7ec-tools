# decode.cpp tests

`decode.cpp`/`decode.h` (`../loader/`) have no Windows/Win32 dependency, so
they're tested natively here instead of needing Wine or a Windows box.

```
python3 make_vectors.py /tmp/vec       # builds req.bin/resp.bin/plain.pb
g++ -std=c++17 -Wall -o /tmp/test_decode test_decode.cpp ../loader/decode.cpp
/tmp/test_decode /tmp/vec
```

`make_vectors.py` encrypts a small hand-built protobuf message the same way
the game's API does (LZ4 frame, then AES-256-CBC with a random IV prefix,
under the client/server API keys documented in the sibling `ff7ecapi`
repo's `Utils/Crypto.cs`) and writes it alongside the plaintext it should
decode back to. `test_decode.cpp` then checks `decode_body()` recovers the
exact plaintext under the expected key for both directions, dumps the
protobuf, and rejects non-matching/garbage input.
