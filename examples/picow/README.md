# Pico W sample
This is the smb-ls-sync.c example adapted to run on a Pico W.  You will need the Pico-SDK and FreeRTOS-Kernel installed for this to work.  See the CMakeLists.txt file - there's some user configuration needed before the sample can be compiled and run.

Configure with `-DSMB2_RANDOM_PROVIDER_SOURCE=/absolute/path/to/board_random.c`.
The supplied C source must implement `int picow_smb2_random(void *buf, size_t len)`
using a board-specific cryptographic random source. Fill all requested bytes and
return zero on success, or a positive errno value on failure. See the Pico W
entropy guidance in the top-level README.
