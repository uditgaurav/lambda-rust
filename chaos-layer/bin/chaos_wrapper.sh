#!/bin/bash
# Set LD_PRELOAD to load the blocking library
export LD_PRELOAD=/opt/lib/libblock.so

# Execute the original Lambda runtime command
exec "$@"
