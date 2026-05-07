#!/bin/bash

input_file="BGPblocks.txt"
output_file="HurricaneBGPresults.txt"

sed -n '1~2p' "$input_file" >> "$output_file"
