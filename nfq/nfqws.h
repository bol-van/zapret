#pragma once

typedef enum
{
	// frag=drop but do not fix checksum
	pass = 0, modify, drop, frag, modfrag
} packet_process_result;
