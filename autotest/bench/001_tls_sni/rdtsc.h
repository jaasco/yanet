#pragma once
#include <cstdint>

inline uint64_t rdtsc()
{
	unsigned int lo, hi;
	__asm__ __volatile__(
	        "lfence\n\t" // serialize
	        "rdtsc\n\t" // read tsc
	        : "=a"(lo), "=d"(hi)
	        :
	        : "%rbx", "%rcx");
	return ((uint64_t)hi << 32) | lo;
}