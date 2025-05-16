#include "dataplane/tls/tls_sni.h"
#include "rdtsc.h"
#include <algorithm>
#include <iostream>
#include <numeric>
#include <vector>

struct SniTestCase
{
	std::string label;
	std::string expected_sni;
	std::vector<uint8_t> payload;
	bool should_match;
};

std::vector<SniTestCase> load_test_cases()
{
	std::vector<SniTestCase> cases;

	for (int i = 0; i < 4; ++i)
	{
		std::string filename = "sni_" + std::to_string(i) + ".bin";
		FILE* f = fopen(filename.c_str(), "rb");
		if (!f)
		{
			std::cerr << "Failed to open " << filename << "\n";
			continue;
		}

		fseek(f, 0, SEEK_END);
		long size = ftell(f);
		fseek(f, 0, SEEK_SET);

		std::vector<uint8_t> raw(size);
		fread(raw.data(), 1, size, f);
		fclose(f);

		std::string expected = (i == 0) ? "example.com" : (i == 1) ? "a.io"
		                                          : (i == 2)       ? "very.very.long.sni.example.com"
		                                                           : "";

		cases.push_back({.label = filename,
		                 .expected_sni = expected,
		                 .payload = raw,
		                 .should_match = !expected.empty()});
	}

	cases.push_back({.label = "garbage_1",
	                 .expected_sni = "",
	                 .payload = std::vector<uint8_t>{0x00, 0x01, 0x02, 0x03, 0x04},
	                 .should_match = false});

	cases.push_back({.label = "garbage_2_incomplete_tls",
	                 .expected_sni = "",
	                 .payload = std::vector<uint8_t>{0x16, 0x03, 0x01, 0x00, 0x10}, // seems like TLS, but lack of data
	                 .should_match = false});

	cases.push_back({.label = "garbage_3_junk_tls",
	                 .expected_sni = "",
	                 .payload = std::vector<uint8_t>{0x16, 0x03, 0x01, 0x00, 0x30, 0x02, 0x00, 0x00}, // Handshake Type != 0x01
	                 .should_match = false});

	return cases;
}

constexpr int iterations = 100000;

int main()
{
	auto test_cases = load_test_cases();

	for (const auto& test : test_cases)
	{
		std::vector<uint64_t> cycles;
		cycles.reserve(iterations);

		std::string_view last_sni;
		bool last_ok = false;

		for (int i = 0; i < iterations; ++i)
		{
			uint64_t start = rdtsc();
			auto maybe_sni = parse_tls_sni(reinterpret_cast<const char*>(test.payload.data()), test.payload.size());
			uint64_t end = rdtsc();

			cycles.push_back(end - start);

			if (i == 0)
			{
				last_ok = maybe_sni.has_value();
				last_sni = maybe_sni.value_or("");
			}
		}

		double avg = std::accumulate(cycles.begin(), cycles.end(), 0.0) / iterations;
		auto [min_it, max_it] = std::minmax_element(cycles.begin(), cycles.end());

		std::cout << "=== " << test.label << " ===\n";
		std::cout << "Expected SNI: " << test.expected_sni << "\n";
		std::cout << "Matched: " << (last_ok ? "yes" : "no") << " | Parsed SNI: \"" << last_sni << "\"\n";
		std::cout << "Iterations: " << iterations << "\n";
		std::cout << "Avg CPU cycles: " << avg << "\n";
		std::cout << "Min cycles: " << *min_it << " | Max cycles: " << *max_it << "\n\n";
	}

	return 0;
}