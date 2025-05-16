#pragma once
#include <cstdint>
#include <optional>
#include <string_view>

inline std::optional<std::string_view> parse_tls_sni(const char* data, uint16_t len)
{
	if (len < 5 || data[0] != 0x16)
		return std::nullopt; // not TLS Handshake
	uint16_t hs_len = (static_cast<uint8_t>(data[3]) << 8) | static_cast<uint8_t>(data[4]);
	if (len < 5 + hs_len)
		return std::nullopt;

	const char* hs_data = data + 5;
	if (hs_data[0] != 0x01)
		return std::nullopt; // not ClientHello

	const char* ptr = hs_data + 38; // skip fixed part of ClientHello
	if (ptr - data >= len)
		return std::nullopt;

	// Session ID
	uint8_t session_id_len = static_cast<uint8_t>(ptr[0]);
	ptr += 1 + session_id_len;

	// Cipher Suites
	if (ptr + 2 > data + len)
		return std::nullopt;
	uint16_t cipher_len = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
	ptr += 2 + cipher_len;

	// Compression Methods
	if (ptr + 1 > data + len)
		return std::nullopt;
	uint8_t comp_len = static_cast<uint8_t>(ptr[0]);
	ptr += 1 + comp_len;

	// Extensions length
	if (ptr + 2 > data + len)
		return std::nullopt;
	ptr += 2;

	while (ptr - data < len)
	{
		if (ptr + 4 > data + len)
			break;
		uint16_t ext_type = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
		uint16_t ext_len = (static_cast<uint8_t>(ptr[2]) << 8) | static_cast<uint8_t>(ptr[3]);
		ptr += 4;
		if (ptr + ext_len > data + len)
			break;

		if (ext_type == 0x0000) // server_name extension
		{
			if (ext_len < 5)
				return std::nullopt;

			if (ptr + ext_len > data + len)
				return std::nullopt;

			uint16_t sni_list_len = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
			ptr += 2;

			if (sni_list_len + 2 > ext_len)
				return std::nullopt;

			uint8_t name_type = static_cast<uint8_t>(ptr[0]);
			ptr += 1;

			if (name_type != 0)
				return std::nullopt;

			uint16_t name_len = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
			ptr += 2;

			if (ptr + name_len > data + len)
				return std::nullopt;

			return std::string_view(ptr, name_len);
		}
		ptr += ext_len;
	}
	return std::nullopt;
}
