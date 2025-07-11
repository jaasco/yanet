#pragma once
#include "metadata.h"
#include <cstdint>

inline bool parse_tls_sni(const uint8_t* data, uint16_t len, const char*& sni_ptr, size_t& sni_len)
{
	if (len < 5 || data[0] != 0x16)
		return false; // not TLS Handshake

	uint16_t hs_len = (static_cast<uint8_t>(data[3]) << 8) | static_cast<uint8_t>(data[4]);
	if (len < 5 + hs_len)
		return false;

	const uint8_t* hs_data = data + 5;
	if (hs_data[0] != 0x01)
		return false; // not ClientHello

	const uint8_t* ptr = hs_data + 38; // skip fixed part of ClientHello
	if (ptr - data >= len)
		return false;

	// Session ID
	uint8_t session_id_len = static_cast<uint8_t>(ptr[0]);
	ptr += 1 + session_id_len;

	// Cipher Suites
	if (ptr + 2 > data + len)
		return false;
	uint16_t cipher_len = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
	ptr += 2 + cipher_len;

	// Compression Methods
	if (ptr + 1 > data + len)
		return false;
	uint8_t comp_len = static_cast<uint8_t>(ptr[0]);
	ptr += 1 + comp_len;

	// Extensions length
	if (ptr + 2 > data + len)
		return false;
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
				return false;

			if (ptr + ext_len > data + len)
				return false;

			uint16_t sni_list_len = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
			ptr += 2;

			if (sni_list_len + 2 > ext_len)
				return false;

			uint8_t name_type = static_cast<uint8_t>(ptr[0]);
			ptr += 1;

			if (name_type != 0)
				return false;

			uint16_t name_len = (static_cast<uint8_t>(ptr[0]) << 8) | static_cast<uint8_t>(ptr[1]);
			ptr += 2;

			if (ptr + name_len > data + len)
				return false;

			sni_ptr = reinterpret_cast<const char*>(ptr);
			sni_len = name_len;
			return true;
		}

		ptr += ext_len;
	}

	return false;
}

inline bool sni_filter_matches(const char (*sni_list)[YANET_CONFIG_TLS_INSPECTORS_SNI_LENGTH],
                               uint32_t sni_count,
                               rte_mbuf* mbuf)
{
	dataplane::metadata* metadata = YADECAP_METADATA(mbuf);

	const uint8_t* payload = rte_pktmbuf_mtod_offset(
	        mbuf, const uint8_t*, metadata->transport_headerOffset + sizeof(rte_tcp_hdr));

	const uint16_t payload_offset = metadata->transport_headerOffset + sizeof(rte_tcp_hdr);
	if (mbuf->pkt_len <= payload_offset)
		return false;

	const uint16_t payload_len = mbuf->pkt_len - payload_offset;

	const char* sni_ptr = nullptr;
	size_t sni_len = 0;

	if (!parse_tls_sni(payload, payload_len, sni_ptr, sni_len))
	{
		YANET_LOG_DEBUG("No SNI found.\n");
		return false;
	}

	for (uint32_t i = 0; i < sni_count; ++i)
	{
		const char* entry = sni_list[i];
		size_t entry_len = strnlen(entry, YANET_CONFIG_TLS_INSPECTORS_SNI_LENGTH);

		if (entry_len == sni_len && memcmp(sni_ptr, entry, sni_len) == 0)
		{
			YANET_LOG_DEBUG("Sni match. Drop it. Matched: %.*s\n", static_cast<int>(sni_len), sni_ptr);
			return true;
		}
	}

	YANET_LOG_DEBUG("Sni mismatch. Got: %.*s\n", static_cast<int>(sni_len), sni_ptr);
	return false;
}