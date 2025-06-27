#include "tls.h"

void tls_inspector_t::reload_before()
{
	generations_config.next_lock();
}

void tls_inspector_t::reload(const controlplane::base_t& base_prev,
                             const controlplane::base_t& base_next,
                             common::idp::updateGlobalBase::request& globalbase)
{
	generations_config.next().update(base_prev, base_next);
	compile(globalbase, generations_config.next());
}

void tls_inspector_t::reload_after()
{
	generations_config.switch_generation();
	generations_config.next_unlock();
}

void tls_inspector_t::compile(common::idp::updateGlobalBase::request& globalbase,
                              tls_inspect::generation_config_t& generation_config)
{
	tls_inspector_id_t tlsId = 0;
	for (const auto& [name, tls_inspector] : generation_config.config_tls_inspectors)
	{
		std::set<std::string> blacklist(tls_inspector.blacklist_sni.begin(), tls_inspector.blacklist_sni.end());

		globalbase.emplace_back(common::idp::updateGlobalBase::requestType::tls_inspector_update,
		                        common::idp::updateGlobalBase::tls_inspector_update::request(tlsId,
		                                                                                     blacklist,
		                                                                                     tls_inspector.flow));
		++tlsId;
	}
}
